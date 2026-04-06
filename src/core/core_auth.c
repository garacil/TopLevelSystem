/*
 * Author: Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/*
 * core_auth.c — Authentication and user management
 *
 * User registry with SHA-256 password hashing, API key auth,
 * session tokens with TTL expiry. Loads from file store and
 * persists changes to all active storage providers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "core_auth.h"
#include "core_log.h"
#include "portal/constants.h"
#include "sha256.h"
#include "core_store.h"

/* --- Token generation --- */

static void generate_token(char *buf, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        for (size_t i = 0; i < len; i++) {
            unsigned char c;
            if (fread(&c, 1, 1, f) == 1)
                buf[i] = hex[c % 16];
            else
                buf[i] = hex[(unsigned)rand() % 16];
        }
        fclose(f);
    } else {
        srand((unsigned)time(NULL));
        for (size_t i = 0; i < len; i++)
            buf[i] = hex[(unsigned)rand() % 16];
    }
    buf[len] = '\0';
}

/* --- Password hashing --- */

void portal_auth_hash_password(const char *password, const char *salt,
                                char *out, size_t out_len)
{
    /* Compute SHA-256(salt + password) */
    char combined[384];
    snprintf(combined, sizeof(combined), "%s%s", salt, password);

    char hex[65];
    sha256_hex((const uint8_t *)combined, strlen(combined), hex);

    /* Output format: $sha256$salt$hash */
    snprintf(out, out_len, "%s%s$%s", AUTH_HASH_PREFIX, salt, hex);
}

int portal_auth_check_password(const char *stored, const char *input)
{
    /* If stored starts with $sha256$, it's hashed */
    if (strncmp(stored, AUTH_HASH_PREFIX, strlen(AUTH_HASH_PREFIX)) == 0) {
        const char *rest = stored + strlen(AUTH_HASH_PREFIX);
        const char *dollar = strchr(rest, '$');
        if (!dollar) return 0;

        /* Extract salt */
        char salt[65];
        size_t slen = (size_t)(dollar - rest);
        if (slen >= sizeof(salt)) return 0;
        memcpy(salt, rest, slen);
        salt[slen] = '\0';

        /* Hash input with same salt and compare */
        char hashed[256];
        portal_auth_hash_password(input, salt, hashed, sizeof(hashed));
        return strcmp(stored, hashed) == 0;
    }

    /* Plain text comparison (backwards compatible) */
    return strcmp(stored, input) == 0;
}

/* --- Lifecycle --- */

void portal_auth_init(portal_auth_registry_t *auth)
{
    memset(auth, 0, sizeof(*auth));
    auth->session_ttl = AUTH_SESSION_TTL;

    portal_labels_t root_labels = {0};
    portal_labels_add(&root_labels, "root");
    portal_auth_add_user(auth, "root", "", &root_labels);

    LOG_DEBUG("auth", "Auth registry initialized (root user created)");
}

void portal_auth_destroy(portal_auth_registry_t *auth)
{
    memset(auth, 0, sizeof(*auth));
}

int portal_auth_add_user(portal_auth_registry_t *auth, const char *username,
                          const char *password, const portal_labels_t *labels)
{
    if (auth->user_count >= AUTH_MAX_USERS)
        return -1;

    /* Update existing user if found (merge from config files) */
    auth_user_t *existing = portal_auth_find_user(auth, username);
    if (existing) {
        if (password && password[0])
            snprintf(existing->password, sizeof(existing->password), "%s", password);
        if (labels && labels->count > 0)
            memcpy(&existing->labels, labels, sizeof(portal_labels_t));
        return 0;
    }

    auth_user_t *u = &auth->users[auth->user_count++];
    snprintf(u->username, sizeof(u->username), "%s", username);
    snprintf(u->password, sizeof(u->password), "%s", password);
    if (labels)
        memcpy(&u->labels, labels, sizeof(portal_labels_t));

    return 0;
}

auth_user_t *portal_auth_find_user(portal_auth_registry_t *auth,
                                    const char *username)
{
    for (int i = 0; i < auth->user_count; i++) {
        if (strcmp(auth->users[i].username, username) == 0)
            return &auth->users[i];
    }
    return NULL;
}

/* --- Sessions --- */

const char *portal_auth_login(portal_auth_registry_t *auth,
                               const char *username, const char *password)
{
    auth_user_t *user = portal_auth_find_user(auth, username);
    if (!user) {
        LOG_WARN("auth", "Login failed: user '%s' not found", username);
        return NULL;
    }

    if (!portal_auth_check_password(user->password, password)) {
        LOG_WARN("auth", "Login failed: wrong password for '%s' (stored_len=%zu input_len=%zu)",
                 username, strlen(user->password), strlen(password));
        return NULL;
    }

    /* Find a free session slot */
    auth_session_t *session = NULL;
    for (int i = 0; i < AUTH_MAX_SESSIONS; i++) {
        if (!auth->sessions[i].active) {
            session = &auth->sessions[i];
            break;
        }
    }
    if (!session)
        session = &auth->sessions[0];  /* reuse oldest */

    uint64_t now = (uint64_t)time(NULL);
    generate_token(session->token, AUTH_TOKEN_LEN);
    snprintf(session->username, sizeof(session->username), "%s", username);
    session->created_at = now;
    session->expires_at = now + (uint64_t)auth->session_ttl;
    session->active = 1;
    auth->session_count++;

    LOG_INFO("auth", "User '%s' logged in (ttl: %ds)", username,
             auth->session_ttl);
    return session->token;
}

int portal_auth_logout(portal_auth_registry_t *auth, const char *token)
{
    for (int i = 0; i < AUTH_MAX_SESSIONS; i++) {
        if (auth->sessions[i].active &&
            strcmp(auth->sessions[i].token, token) == 0) {
            LOG_INFO("auth", "User '%s' logged out", auth->sessions[i].username);
            auth->sessions[i].active = 0;
            auth->session_count--;
            return 0;
        }
    }
    return -1;
}

auth_user_t *portal_auth_resolve_token(portal_auth_registry_t *auth,
                                        const char *token)
{
    if (!token || token[0] == '\0') return NULL;

    uint64_t now = (uint64_t)time(NULL);
    for (int i = 0; i < AUTH_MAX_SESSIONS; i++) {
        if (auth->sessions[i].active &&
            strcmp(auth->sessions[i].token, token) == 0) {
            /* Check expiry */
            if (auth->sessions[i].expires_at > 0 &&
                now > auth->sessions[i].expires_at) {
                LOG_DEBUG("auth", "Session expired for '%s'",
                          auth->sessions[i].username);
                auth->sessions[i].active = 0;
                auth->session_count--;
                return NULL;
            }
            return portal_auth_find_user(auth, auth->sessions[i].username);
        }
    }
    return NULL;
}

portal_ctx_t *portal_auth_build_context(portal_auth_registry_t *auth,
                                         const char *token)
{
    auth_user_t *user = portal_auth_resolve_token(auth, token);
    if (!user) return NULL;

    portal_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->auth.user = strdup(user->username);
    ctx->auth.token = strdup(token);
    memcpy(&ctx->auth.labels, &user->labels, sizeof(portal_labels_t));
    return ctx;
}

int portal_auth_cleanup_sessions(portal_auth_registry_t *auth)
{
    uint64_t now = (uint64_t)time(NULL);
    int cleaned = 0;

    for (int i = 0; i < AUTH_MAX_SESSIONS; i++) {
        if (auth->sessions[i].active &&
            auth->sessions[i].expires_at > 0 &&
            now > auth->sessions[i].expires_at) {
            LOG_DEBUG("auth", "Cleaned expired session for '%s'",
                      auth->sessions[i].username);
            auth->sessions[i].active = 0;
            auth->session_count--;
            cleaned++;
        }
    }

    if (cleaned > 0)
        LOG_INFO("auth", "Cleaned %d expired sessions", cleaned);
    return cleaned;
}

/* --- API keys --- */

void portal_auth_generate_key(char *buf, size_t len)
{
    generate_token(buf, len);
}

const char *portal_auth_login_key(portal_auth_registry_t *auth,
                                   const char *api_key)
{
    if (!api_key || api_key[0] == '\0') return NULL;

    /* Find user by API key */
    auth_user_t *user = NULL;
    for (int i = 0; i < auth->user_count; i++) {
        if (auth->users[i].api_key[0] != '\0' &&
            strcmp(auth->users[i].api_key, api_key) == 0) {
            user = &auth->users[i];
            break;
        }
    }
    if (!user) {
        LOG_WARN("auth", "API key login failed: key not found");
        return NULL;
    }

    /* Create session directly (bypass password check) */
    auth_session_t *session = NULL;
    for (int i = 0; i < AUTH_MAX_SESSIONS; i++) {
        if (!auth->sessions[i].active) { session = &auth->sessions[i]; break; }
    }
    if (!session) session = &auth->sessions[0];

    uint64_t now = (uint64_t)time(NULL);
    generate_token(session->token, AUTH_TOKEN_LEN);
    snprintf(session->username, sizeof(session->username), "%s", user->username);
    session->created_at = now;
    session->expires_at = now + (uint64_t)auth->session_ttl;
    session->active = 1;
    auth->session_count++;

    LOG_INFO("auth", "User '%s' logged in via API key", user->username);
    return session->token;
}

int portal_auth_rotate_key(portal_auth_registry_t *auth, const char *username)
{
    auth_user_t *user = portal_auth_find_user(auth, username);
    if (!user) return -1;

    portal_auth_generate_key(user->api_key, AUTH_KEY_LEN);
    LOG_INFO("auth", "API key rotated for user '%s'", username);
    return 0;
}

/* --- Config file loading --- */

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

int portal_auth_load_users(portal_auth_registry_t *auth, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_WARN("auth", "Users file '%s' not found", path);
        return -1;
    }

    char line[512];
    int loaded = 0;

    while (fgets(line, sizeof(line), f)) {
        char *s = trim(line);
        if (*s == '\0' || *s == '#') continue;

        char *colon1 = strchr(s, ':');
        if (!colon1) continue;
        *colon1 = '\0';

        char *username = trim(s);
        char *rest = colon1 + 1;

        /* Parse: password:labels:apikey */
        char *colon2 = strchr(rest, ':');
        char *password;
        char *labels_str = NULL;
        char *apikey_str = NULL;

        if (colon2) {
            *colon2 = '\0';
            password = trim(rest);
            char *after_labels = colon2 + 1;
            char *colon3 = strchr(after_labels, ':');
            if (colon3) {
                *colon3 = '\0';
                labels_str = trim(after_labels);
                apikey_str = trim(colon3 + 1);
            } else {
                labels_str = trim(after_labels);
            }
        } else {
            password = trim(rest);
        }

        /* Parse labels */
        portal_labels_t labels = {0};
        if (labels_str && labels_str[0] != '\0') {
            char *saveptr = NULL;
            char *tok = strtok_r(labels_str, ",", &saveptr);
            while (tok) {
                portal_labels_add(&labels, trim(tok));
                tok = strtok_r(NULL, ",", &saveptr);
            }
        }

        if (strcmp(username, "root") == 0) {
            auth_user_t *root = portal_auth_find_user(auth, "root");
            if (root) {
                if (password[0] != '\0')
                    snprintf(root->password, sizeof(root->password), "%s", password);
                if (apikey_str && strcmp(apikey_str, "auto") == 0)
                    portal_auth_generate_key(root->api_key, AUTH_KEY_LEN);
                else if (apikey_str && apikey_str[0] != '\0')
                    snprintf(root->api_key, sizeof(root->api_key), "%s", apikey_str);
                /* Update root labels if provided */
                if (labels.count > 0) {
                    portal_labels_add(&root->labels, "root");  /* always keep root */
                    for (int j = 0; j < labels.count; j++)
                        portal_labels_add(&root->labels, labels.labels[j]);
                }
            }
            continue;
        }

        if (portal_auth_add_user(auth, username, password, &labels) == 0) {
            auth_user_t *u = portal_auth_find_user(auth, username);
            if (u) {
                if (apikey_str && strcmp(apikey_str, "auto") == 0)
                    portal_auth_generate_key(u->api_key, AUTH_KEY_LEN);
                else if (apikey_str && apikey_str[0] != '\0')
                    snprintf(u->api_key, sizeof(u->api_key), "%s", apikey_str);
            }
            LOG_DEBUG("auth", "Loaded user '%s' with %d labels",
                     username, labels.count);
            loaded++;
        }
    }

    fclose(f);
    LOG_INFO("auth", "Loaded %d users from '%s'", loaded, path);
    return loaded;
}

/* --- Persistent store integration --- */

typedef struct {
    portal_auth_registry_t *auth;
    portal_store_t *store;
    int count;
} load_store_ctx_t;

static void load_user_cb(const char *name, void *userdata)
{
    load_store_ctx_t *ctx = userdata;
    char path[PORTAL_MAX_PATH_LEN];
    portal_store_path(ctx->store, "users", name, path, sizeof(path));

    portal_ht_t kv;
    portal_ht_init(&kv, 16);
    if (portal_store_read_ini(path, &kv) < 0) {
        portal_ht_destroy(&kv);
        return;
    }

    char *password = portal_ht_get(&kv, "password");
    char *api_key = portal_ht_get(&kv, "api_key");
    char *groups = portal_ht_get(&kv, "groups");

    portal_labels_t labels = {0};
    if (groups && groups[0]) {
        char buf[512];
        snprintf(buf, sizeof(buf), "%s", groups);
        char *saveptr = NULL;
        char *tok = strtok_r(buf, ",", &saveptr);
        while (tok) {
            while (*tok == ' ') tok++;
            portal_labels_add(&labels, tok);
            tok = strtok_r(NULL, ",", &saveptr);
        }
    }

    if (strcmp(name, "root") == 0) {
        auth_user_t *root = portal_auth_find_user(ctx->auth, "root");
        if (root) {
            if (password) snprintf(root->password, sizeof(root->password), "%s", password);
            if (api_key) snprintf(root->api_key, sizeof(root->api_key), "%s", api_key);
            if (labels.count > 0) {
                portal_labels_add(&labels, "root");
                memcpy(&root->labels, &labels, sizeof(portal_labels_t));
            }
        }
    } else {
        if (portal_auth_add_user(ctx->auth, name,
                                  password ? password : "", &labels) == 0) {
            auth_user_t *u = portal_auth_find_user(ctx->auth, name);
            if (u && api_key)
                snprintf(u->api_key, sizeof(u->api_key), "%s", api_key);
            ctx->count++;
        }
    }

    portal_ht_destroy(&kv);
}

int portal_auth_load_from_store(portal_auth_registry_t *auth,
                                 portal_store_t *store)
{
    char dir[PORTAL_MAX_PATH_LEN + 32];
    snprintf(dir, sizeof(dir), "%s/users", store->base_dir);

    load_store_ctx_t ctx = { .auth = auth, .store = store, .count = 0 };
    portal_store_list_dir(dir, load_user_cb, &ctx);

    LOG_INFO("auth", "Loaded %d users from store", ctx.count);
    return ctx.count;
}

int portal_auth_save_user_to_store(portal_auth_registry_t *auth,
                                    const char *username,
                                    portal_store_t *store)
{
    auth_user_t *user = portal_auth_find_user(auth, username);
    if (!user) return -1;

    char path[PORTAL_MAX_PATH_LEN];
    portal_store_path(store, "users", username, path, sizeof(path));

    portal_ht_t kv;
    portal_ht_init(&kv, 16);

    portal_ht_set(&kv, "password", strdup(user->password));
    if (user->api_key[0])
        portal_ht_set(&kv, "api_key", strdup(user->api_key));

    /* Build groups string from labels */
    char groups[1024] = {0};
    for (int i = 0; i < user->labels.count; i++) {
        if (i > 0) strcat(groups, ",");
        strcat(groups, user->labels.labels[i]);
    }
    portal_ht_set(&kv, "groups", strdup(groups));

    int rc = portal_store_write_ini(path, &kv);
    portal_ht_destroy(&kv);

    LOG_DEBUG("auth", "Saved user '%s' to store", username);
    return rc;
}
