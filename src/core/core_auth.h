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
 * core_auth.h — User authentication, sessions, API keys, password hashing
 */

#ifndef CORE_AUTH_H
#define CORE_AUTH_H

#include "portal/types.h"
#include "core_hashtable.h"

#define AUTH_MAX_USERS      128
#define AUTH_MAX_SESSIONS   256
#define AUTH_TOKEN_LEN      32
#define AUTH_SESSION_TTL    3600    /* seconds (1 hour default) */
#define AUTH_HASH_PREFIX    "$sha256$"

#define AUTH_KEY_LEN 64

/* A registered user */
typedef struct {
    char             username[PORTAL_MAX_LABEL_LEN];
    char             password[256];    /* plain text or $sha256$salt$hash */
    char             api_key[AUTH_KEY_LEN + 1];  /* 64-char hex API key */
    portal_labels_t  labels;
} auth_user_t;

/* An active session */
typedef struct {
    char         token[AUTH_TOKEN_LEN + 1];
    char         username[PORTAL_MAX_LABEL_LEN];
    uint64_t     created_at;
    uint64_t     expires_at;
    int          active;
} auth_session_t;

/* Auth registry */
typedef struct {
    auth_user_t     users[AUTH_MAX_USERS];
    int             user_count;
    auth_session_t  sessions[AUTH_MAX_SESSIONS];
    int             session_count;
    int             session_ttl;    /* configurable TTL */
} portal_auth_registry_t;

void portal_auth_init(portal_auth_registry_t *auth);
void portal_auth_destroy(portal_auth_registry_t *auth);

int  portal_auth_load_users(portal_auth_registry_t *auth, const char *path);
int  portal_auth_add_user(portal_auth_registry_t *auth, const char *username,
                           const char *password, const portal_labels_t *labels);
auth_user_t *portal_auth_find_user(portal_auth_registry_t *auth,
                                    const char *username);

const char *portal_auth_login(portal_auth_registry_t *auth,
                               const char *username, const char *password);
int  portal_auth_logout(portal_auth_registry_t *auth, const char *token);
auth_user_t *portal_auth_resolve_token(portal_auth_registry_t *auth,
                                        const char *token);
portal_ctx_t *portal_auth_build_context(portal_auth_registry_t *auth,
                                         const char *token);

/* Cleanup expired sessions. Returns number cleaned. */
int  portal_auth_cleanup_sessions(portal_auth_registry_t *auth);

/* Hash a password: sha256(salt + password) → "$sha256$salt$hexhash" */
void portal_auth_hash_password(const char *password, const char *salt,
                                char *out, size_t out_len);

/* Check if a stored password matches a plain-text input */
int  portal_auth_check_password(const char *stored, const char *input);

/* Login by API key (alternative to password). Returns token or NULL. */
const char *portal_auth_login_key(portal_auth_registry_t *auth,
                                   const char *api_key);

/* Generate a new API key for a user. Returns 0 on success. */
int  portal_auth_rotate_key(portal_auth_registry_t *auth, const char *username);

/* Generate an API key string */
void portal_auth_generate_key(char *buf, size_t len);

/* Persistent storage integration */
#include "core_store.h"
int  portal_auth_load_from_store(portal_auth_registry_t *auth,
                                  portal_store_t *store);
int  portal_auth_save_user_to_store(portal_auth_registry_t *auth,
                                     const char *username,
                                     portal_store_t *store);

#endif /* CORE_AUTH_H */
