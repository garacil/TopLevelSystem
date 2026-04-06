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
 * core_handlers.c — Internal path handlers for core services
 *
 * Handles all /core, /auth, /users, /groups, /events paths.
 * Implements user/group CRUD, authentication, event listing,
 * storage management, module lifecycle, and path navigation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include "core_handlers.h"
#include "core_auth.h"
#include "core_events.h"
#include "core_store.h"
#include "core_log.h"
#include "core_path.h"
#include "core_module.h"
#include "core_message.h"

/* Forward declaration — we access the instance from core->_internal */
#include "portal_instance.h"

/* --- /core/status --- */

static int handle_status(portal_instance_t *inst, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)msg;
    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "Portal v%s\n"
        "Status: running\n"
        "Modules loaded: %d\n"
        "Paths registered: %d\n",
        PORTAL_VERSION_STR,
        inst->modules.count,
        inst->paths.count);

    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, buf, (size_t)n + 1);
    return 0;
}

/* --- /core/modules --- */

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} strbuf_t;

static void strbuf_append(strbuf_t *sb, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int needed = vsnprintf(sb->buf + sb->len, sb->cap - sb->len, fmt, ap);
    va_end(ap);

    if (needed > 0 && (size_t)needed < sb->cap - sb->len)
        sb->len += (size_t)needed;
}

static int handle_modules_list(portal_instance_t *inst, portal_resp_t *resp)
{
    char buf[4096];
    strbuf_t sb = { .buf = buf, .len = 0, .cap = sizeof(buf) };

    strbuf_append(&sb, "Loaded modules:\n");

    for (int i = 0; i < inst->modules.count; i++) {
        portal_module_entry_t *e = &inst->modules.entries[i];
        if (e->loaded && e->info) {
            strbuf_append(&sb, "  %-16s v%-8s %s\n",
                         e->info->name, e->info->version, e->info->description);
        }
    }

    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, buf, sb.len + 1);
    return 0;
}

static int handle_module_action(portal_instance_t *inst, const char *mod_name,
                                 const portal_msg_t *msg, portal_resp_t *resp)
{
    /* Find action header */
    const char *action = NULL;
    for (uint16_t i = 0; i < msg->header_count; i++) {
        if (strcmp(msg->headers[i].key, "action") == 0) {
            action = msg->headers[i].value;
            break;
        }
    }

    if (!action) {
        portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
        const char *err = "Missing 'action' header\n";
        portal_resp_set_body(resp, err, strlen(err) + 1);
        return -1;
    }

    int rc;
    if (strcmp(action, "load") == 0) {
        rc = portal_module_do_load(&inst->modules, mod_name, &inst->api);
    } else if (strcmp(action, "unload") == 0) {
        rc = portal_module_do_unload(&inst->modules, mod_name, &inst->api);
    } else if (strcmp(action, "reload") == 0) {
        rc = portal_module_do_reload(&inst->modules, mod_name, &inst->api);
    } else {
        portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
        char err[128];
        snprintf(err, sizeof(err), "Unknown action: %s\n", action);
        portal_resp_set_body(resp, err, strlen(err) + 1);
        return -1;
    }

    if (rc == 0) {
        portal_resp_set_status(resp, PORTAL_OK);
        char msg_buf[128];
        snprintf(msg_buf, sizeof(msg_buf), "Module '%s': %s OK\n", mod_name, action);
        portal_resp_set_body(resp, msg_buf, strlen(msg_buf));
    } else {
        portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
        char msg_buf[128];
        snprintf(msg_buf, sizeof(msg_buf), "Module '%s': %s failed\n", mod_name, action);
        portal_resp_set_body(resp, msg_buf, strlen(msg_buf));
    }
    return rc;
}

/* --- /core/paths --- */

typedef struct {
    strbuf_t *sb;
} path_list_ctx_t;

static void path_list_cb(const char *path, const char *module_name, void *userdata)
{
    path_list_ctx_t *ctx = userdata;
    strbuf_append(ctx->sb, "  %-40s → %s\n", path, module_name);
}

static int handle_paths_list(portal_instance_t *inst, portal_resp_t *resp)
{
    char buf[65536];
    strbuf_t sb = { .buf = buf, .len = 0, .cap = sizeof(buf) };

    strbuf_append(&sb, "Registered paths:\n");

    path_list_ctx_t ctx = { .sb = &sb };
    portal_path_list(&inst->paths, path_list_cb, &ctx);

    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, buf, sb.len + 1);
    return 0;
}

/* --- /core/ls (list next-level children at a path, like a filesystem) --- */

#define LS_MAX_ENTRIES 128

typedef struct {
    const char *prefix;
    size_t      prefix_len;
    char        children[LS_MAX_ENTRIES][128];   /* unique child segment names */
    char        modules[LS_MAX_ENTRIES][PORTAL_MAX_MODULE_NAME];
    int         is_leaf[LS_MAX_ENTRIES];          /* 1 = registered path, 0 = intermediate */
    int         count;
} ls_ctx_t;

static void ls_cb(const char *path, const char *module_name, void *userdata)
{
    ls_ctx_t *ctx = userdata;
    size_t plen = ctx->prefix_len;

    /* Must start with prefix */
    if (plen > 0 && strncmp(path, ctx->prefix, plen) != 0)
        return;

    /* Get the part after the prefix */
    const char *rest = path + plen;

    /* Skip leading slash if prefix is not "/" */
    if (rest[0] == '/' && plen > 0 && ctx->prefix[plen - 1] != '/')
        rest++;

    /* If empty, this IS the prefix path itself — show as "." */
    if (rest[0] == '\0') {
        /* The prefix itself is a registered path */
        if (ctx->count < LS_MAX_ENTRIES) {
            snprintf(ctx->children[ctx->count], 128, ".");
            snprintf(ctx->modules[ctx->count], PORTAL_MAX_MODULE_NAME, "%s", module_name);
            ctx->is_leaf[ctx->count] = 1;
            ctx->count++;
        }
        return;
    }

    /* Extract the next segment */
    char segment[128];
    const char *slash = strchr(rest, '/');
    if (slash) {
        size_t slen = (size_t)(slash - rest);
        if (slen >= sizeof(segment)) slen = sizeof(segment) - 1;
        memcpy(segment, rest, slen);
        segment[slen] = '\0';
    } else {
        snprintf(segment, sizeof(segment), "%s", rest);
    }

    /* Check for duplicate */
    for (int i = 0; i < ctx->count; i++) {
        if (strcmp(ctx->children[i], segment) == 0) {
            /* If this is a direct child (no slash after), mark as leaf */
            if (!slash) {
                ctx->is_leaf[i] = 1;
                snprintf(ctx->modules[i], PORTAL_MAX_MODULE_NAME, "%s", module_name);
            }
            return;
        }
    }

    if (ctx->count < LS_MAX_ENTRIES) {
        snprintf(ctx->children[ctx->count], 128, "%s", segment);
        if (!slash) {
            ctx->is_leaf[ctx->count] = 1;
            snprintf(ctx->modules[ctx->count], PORTAL_MAX_MODULE_NAME, "%s", module_name);
        } else {
            ctx->is_leaf[ctx->count] = 0;
            ctx->modules[ctx->count][0] = '\0';
        }
        ctx->count++;
    }
}

static int handle_ls(portal_instance_t *inst, const portal_msg_t *msg,
                      portal_resp_t *resp)
{
    const char *prefix = "/";
    for (uint16_t i = 0; i < msg->header_count; i++) {
        if (strcmp(msg->headers[i].key, "prefix") == 0) {
            prefix = msg->headers[i].value;
            break;
        }
    }

    /* Strip trailing slash from prefix (work on a copy) */
    static char clean_prefix[PORTAL_MAX_PATH_LEN];
    snprintf(clean_prefix, sizeof(clean_prefix), "%s", prefix);
    size_t cplen = strlen(clean_prefix);
    while (cplen > 1 && clean_prefix[cplen - 1] == '/')
        clean_prefix[--cplen] = '\0';

    ls_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.prefix = clean_prefix;
    ctx.prefix_len = cplen;

    portal_path_list(&inst->paths, ls_cb, &ctx);

    char buf[8192];
    strbuf_t sb = { .buf = buf, .len = 0, .cap = sizeof(buf) };

    for (int i = 0; i < ctx.count; i++) {
        if (strcmp(ctx.children[i], ".") == 0)
            continue;  /* skip self */
        if (ctx.is_leaf[i])
            strbuf_append(&sb, "  %-30s [%s]\n", ctx.children[i], ctx.modules[i]);
        else
            strbuf_append(&sb, "  %-30s/\n", ctx.children[i]);
    }

    /* Dynamic children: /users shows user names, /groups shows group names */
    if (strcmp(clean_prefix, "/users") == 0) {
        for (int i = 0; i < inst->auth.user_count; i++)
            strbuf_append(&sb, "  %-30s [user]\n", inst->auth.users[i].username);
    } else if (strcmp(clean_prefix, "/groups") == 0) {
        /* Collect unique groups from all users */
        char seen[128][PORTAL_MAX_LABEL_LEN];
        int seen_count = 0;
        for (int i = 0; i < inst->auth.user_count; i++) {
            for (int j = 0; j < inst->auth.users[i].labels.count; j++) {
                const char *lbl = inst->auth.users[i].labels.labels[j];
                int found = 0;
                for (int k = 0; k < seen_count; k++)
                    if (strcmp(seen[k], lbl) == 0) { found = 1; break; }
                if (!found && seen_count < 128) {
                    snprintf(seen[seen_count++], PORTAL_MAX_LABEL_LEN, "%s", lbl);
                    strbuf_append(&sb, "  %-30s [group]\n", lbl);
                }
            }
        }
    }

    if (sb.len == 0)
        strbuf_append(&sb, "  (empty)\n");

    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, buf, sb.len + 1);
    return 0;
}

/* --- /core/resolve (normalize path: cwd + relative → absolute) --- */

static int handle_resolve(const portal_msg_t *msg, portal_resp_t *resp)
{
    const char *cwd = "/";
    const char *target = "";

    for (uint16_t i = 0; i < msg->header_count; i++) {
        if (strcmp(msg->headers[i].key, "cwd") == 0)
            cwd = msg->headers[i].value;
        else if (strcmp(msg->headers[i].key, "target") == 0)
            target = msg->headers[i].value;
    }

    char resolved[PORTAL_MAX_PATH_LEN];

    if (target[0] == '/') {
        /* Absolute path — use as-is */
        snprintf(resolved, sizeof(resolved), "%s", target);
    } else if (strcmp(target, "..") == 0) {
        /* Go up one level */
        snprintf(resolved, sizeof(resolved), "%s", cwd);
        char *last = strrchr(resolved, '/');
        if (last && last != resolved)
            *last = '\0';
        else
            snprintf(resolved, sizeof(resolved), "/");
    } else if (target[0] == '\0') {
        snprintf(resolved, sizeof(resolved), "%s", cwd);
    } else {
        /* Relative path — append to cwd */
        if (strcmp(cwd, "/") == 0)
            snprintf(resolved, sizeof(resolved), "/%s", target);
        else
            snprintf(resolved, sizeof(resolved), "%s/%s", cwd, target);
    }

    /* Remove trailing slash if not root */
    size_t len = strlen(resolved);
    if (len > 1 && resolved[len - 1] == '/')
        resolved[len - 1] = '\0';

    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, resolved, strlen(resolved) + 1);
    return 0;
}

/* --- /auth/login --- */

/* Dual-write: save user to file store AND ALL DB providers */
static void save_user_dual(portal_instance_t *inst, const char *username)
{
    portal_auth_save_user_to_store(&inst->auth, username, &inst->store);
    auth_user_t *u = portal_auth_find_user(&inst->auth, username);
    if (u) {
        char groups[1024] = {0};
        for (int j = 0; j < u->labels.count; j++) {
            if (j > 0) strcat(groups, ",");
            strcat(groups, u->labels.labels[j]);
        }
        portal_storage_save_user(&inst->storage, u->username,
                                  u->password, u->api_key, groups);
    }
}

static const char *get_header(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++) {
        if (strcmp(msg->headers[i].key, key) == 0)
            return msg->headers[i].value;
    }
    return NULL;
}

/* --- /auth/logout --- */

static int handle_auth_logout(portal_instance_t *inst, const portal_msg_t *msg,
                               portal_resp_t *resp)
{
    const char *token = NULL;
    if (msg->ctx && msg->ctx->auth.token)
        token = msg->ctx->auth.token;
    if (!token)
        token = get_header(msg, "token");

    if (!token) {
        portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
        return -1;
    }

    portal_auth_logout(&inst->auth, token);
    portal_resp_set_status(resp, PORTAL_OK);
    const char *ok = "Logged out\n";
    portal_resp_set_body(resp, ok, strlen(ok) + 1);
    return 0;
}

/* --- /auth/whoami --- */

static int handle_auth_whoami(portal_instance_t *inst, const portal_msg_t *msg,
                               portal_resp_t *resp)
{
    const char *token = NULL;
    if (msg->ctx && msg->ctx->auth.token)
        token = msg->ctx->auth.token;
    if (!token)
        token = get_header(msg, "token");

    if (!token) {
        portal_resp_set_status(resp, PORTAL_OK);
        const char *anon = "anonymous (not logged in)\n";
        portal_resp_set_body(resp, anon, strlen(anon) + 1);
        return 0;
    }

    auth_user_t *user = portal_auth_resolve_token(&inst->auth, token);
    if (!user) {
        portal_resp_set_status(resp, PORTAL_UNAUTHORIZED);
        const char *err = "Invalid or expired token\n";
        portal_resp_set_body(resp, err, strlen(err) + 1);
        return -1;
    }

    char buf[1024];
    strbuf_t sb = { .buf = buf, .len = 0, .cap = sizeof(buf) };
    strbuf_append(&sb, "User: %s\n", user->username);
    strbuf_append(&sb, "Labels: ");
    for (int i = 0; i < user->labels.count; i++) {
        if (i > 0) strbuf_append(&sb, ", ");
        strbuf_append(&sb, "%s", user->labels.labels[i]);
    }
    strbuf_append(&sb, "\n");

    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, buf, sb.len + 1);
    return 0;
}

/* --- /events --- */

static void event_list_cb(const portal_event_def_t *def, void *userdata)
{
    strbuf_t *sb = userdata;
    strbuf_append(sb, "  %-40s [%s]", def->path, def->module);
    if (def->labels.count > 0) {
        strbuf_append(sb, " labels:");
        for (int i = 0; i < def->labels.count; i++)
            strbuf_append(sb, "%s%s", i ? "," : "", def->labels.labels[i]);
    }
    strbuf_append(sb, "\n");
    if (def->description[0])
        strbuf_append(sb, "    %s\n", def->description);
}

static int handle_events_list(portal_instance_t *inst, portal_resp_t *resp)
{
    char buf[8192];
    strbuf_t sb = { .buf = buf, .len = 0, .cap = sizeof(buf) };

    int count = portal_events_count(&inst->events_reg);
    strbuf_append(&sb, "Events registered: %d\n", count);
    portal_events_list(&inst->events_reg, event_list_cb, &sb);

    if (count == 0)
        strbuf_append(&sb, "  (none)\n");

    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, buf, sb.len + 1);
    return 0;
}

/* --- /auth/key --- */

static int handle_auth_key(portal_instance_t *inst, const portal_msg_t *msg,
                            portal_resp_t *resp)
{
    const char *token = get_header(msg, "token");
    if (!token && msg->ctx && msg->ctx->auth.token)
        token = msg->ctx->auth.token;

    if (!token) {
        portal_resp_set_status(resp, PORTAL_UNAUTHORIZED);
        return -1;
    }

    auth_user_t *user = portal_auth_resolve_token(&inst->auth, token);
    if (!user) {
        portal_resp_set_status(resp, PORTAL_UNAUTHORIZED);
        return -1;
    }

    if (user->api_key[0] == '\0') {
        /* Auto-generate if none exists */
        portal_auth_generate_key(user->api_key, AUTH_KEY_LEN);
    }

    char buf[256];
    int n = snprintf(buf, sizeof(buf), "User: %s\nAPI Key: %s\n",
                     user->username, user->api_key);
    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, buf, (size_t)n + 1);
    return 0;
}

static int handle_auth_key_rotate(portal_instance_t *inst,
                                   const portal_msg_t *msg,
                                   portal_resp_t *resp)
{
    const char *token = get_header(msg, "token");
    if (!token && msg->ctx && msg->ctx->auth.token)
        token = msg->ctx->auth.token;

    if (!token) {
        portal_resp_set_status(resp, PORTAL_UNAUTHORIZED);
        return -1;
    }

    auth_user_t *user = portal_auth_resolve_token(&inst->auth, token);
    if (!user) {
        portal_resp_set_status(resp, PORTAL_UNAUTHORIZED);
        return -1;
    }

    portal_auth_rotate_key(&inst->auth, user->username);

    char buf[256];
    int n = snprintf(buf, sizeof(buf), "New API Key: %s\n", user->api_key);
    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, buf, (size_t)n + 1);
    return 0;
}

/* --- /auth/login with API key support --- */

static int handle_auth_login_enhanced(portal_instance_t *inst,
                                       const portal_msg_t *msg,
                                       portal_resp_t *resp)
{
    const char *username = get_header(msg, "username");
    const char *password = get_header(msg, "password");
    const char *api_key  = get_header(msg, "api_key");

    const char *token = NULL;

    if (api_key && api_key[0] != '\0') {
        token = portal_auth_login_key(&inst->auth, api_key);
    } else if (username && password) {
        token = portal_auth_login(&inst->auth, username, password);
    } else {
        portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
        const char *err = "Provide username+password or api_key\n";
        portal_resp_set_body(resp, err, strlen(err) + 1);
        return -1;
    }

    if (!token) {
        portal_resp_set_status(resp, PORTAL_UNAUTHORIZED);
        const char *err = "Authentication failed\n";
        portal_resp_set_body(resp, err, strlen(err) + 1);
        return -1;
    }

    char buf[256];
    int n = snprintf(buf, sizeof(buf), "%s\n", token);
    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, buf, (size_t)n + 1);
    return 0;
}

/* --- Main dispatcher --- */

int core_handle_message(portal_core_t *core, const portal_msg_t *msg,
                         portal_resp_t *resp)
{
    portal_instance_t *inst = core->_internal;
    const char *path = msg->path;

    if (strcmp(path, "/core/status") == 0) {
        return handle_status(inst, msg, resp);
    }

    if (strcmp(path, "/core/modules") == 0 && msg->method == PORTAL_METHOD_GET) {
        return handle_modules_list(inst, resp);
    }

    if (strcmp(path, "/core/paths") == 0 && msg->method == PORTAL_METHOD_GET) {
        return handle_paths_list(inst, resp);
    }

    if (strcmp(path, "/core/ls") == 0) {
        return handle_ls(inst, msg, resp);
    }

    if (strcmp(path, "/core/resolve") == 0) {
        return handle_resolve(msg, resp);
    }

    /* /core/modules/<name> with CALL method = load/unload */
    if (strncmp(path, "/core/modules/", 14) == 0 && msg->method == PORTAL_METHOD_CALL) {
        const char *mod_name = path + 14;
        if (mod_name[0] != '\0')
            return handle_module_action(inst, mod_name, msg, resp);
    }

    /* Auth paths */
    if (strcmp(path, "/auth/login") == 0) {
        return handle_auth_login_enhanced(inst, msg, resp);
    }

    if (strcmp(path, "/auth/logout") == 0) {
        return handle_auth_logout(inst, msg, resp);
    }

    if (strcmp(path, "/auth/whoami") == 0) {
        return handle_auth_whoami(inst, msg, resp);
    }

    if (strcmp(path, "/auth/key") == 0 && msg->method == PORTAL_METHOD_GET) {
        return handle_auth_key(inst, msg, resp);
    }

    if (strcmp(path, "/auth/key/rotate") == 0) {
        return handle_auth_key_rotate(inst, msg, resp);
    }

    /* Event paths */
    if (strcmp(path, "/events") == 0 && msg->method == PORTAL_METHOD_GET) {
        return handle_events_list(inst, resp);
    }

    /* Subscribe/unsubscribe to events via /events paths */
    if (strncmp(path, "/events/", 8) == 0) {
        if (msg->method == PORTAL_METHOD_SUB) {
            const char *subscriber = "anonymous";
            portal_labels_t sub_labels = {0};
            int notify_fd = -1;

            if (msg->ctx && msg->ctx->auth.user)
                subscriber = msg->ctx->auth.user;
            if (msg->ctx)
                memcpy(&sub_labels, &msg->ctx->auth.labels, sizeof(portal_labels_t));

            /* Get notify_fd from header (CLI sets this) */
            const char *fd_str = get_header(msg, "notify_fd");
            if (fd_str) notify_fd = atoi(fd_str);

            const char *token = NULL;
            if (msg->ctx && msg->ctx->auth.token)
                token = msg->ctx->auth.token;

            int rc;
            if (notify_fd >= 0)
                rc = portal_events_subscribe_fd(&inst->events_reg, path,
                                                 subscriber, &sub_labels,
                                                 token, notify_fd);
            else
                rc = portal_events_subscribe(&inst->events_reg, path,
                                              subscriber, &sub_labels,
                                              NULL, NULL);

            portal_resp_set_status(resp, rc == 0 ? PORTAL_OK : PORTAL_FORBIDDEN);
            const char *body = rc == 0 ? "Subscribed\n" : "Subscribe denied\n";
            portal_resp_set_body(resp, body, strlen(body) + 1);
            return rc;
        }

        if (msg->method == PORTAL_METHOD_UNSUB) {
            const char *subscriber = "anonymous";
            if (msg->ctx && msg->ctx->auth.user)
                subscriber = msg->ctx->auth.user;

            int rc = portal_events_unsubscribe(&inst->events_reg, path, subscriber);
            portal_resp_set_status(resp, rc == 0 ? PORTAL_OK : PORTAL_NOT_FOUND);
            return rc;
        }
    }

    /* /users — list users */
    if (strcmp(path, "/users") == 0 && msg->method == PORTAL_METHOD_GET) {
        char buf[4096];
        strbuf_t sb = { .buf = buf, .len = 0, .cap = sizeof(buf) };
        strbuf_append(&sb, "Users:\n");
        for (int i = 0; i < inst->auth.user_count; i++) {
            auth_user_t *u = &inst->auth.users[i];
            strbuf_append(&sb, "  %-16s groups:", u->username);
            for (int j = 0; j < u->labels.count; j++)
                strbuf_append(&sb, "%s%s", j ? "," : " ", u->labels.labels[j]);
            strbuf_append(&sb, "\n");
        }
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, sb.len + 1);
        return 0;
    }

    /* /users/<name> — user info or create */
    if (strncmp(path, "/users/", 7) == 0) {
        const char *uname = path + 7;
        const char *slash = strchr(uname, '/');
        char name[PORTAL_MAX_LABEL_LEN];
        if (slash) {
            size_t nlen = (size_t)(slash - uname);
            if (nlen >= sizeof(name)) nlen = sizeof(name) - 1;
            memcpy(name, uname, nlen); name[nlen] = '\0';
        } else {
            snprintf(name, sizeof(name), "%s", uname);
        }

        /* /users/<name>/password CALL — change password */
        if (slash && strcmp(slash, "/password") == 0 && msg->method == PORTAL_METHOD_CALL) {
            const char *newpass = get_header(msg, "password");
            if (!newpass) {
                portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
                return -1;
            }
            auth_user_t *u = portal_auth_find_user(&inst->auth, name);
            if (!u) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
            snprintf(u->password, sizeof(u->password), "%s", newpass);
            save_user_dual(inst, name);
            portal_resp_set_status(resp, PORTAL_OK);
            const char *ok = "Password changed\n";
            portal_resp_set_body(resp, ok, strlen(ok) + 1);
            return 0;
        }

        if (msg->method == PORTAL_METHOD_GET) {
            auth_user_t *u = portal_auth_find_user(&inst->auth, name);
            if (!u) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
            char buf[1024];
            strbuf_t sb = { .buf = buf, .len = 0, .cap = sizeof(buf) };
            strbuf_append(&sb, "User: %s\n", u->username);
            strbuf_append(&sb, "Groups:");
            for (int j = 0; j < u->labels.count; j++)
                strbuf_append(&sb, " %s", u->labels.labels[j]);
            strbuf_append(&sb, "\nAPI Key: %s\n", u->api_key[0] ? "set" : "none");
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, buf, sb.len + 1);
            return 0;
        }

        if (msg->method == PORTAL_METHOD_SET) {
            const char *password = get_header(msg, "password");
            if (!password) password = "";
            portal_labels_t labels = {0};
            const char *groups = get_header(msg, "groups");
            if (groups && groups[0]) {
                char gbuf[512];
                snprintf(gbuf, sizeof(gbuf), "%s", groups);
                char *sv = NULL;
                char *tok = strtok_r(gbuf, ",", &sv);
                while (tok) { portal_labels_add(&labels, tok); tok = strtok_r(NULL, ",", &sv); }
            }
            int rc = portal_auth_add_user(&inst->auth, name, password, &labels);
            if (rc == 0)
                save_user_dual(inst, name);
            portal_resp_set_status(resp, rc == 0 ? PORTAL_CREATED : PORTAL_CONFLICT);
            return rc;
        }
    }

    /* /groups — list groups */
    if (strcmp(path, "/groups") == 0 && msg->method == PORTAL_METHOD_GET) {
        char buf[4096];
        strbuf_t sb = { .buf = buf, .len = 0, .cap = sizeof(buf) };
        strbuf_append(&sb, "Groups:\n");
        /* Collect unique labels from all users */
        char seen[128][PORTAL_MAX_LABEL_LEN];
        int seen_count = 0;
        for (int i = 0; i < inst->auth.user_count; i++) {
            for (int j = 0; j < inst->auth.users[i].labels.count; j++) {
                const char *lbl = inst->auth.users[i].labels.labels[j];
                int found = 0;
                for (int k = 0; k < seen_count; k++)
                    if (strcmp(seen[k], lbl) == 0) { found = 1; break; }
                if (!found && seen_count < 128)
                    snprintf(seen[seen_count++], PORTAL_MAX_LABEL_LEN, "%s", lbl);
            }
        }
        for (int i = 0; i < seen_count; i++) {
            /* Count members */
            int members = 0;
            for (int j = 0; j < inst->auth.user_count; j++)
                if (portal_labels_has(&inst->auth.users[j].labels, seen[i]))
                    members++;
            strbuf_append(&sb, "  %-20s %d members\n", seen[i], members);
        }
        if (seen_count == 0) strbuf_append(&sb, "  (none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, sb.len + 1);
        return 0;
    }

    /* /groups/<name> — group info or create, /groups/<name>/add, /groups/<name>/remove */
    if (strncmp(path, "/groups/", 8) == 0) {
        const char *gpath = path + 8;
        char gname[PORTAL_MAX_LABEL_LEN];
        const char *action = NULL;
        const char *slash = strchr(gpath, '/');
        if (slash) {
            size_t nlen = (size_t)(slash - gpath);
            if (nlen >= sizeof(gname)) nlen = sizeof(gname) - 1;
            memcpy(gname, gpath, nlen); gname[nlen] = '\0';
            action = slash + 1;
        } else {
            snprintf(gname, sizeof(gname), "%s", gpath);
        }

        /* /groups/<name>/add CALL — add user to group */
        if (action && strcmp(action, "add") == 0 && msg->method == PORTAL_METHOD_CALL) {
            const char *uname = get_header(msg, "user");
            if (!uname) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
            auth_user_t *u = portal_auth_find_user(&inst->auth, uname);
            if (!u) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
            portal_labels_add(&u->labels, gname);
            save_user_dual(inst, uname);
            portal_resp_set_status(resp, PORTAL_OK);
            char buf[128];
            snprintf(buf, sizeof(buf), "Added '%s' to group '%s'\n", uname, gname);
            portal_resp_set_body(resp, buf, strlen(buf) + 1);
            return 0;
        }

        /* /groups/<name>/remove CALL — remove user from group */
        if (action && strcmp(action, "remove") == 0 && msg->method == PORTAL_METHOD_CALL) {
            const char *uname = get_header(msg, "user");
            if (!uname) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
            auth_user_t *u = portal_auth_find_user(&inst->auth, uname);
            if (!u) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
            portal_labels_remove(&u->labels, gname);
            save_user_dual(inst, uname);
            portal_resp_set_status(resp, PORTAL_OK);
            char buf[128];
            snprintf(buf, sizeof(buf), "Removed '%s' from group '%s'\n", uname, gname);
            portal_resp_set_body(resp, buf, strlen(buf) + 1);
            return 0;
        }

        /* /groups/<name> SET — create group */
        if (!action && msg->method == PORTAL_METHOD_SET) {
            const char *desc = get_header(msg, "description");
            const char *created_by = "cli";
            if (msg->ctx && msg->ctx->auth.user)
                created_by = msg->ctx->auth.user;
            char gpath_buf[PORTAL_MAX_PATH_LEN];
            portal_store_path(&inst->store, "groups", gname, gpath_buf, sizeof(gpath_buf));
            portal_store_write_value(gpath_buf, "description", desc ? desc : "");
            portal_store_write_value(gpath_buf, "created_by", created_by);
            portal_resp_set_status(resp, PORTAL_CREATED);
            char buf[128];
            snprintf(buf, sizeof(buf), "Group '%s' created\n", gname);
            portal_resp_set_body(resp, buf, strlen(buf) + 1);
            return 0;
        }

        /* /groups/<name> GET — group info + members */
        if (!action && msg->method == PORTAL_METHOD_GET) {
            char buf[2048];
            strbuf_t sb = { .buf = buf, .len = 0, .cap = sizeof(buf) };
            strbuf_append(&sb, "Group: %s\n", gname);
            /* Read metadata from store */
            char gpath_buf[PORTAL_MAX_PATH_LEN];
            portal_store_path(&inst->store, "groups", gname, gpath_buf, sizeof(gpath_buf));
            char *desc = portal_store_read_value(gpath_buf, "description");
            if (desc) { strbuf_append(&sb, "Description: %s\n", desc); free(desc); }
            strbuf_append(&sb, "Members:");
            int mc = 0;
            for (int i = 0; i < inst->auth.user_count; i++) {
                if (portal_labels_has(&inst->auth.users[i].labels, gname)) {
                    strbuf_append(&sb, " %s", inst->auth.users[i].username);
                    mc++;
                }
            }
            if (mc == 0) strbuf_append(&sb, " (none)");
            strbuf_append(&sb, "\n");
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, buf, sb.len + 1);
            return 0;
        }
    }

    /* /core/config/get — read a config value from database or .conf */
    if (strcmp(path, "/core/config/get") == 0) {
        const char *mod = NULL, *key = NULL;
        for (uint16_t i = 0; i < msg->header_count; i++) {
            if (strcmp(msg->headers[i].key, "module") == 0) mod = msg->headers[i].value;
            if (strcmp(msg->headers[i].key, "key") == 0) key = msg->headers[i].value;
        }
        if (!mod || !key) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            const char *err = "Need: module, key headers\n";
            portal_resp_set_body(resp, err, strlen(err) + 1);
            return -1;
        }
        const char *val = core->config_get(core, mod, key);
        if (val) {
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, val, strlen(val) + 1);
        } else {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            char buf[256];
            int n = snprintf(buf, sizeof(buf), "Config not found: %s.%s\n", mod, key);
            portal_resp_set_body(resp, buf, (size_t)n + 1);
        }
        return 0;
    }

    /* /core/config/set — write a config value to database + memory */
    if (strcmp(path, "/core/config/set") == 0) {
        const char *mod = NULL, *key = NULL, *val = NULL;
        for (uint16_t i = 0; i < msg->header_count; i++) {
            if (strcmp(msg->headers[i].key, "module") == 0) mod = msg->headers[i].value;
            if (strcmp(msg->headers[i].key, "key") == 0) key = msg->headers[i].value;
            if (strcmp(msg->headers[i].key, "value") == 0) val = msg->headers[i].value;
        }
        if (!mod || !key || !val) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            const char *err = "Need: module, key, value headers\n";
            portal_resp_set_body(resp, err, strlen(err) + 1);
            return -1;
        }
        /* Write to in-memory hash table */
        char full_key[256];
        snprintf(full_key, sizeof(full_key), "mod_%s.%s", mod, key);
        portal_ht_set(&inst->config.sections, full_key, strdup(val));
        /* Write to ALL storage providers */
        char db_module[128];
        snprintf(db_module, sizeof(db_module), "mod_%s", mod);
        portal_storage_save_config(&inst->storage, db_module, key, val);
        portal_resp_set_status(resp, PORTAL_OK);
        char buf[256];
        int n = snprintf(buf, sizeof(buf), "Set %s.%s = %s\n", mod, key, val);
        portal_resp_set_body(resp, buf, (size_t)n + 1);
        core->event_emit(core, "/events/config/set", full_key, strlen(full_key));
        return 0;
    }

    /* /core/config/list — list all config values for a module (or all) */
    if (strcmp(path, "/core/config/list") == 0) {
        const char *mod = NULL;
        for (uint16_t i = 0; i < msg->header_count; i++)
            if (strcmp(msg->headers[i].key, "module") == 0) mod = msg->headers[i].value;

        char buf[65536];
        strbuf_t sb = { .buf = buf, .len = 0, .cap = sizeof(buf) };
        if (mod)
            strbuf_append(&sb, "Config for module '%s':\n", mod);
        else
            strbuf_append(&sb, "All module config:\n");

        char prefix[128] = "";
        if (mod) snprintf(prefix, sizeof(prefix), "mod_%s.", mod);
        size_t plen = strlen(prefix);

        portal_ht_t *ht = &inst->config.sections;
        for (size_t b = 0; b < ht->capacity && sb.len < sb.cap - 256; b++) {
            if (ht->entries[b].occupied != 1) continue;
            const char *k = ht->entries[b].key;
            const char *v = (const char *)ht->entries[b].value;
            if (plen > 0 && strncmp(k, prefix, plen) != 0) continue;
            if (plen == 0 && strncmp(k, "mod_", 4) != 0) continue;
            strbuf_append(&sb, "  %-40s = %s\n", k, v);
        }
        if (sb.len < 30)
            strbuf_append(&sb, "  (none)\n");

        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, sb.len + 1);
        return 0;
    }

    /* /core/locks — list active resource locks, optional filter */
    if (strcmp(path, "/core/locks") == 0 && msg->method == PORTAL_METHOD_GET) {
        const char *filter = NULL;
        for (uint16_t hi = 0; hi < msg->header_count; hi++)
            if (strcmp(msg->headers[hi].key, "resource") == 0)
                filter = msg->headers[hi].value;

        char buf[4096];
        size_t off = 0;
        if (!filter)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Resource locks:\n");
        int found = 0;
        time_t now = time(NULL);
        for (int i = 0; i < LOCK_MAX; i++) {
            if (!inst->locks[i].active) continue;
            if (filter && strncmp(inst->locks[i].resource, filter, strlen(filter)) != 0)
                continue;
            found++;
            long age = (long)(now - inst->locks[i].locked_at);
            long ka = (long)(now - inst->locks[i].last_keepalive);
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "  %-30s owner:%-20s age:%lds keepalive:%lds ago\n",
                inst->locks[i].resource, inst->locks[i].owner, age, ka);
        }
        if (!found)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                filter ? "  (no locks matching '%s')\n" : "  (none)\n",
                filter ? filter : "");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    /* /core/locks/lock — acquire a resource lock */
    if (strcmp(path, "/core/locks/lock") == 0 && msg->method == PORTAL_METHOD_CALL) {
        const char *resource = NULL, *owner = NULL;
        for (uint16_t hi = 0; hi < msg->header_count; hi++) {
            if (strcmp(msg->headers[hi].key, "resource") == 0) resource = msg->headers[hi].value;
            if (strcmp(msg->headers[hi].key, "owner") == 0) owner = msg->headers[hi].value;
        }
        if (!resource || !owner) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            char err[] = "Need: resource, owner headers\n";
            portal_resp_set_body(resp, err, sizeof(err) - 1);
            return -1;
        }
        char buf[256];
        int n;
        int rc = core->resource_lock(core, resource, owner);
        if (rc == 0) {
            n = snprintf(buf, sizeof(buf), "Locked: %s (owner: %s)\n", resource, owner);
            portal_resp_set_status(resp, PORTAL_OK);
        } else {
            const char *cur = core->resource_owner(core, resource);
            n = snprintf(buf, sizeof(buf), "Already locked by: %s\n", cur ? cur : "?");
            portal_resp_set_status(resp, PORTAL_CONFLICT);
        }
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* /core/locks/unlock — release a resource lock */
    if (strcmp(path, "/core/locks/unlock") == 0 && msg->method == PORTAL_METHOD_CALL) {
        const char *resource = NULL, *owner = NULL;
        for (uint16_t hi = 0; hi < msg->header_count; hi++) {
            if (strcmp(msg->headers[hi].key, "resource") == 0) resource = msg->headers[hi].value;
            if (strcmp(msg->headers[hi].key, "owner") == 0) owner = msg->headers[hi].value;
        }
        if (!resource || !owner) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
        char buf[256];
        int n;
        int rc = core->resource_unlock(core, resource, owner);
        if (rc == 0) {
            n = snprintf(buf, sizeof(buf), "Unlocked: %s\n", resource);
            portal_resp_set_status(resp, PORTAL_OK);
        } else if (rc == -2) {
            n = snprintf(buf, sizeof(buf), "Not your lock\n");
            portal_resp_set_status(resp, PORTAL_FORBIDDEN);
        } else {
            n = snprintf(buf, sizeof(buf), "Not locked\n");
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
        }
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* /core/locks/keepalive — refresh lock keepalive */
    if (strcmp(path, "/core/locks/keepalive") == 0 && msg->method == PORTAL_METHOD_CALL) {
        const char *resource = NULL, *owner = NULL;
        for (uint16_t hi = 0; hi < msg->header_count; hi++) {
            if (strcmp(msg->headers[hi].key, "resource") == 0) resource = msg->headers[hi].value;
            if (strcmp(msg->headers[hi].key, "owner") == 0) owner = msg->headers[hi].value;
        }
        if (!resource || !owner) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
        int rc = core->resource_keepalive(core, resource, owner);
        portal_resp_set_status(resp, rc == 0 ? PORTAL_OK : PORTAL_NOT_FOUND);
        return 0;
    }

    /* /core/storage — list all active backends */
    if (strcmp(path, "/core/storage") == 0 && msg->method == PORTAL_METHOD_GET) {
        char buf[2048];
        strbuf_t sb = { .buf = buf, .len = 0, .cap = sizeof(buf) };
        strbuf_append(&sb, "Storage backends:\n");
        strbuf_append(&sb, "  file: active (%s)\n", inst->store.base_dir);
        for (int i = 0; i < inst->storage.count; i++)
            strbuf_append(&sb, "  %s: active\n", inst->storage.providers[i]->name);
        if (inst->storage.count == 0)
            strbuf_append(&sb, "  (no database backends)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, sb.len + 1);
        return 0;
    }

    /* /core/storage/<provider>/resources/status — provider details */
    /* /core/storage/<provider>/functions/sync — force sync to provider */
    if (strncmp(path, "/core/storage/", 14) == 0) {
        const char *rest = path + 14;

        /* Parse: <provider_name>/resources/status or <provider_name>/functions/sync */
        char prov_name[64];
        const char *slash = strchr(rest, '/');
        if (slash) {
            size_t nlen = (size_t)(slash - rest);
            if (nlen >= sizeof(prov_name)) nlen = sizeof(prov_name) - 1;
            memcpy(prov_name, rest, nlen);
            prov_name[nlen] = '\0';
            const char *sub = slash;  /* /resources/status or /functions/sync */

            portal_storage_provider_t *prov =
                portal_storage_find(&inst->storage, prov_name);

            if (!prov) {
                portal_resp_set_status(resp, PORTAL_NOT_FOUND);
                return -1;
            }

            /* /resources/status */
            if (strcmp(sub, "/resources/status") == 0) {
                char buf[1024];
                if (prov->status) {
                    prov->status(prov->ctx, buf, sizeof(buf));
                } else {
                    snprintf(buf, sizeof(buf), "Backend: %s (active)\n", prov->name);
                }
                portal_resp_set_status(resp, PORTAL_OK);
                portal_resp_set_body(resp, buf, strlen(buf) + 1);
                return 0;
            }

            /* /functions/sync */
            if (strcmp(sub, "/functions/sync") == 0) {
                int synced = 0;
                for (int i = 0; i < inst->auth.user_count; i++) {
                    auth_user_t *u = &inst->auth.users[i];
                    char groups[1024] = {0};
                    for (int j = 0; j < u->labels.count; j++) {
                        if (j > 0) strcat(groups, ",");
                        strcat(groups, u->labels.labels[j]);
                    }
                    if (prov->user_save(prov->ctx, u->username,
                        u->password, u->api_key, groups) == 0)
                        synced++;
                }
                char buf[128];
                int n = snprintf(buf, sizeof(buf), "Synced %d users to %s\n",
                                 synced, prov->name);
                portal_resp_set_status(resp, PORTAL_OK);
                portal_resp_set_body(resp, buf, (size_t)n + 1);
                return 0;
            }
        }
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
