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
 * portal_instance.c — Portal core instance wiring
 *
 * Connects all subsystems: paths, modules, auth, events, storage.
 * Implements the core API function pointers that modules receive.
 * Includes message routing with ACL, tracing, crash isolation,
 * wildcard matching, and dual-write to storage providers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include "portal_instance.h"
#include "core_log.h"
#include "core_message.h"
#include "core_handlers.h"

/* --- Crash isolation --- */

static sigjmp_buf g_crash_jmp;
static volatile int g_crash_active = 0;
static struct sigaction g_crash_sa;

/* Forward declaration for trace */
static void trace_message(portal_instance_t *inst, const portal_msg_t *msg,
                           const portal_resp_t *resp);

static void crash_signal_handler(int sig)
{
    if (g_crash_active)
        siglongjmp(g_crash_jmp, sig);
    _exit(128 + sig);
}

__attribute__((constructor))
static void init_crash_handler(void)
{
    memset(&g_crash_sa, 0, sizeof(g_crash_sa));
    g_crash_sa.sa_handler = crash_signal_handler;
    sigemptyset(&g_crash_sa.sa_mask);
}

/* --- Core API implementations (called by modules) --- */

static int api_path_register(portal_core_t *core, const char *path,
                              const char *module_name)
{
    portal_instance_t *inst = core->_internal;
    return portal_path_register(&inst->paths, path, module_name);
}

static int api_path_unregister(portal_core_t *core, const char *path)
{
    portal_instance_t *inst = core->_internal;
    return portal_path_unregister(&inst->paths, path);
}

static int api_path_set_access(portal_core_t *core, const char *path, uint8_t mode)
{
    portal_instance_t *inst = core->_internal;
    path_entry_t *entry = portal_path_lookup_entry(&inst->paths, path);
    if (!entry) return -1;
    entry->access_mode = mode;
    return 0;
}

static int api_path_add_label(portal_core_t *core, const char *path,
                               const char *label)
{
    portal_instance_t *inst = core->_internal;
    return portal_path_add_label(&inst->paths, path, label);
}

static int api_path_remove_label(portal_core_t *core, const char *path,
                                  const char *label)
{
    portal_instance_t *inst = core->_internal;
    return portal_path_remove_label(&inst->paths, path, label);
}

static int api_path_set_description(portal_core_t *core, const char *path,
                                     const char *description)
{
    portal_instance_t *inst = core->_internal;
    return portal_path_set_description(&inst->paths, path, description);
}

static int api_send(portal_core_t *core, portal_msg_t *msg, portal_resp_t *resp)
{
    portal_instance_t *inst = core->_internal;

    /* Auto-populate tracing */
    if (!msg->ctx)
        msg->ctx = calloc(1, sizeof(portal_ctx_t));
    if (msg->ctx) {
        if (msg->ctx->trace.trace_id == 0)
            msg->ctx->trace.trace_id = portal_msg_next_id();
        msg->ctx->trace.timestamp_us = portal_time_us();
        msg->ctx->trace.hops++;
    }

    /* Self-reference detection: if path starts with own node name, strip it.
     * e.g., on node "devtest2", path "/devtest2/hello" → "/hello" (local) */
    /* Try mod_node.node_name then node.node_name */
    const char *own_name = portal_config_get(&inst->config, "mod_node", "node_name");
    if (!own_name) own_name = portal_config_get(&inst->config, "node", "node_name");
    if (own_name && own_name[0] && msg->path && msg->path[0] == '/') {
        size_t nlen = strlen(own_name);
        if (strncmp(msg->path + 1, own_name, nlen) == 0 &&
            (msg->path[nlen + 1] == '/' || msg->path[nlen + 1] == '\0')) {
            /* Strip own node prefix — copy before set_path frees the old one */
            char stripped[PORTAL_MAX_PATH_LEN];
            const char *rest = msg->path + nlen + 1;
            snprintf(stripped, sizeof(stripped), "%s", rest[0] ? rest : "/");
            LOG_TRACE("router", "Self-reference: /%s → '%s'", own_name, stripped);
            portal_msg_set_path(msg, stripped);
        }
    }

    /* Trace: notify verbose/debug CLI subscribers */
    if (inst->trace_count > 0 && msg->path)
        trace_message(inst, msg, NULL);

    /* EVENT method: fan out via unified events registry */
    if (msg->method == PORTAL_METHOD_EVENT)
        portal_events_emit(&inst->events_reg, msg->path,
                           msg->body, msg->body_len);

    const char *mod_name = portal_path_lookup(&inst->paths, msg->path);

    /* Prefix routing: /core and /auth paths → core handler */
    if (!mod_name && (strncmp(msg->path, "/core/", 6) == 0 ||
                      strncmp(msg->path, "/auth/", 6) == 0 ||
                      strncmp(msg->path, "/events/", 8) == 0 ||
                      strncmp(msg->path, "/users/", 7) == 0 ||
                      strncmp(msg->path, "/groups/", 8) == 0))
        mod_name = "core";

    /* Wildcard fallback: progressively shorten path and try with wildcard */
    if (!mod_name) {
        char wild[PORTAL_MAX_PATH_LEN];
        snprintf(wild, sizeof(wild), "%s", msg->path);
        char *slash = strrchr(wild, '/');
        while (slash && !mod_name) {
            snprintf(slash + 1, sizeof(wild) - (size_t)(slash - wild) - 1, "*");
            mod_name = portal_path_lookup(&inst->paths, wild);
            if (mod_name) break;
            *slash = '\0';
            slash = strrchr(wild, '/');
        }
        if (!mod_name)
            mod_name = portal_path_lookup(&inst->paths, "/*");
    }

    if (!mod_name) {
        resp->status = PORTAL_NOT_FOUND;
        return -1;
    }

    /* Label-based access check (skip for core prefix routes without entry) */
    if (portal_path_lookup(&inst->paths, msg->path) &&
        !portal_path_check_access(&inst->paths, msg->path, msg->ctx)) {
        LOG_WARN("router", "[%lu] ACCESS DENIED: %s (user: %s)",
                 msg->id, msg->path,
                 (msg->ctx && msg->ctx->auth.user) ? msg->ctx->auth.user : "anonymous");
        resp->status = PORTAL_FORBIDDEN;
        return -1;
    }

    /* "core" is a virtual module — handled internally */
    if (strcmp(mod_name, "core") == 0) {
        LOG_TRACE("router", "[%lu] %s → core (t:%lu h:%d)",
                  msg->id, msg->path,
                  msg->ctx ? msg->ctx->trace.trace_id : 0,
                  msg->ctx ? msg->ctx->trace.hops : 0);
        int rc = core_handle_message(core, msg, resp);
        if (inst->trace_count > 0 && msg->path)
            trace_message(inst, msg, resp);
        return rc;
    }

    portal_module_entry_t *entry = portal_module_find(&inst->modules, mod_name);
    if (!entry || !entry->loaded || entry->unloading) {
        resp->status = PORTAL_UNAVAILABLE;
        return -1;
    }

    /* Reference count: protect against unload during handle */
    entry->use_count++;
    /* Observability counters (Law 13: O(1) increment, no locks — single thread) */
    entry->msg_count++;
    entry->last_msg_us = portal_time_us();

    LOG_TRACE("router", "[%lu] %s → %s (t:%lu h:%d)",
              msg->id, msg->path, mod_name,
              msg->ctx ? msg->ctx->trace.trace_id : 0,
              msg->ctx ? msg->ctx->trace.hops : 0);

    /* Crash isolation: catch SIGSEGV/SIGBUS in module handler */
    struct sigaction sa_old_segv, sa_old_bus;

    sigaction(SIGSEGV, &g_crash_sa, &sa_old_segv);
    sigaction(SIGBUS, &g_crash_sa, &sa_old_bus);

    int rc;
    g_crash_active = 1;
    int crash_sig = sigsetjmp(g_crash_jmp, 1);
    if (crash_sig == 0) {
        rc = entry->fn_handle(core, msg, resp);
    } else {
        LOG_ERROR("router", "MODULE CRASH: '%s' caught signal %d on path '%s'",
                  mod_name, crash_sig, msg->path);
        resp->status = PORTAL_INTERNAL_ERROR;
        const char *err = "Module crashed\n";
        portal_resp_set_body(resp, err, strlen(err) + 1);
        entry->loaded = 0;
        rc = -1;
    }
    g_crash_active = 0;

    sigaction(SIGSEGV, &sa_old_segv, NULL);
    sigaction(SIGBUS, &sa_old_bus, NULL);

    entry->use_count--;

    /* Trace response (debug mode) */
    if (inst->trace_count > 0 && msg->path)
        trace_message(inst, msg, resp);

    return rc;
}

static int api_subscribe(portal_core_t *core, const char *path_pattern,
                          portal_event_fn handler, void *userdata)
{
    portal_instance_t *inst = core->_internal;
    /* Unified: route through events_reg with wildcard-pattern semantics.
     * Internal module subscribers get trusted-by-default ACL (labels=NULL
     * → {root}). External clients should use portal_events_subscribe_fd. */
    return portal_events_subscribe_pattern(&inst->events_reg, path_pattern,
                                            "module", NULL,
                                            handler, userdata);
}

static int api_unsubscribe(portal_core_t *core, const char *path_pattern,
                            portal_event_fn handler)
{
    portal_instance_t *inst = core->_internal;
    return portal_events_unsubscribe_handler(&inst->events_reg,
                                              path_pattern, handler);
}

static int api_module_loaded(portal_core_t *core, const char *name)
{
    portal_instance_t *inst = core->_internal;
    return portal_module_is_loaded(&inst->modules, name);
}

static int api_fd_add(portal_core_t *core, int fd, uint32_t events,
                       portal_fd_fn callback, void *userdata)
{
    portal_instance_t *inst = core->_internal;
    return portal_event_add(&inst->events, fd, events, callback, userdata);
}

static int api_fd_del(portal_core_t *core, int fd)
{
    portal_instance_t *inst = core->_internal;
    return portal_event_del(&inst->events, fd);
}

static int api_fd_modify(portal_core_t *core, int fd, uint32_t events)
{
    portal_instance_t *inst = core->_internal;
    return portal_event_modify(&inst->events, fd, events);
}

static void *api_ev_loop_get(portal_core_t *core)
{
    portal_instance_t *inst = core->_internal;
    return inst->events.loop;
}

static int api_event_register(portal_core_t *core, const char *event_path,
                              const char *description,
                              const portal_labels_t *labels)
{
    portal_instance_t *inst = core->_internal;
    /* Determine module name from the event path: /events/<module>/... */
    char module[PORTAL_MAX_MODULE_NAME] = "unknown";
    if (strncmp(event_path, "/events/", 8) == 0) {
        const char *start = event_path + 8;
        const char *slash = strchr(start, '/');
        if (slash) {
            size_t len = (size_t)(slash - start);
            if (len < sizeof(module)) {
                memcpy(module, start, len);
                module[len] = '\0';
            }
        }
    }

    int rc = portal_events_register(&inst->events_reg, event_path, module,
                                     description, labels);
    if (rc == 0) {
        /* Also register as a path so it's visible in ls */
        portal_path_register(&inst->paths, event_path, module);
        if (labels)
            for (int i = 0; i < labels->count; i++)
                portal_path_add_label(&inst->paths, event_path,
                                       labels->labels[i]);
    }
    return rc;
}

static int api_event_unregister(portal_core_t *core, const char *event_path)
{
    portal_instance_t *inst = core->_internal;
    portal_path_unregister(&inst->paths, event_path);
    return portal_events_unregister(&inst->events_reg, event_path);
}

static int api_event_emit(portal_core_t *core, const char *event_path,
                           const void *data, size_t data_len)
{
    portal_instance_t *inst = core->_internal;
    /* Unified delivery: events_reg handles both declared subscribers
     * (event_subscribe) and pattern subscribers (core->subscribe). */
    return portal_events_emit(&inst->events_reg, event_path, data, data_len);
}

static int api_storage_register(portal_core_t *core,
                                portal_storage_provider_t *provider)
{
    portal_instance_t *inst = core->_internal;

    if (!provider) {
        /* Deregister — find and remove by name (caller should have set name) */
        return 0;
    }

    if (portal_storage_add(&inst->storage, provider) < 0)
        return -1;

    /* Register provider paths: /core/storage/<name>/resources and functions */
    char path[PORTAL_MAX_PATH_LEN];
    snprintf(path, sizeof(path), "/core/storage/%s/resources/status", provider->name);
    portal_path_register(&inst->paths, path, "core");
    snprintf(path, sizeof(path), "/core/storage/%s/functions/sync", provider->name);
    portal_path_register(&inst->paths, path, "core");

    /* Sync existing users to the new provider */
    for (int i = 0; i < inst->auth.user_count; i++) {
        auth_user_t *u = &inst->auth.users[i];
        char groups[1024] = {0};
        for (int j = 0; j < u->labels.count; j++) {
            if (j > 0) strcat(groups, ",");
            strcat(groups, u->labels.labels[j]);
        }
        provider->user_save(provider->ctx, u->username, u->password,
                             u->api_key, groups);
    }
    LOG_INFO("core", "Synced %d users to provider '%s'",
             inst->auth.user_count, provider->name);

    /* Sync module configs from .conf files to the new provider */
    if (provider->config_set) {
        int sync_count = 0;

        /* Iterate all config entries */
        portal_ht_t *ht = &inst->config.sections;
        for (size_t b = 0; b < ht->capacity; b++) {
            if (ht->entries[b].occupied != 1) continue;
            const char *full_key = ht->entries[b].key;
            const char *val = (const char *)ht->entries[b].value;
            /* Keys are "section.key" — sync mod_* entries */
            const char *dot = strchr(full_key, '.');
            if (dot && strncmp(full_key, "mod_", 4) == 0) {
                char module[128];
                size_t mlen = (size_t)(dot - full_key);
                if (mlen < sizeof(module)) {
                    memcpy(module, full_key, mlen);
                    module[mlen] = '\0';
                    provider->config_set(provider->ctx,
                        module, dot + 1, val);
                    sync_count++;
                }
            }
        }
        if (sync_count > 0)
            LOG_INFO("core", "Synced %d config values to provider '%s'",
                     sync_count, provider->name);
    }

    return 0;
}

/* Thread-local buffer for DB config values (avoids malloc per call) */
static __thread char g_config_buf[4096];

static const char *api_config_get(portal_core_t *core, const char *module,
                                   const char *key)
{
    portal_instance_t *inst = core->_internal;

    /* 1. Check in-memory hash table first (fast, no I/O) */
    const char *val = portal_config_get(&inst->config, module, key);
    if (val) return val;

    /* 2. Fall back to database (slow, only if not in memory) */
    char db_module[128];
    snprintf(db_module, sizeof(db_module), "mod_%s", module);
    if (portal_storage_get_config(&inst->storage, db_module, key,
                                   g_config_buf, sizeof(g_config_buf)) == 0)
        return g_config_buf;

    return NULL;
}

static void api_log(portal_core_t *core, int level, const char *module,
                     const char *fmt, ...)
{
    (void)core;
    va_list ap;
    va_start(ap, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    portal_log_write(level, module, "%s", buf);
}

/* --- Exclusive resource locking --- */

static resource_lock_t *find_lock(portal_instance_t *inst, const char *resource)
{
    for (int i = 0; i < inst->lock_count; i++)
        if (inst->locks[i].active && strcmp(inst->locks[i].resource, resource) == 0)
            return &inst->locks[i];
    return NULL;
}

static int api_resource_lock(portal_core_t *core, const char *resource,
                              const char *owner)
{
    portal_instance_t *inst = core->_internal;
    resource_lock_t *existing = find_lock(inst, resource);
    if (existing) return -1;  /* already locked */
    if (inst->lock_count >= LOCK_MAX) return -1;

    /* Find free slot */
    resource_lock_t *lk = NULL;
    for (int i = 0; i < LOCK_MAX; i++) {
        if (!inst->locks[i].active) { lk = &inst->locks[i]; break; }
    }
    if (!lk) return -1;

    snprintf(lk->resource, sizeof(lk->resource), "%s", resource);
    snprintf(lk->owner, sizeof(lk->owner), "%s", owner);
    lk->locked_at = time(NULL);
    lk->last_keepalive = lk->locked_at;
    lk->active = 1;
    inst->lock_count++;

    LOG_INFO("lock", "Locked '%s' by '%s'", resource, owner);
    return 0;
}

static int api_resource_unlock(portal_core_t *core, const char *resource,
                                const char *owner)
{
    portal_instance_t *inst = core->_internal;
    resource_lock_t *lk = find_lock(inst, resource);
    if (!lk) return -1;  /* not locked */
    if (strcmp(lk->owner, owner) != 0) return -2;  /* not your lock */

    lk->active = 0;
    inst->lock_count--;
    LOG_INFO("lock", "Unlocked '%s' by '%s'", resource, owner);
    return 0;
}

static int api_resource_keepalive(portal_core_t *core, const char *resource,
                                   const char *owner)
{
    portal_instance_t *inst = core->_internal;
    resource_lock_t *lk = find_lock(inst, resource);
    if (!lk || strcmp(lk->owner, owner) != 0) return -1;
    lk->last_keepalive = time(NULL);
    return 0;
}

static int api_resource_locked(portal_core_t *core, const char *resource)
{
    portal_instance_t *inst = core->_internal;
    return find_lock(inst, resource) ? 1 : 0;
}

static const char *api_resource_owner(portal_core_t *core, const char *resource)
{
    portal_instance_t *inst = core->_internal;
    resource_lock_t *lk = find_lock(inst, resource);
    return lk ? lk->owner : NULL;
}

/* Called by timer: release expired locks */
void lock_cleanup(portal_instance_t *inst)
{
    time_t now = time(NULL);
    for (int i = 0; i < LOCK_MAX; i++) {
        if (!inst->locks[i].active) continue;
        if (now - inst->locks[i].last_keepalive > LOCK_TIMEOUT_SEC) {
            LOG_WARN("lock", "Auto-released '%s' (owner '%s' — keepalive expired)",
                     inst->locks[i].resource, inst->locks[i].owner);
            inst->locks[i].active = 0;
            inst->lock_count--;
        }
    }
}

/* --- Message tracing (verbose/debug) --- */

static int api_trace_add(portal_core_t *core, int fd, const char *filter,
                          const char *prompt, char *line_buf, int *line_len,
                          int *cursor_pos, int debug)
{
    portal_instance_t *inst = core->_internal;
    for (int i = 0; i < inst->trace_count; i++) {
        if (inst->trace_subs[i].fd == fd) {
            snprintf(inst->trace_subs[i].filter, sizeof(inst->trace_subs[i].filter),
                     "%s", filter);
            if (prompt)
                snprintf(inst->trace_subs[i].prompt, sizeof(inst->trace_subs[i].prompt),
                         "%s", prompt);
            inst->trace_subs[i].line_buf = line_buf;
            inst->trace_subs[i].line_len = line_len;
            inst->trace_subs[i].cursor_pos = cursor_pos;
            inst->trace_subs[i].debug = debug;
            inst->trace_subs[i].active = 1;
            return 0;
        }
    }
    if (inst->trace_count >= TRACE_MAX_SUBS) return -1;
    trace_sub_t *ts = &inst->trace_subs[inst->trace_count++];
    ts->fd = fd;
    snprintf(ts->filter, sizeof(ts->filter), "%s", filter);
    if (prompt)
        snprintf(ts->prompt, sizeof(ts->prompt), "%s", prompt);
    else
        ts->prompt[0] = '\0';
    ts->line_buf = line_buf;
    ts->line_len = line_len;
    ts->cursor_pos = cursor_pos;
    ts->debug = debug;
    ts->active = 1;
    return 0;
}

static int api_trace_del(portal_core_t *core, int fd)
{
    portal_instance_t *inst = core->_internal;
    for (int i = 0; i < inst->trace_count; i++) {
        if (inst->trace_subs[i].fd == fd) {
            inst->trace_subs[i].active = 0;
            return 0;
        }
    }
    return -1;
}

static void trace_message(portal_instance_t *inst, const portal_msg_t *msg,
                           const portal_resp_t *resp)
{
    if (!msg || !msg->path) return;

    static const char *mnames[] = {"?","GET","SET","CALL","EVT","SUB","UNSUB","META"};
    int mi = (msg->method < 8) ? msg->method : 0;

    for (int i = 0; i < inst->trace_count; i++) {
        trace_sub_t *ts = &inst->trace_subs[i];
        if (!ts->active) continue;

        /* Filter: path must contain filter string */
        if (strlen(ts->filter) > 1 && !strstr(msg->path, ts->filter))
            continue;

        char tbuf[512];
        int tn;
        const char *src = (msg->ctx && msg->ctx->source_module)
                          ? msg->ctx->source_module : "-";
        const char *usr = (msg->ctx && msg->ctx->auth.user)
                          ? msg->ctx->auth.user : "-";

        uint64_t tid = msg->ctx ? msg->ctx->trace.trace_id : 0;

        if (!resp) {
            /* → request going out */
            tn = snprintf(tbuf, sizeof(tbuf),
                "→ #%lu [%s] %s → %s (user:%s)\n",
                (unsigned long)tid, mnames[mi], src, msg->path, usr);
        } else {
            /* ← response coming back */
            tn = snprintf(tbuf, sizeof(tbuf),
                "← #%lu [%d] %s (%zu bytes)\n",
                (unsigned long)tid, resp->status, msg->path, resp->body_len);
        }

        /* Clear current line, write trace, redraw prompt + editor text */
        if (write(ts->fd, "\r\033[K", 4) < 0 ||
            write(ts->fd, tbuf, (size_t)tn) < 0) {
            ts->active = 0;
            continue;
        }
        /* Debug: hex+text dump of body (max 5 lines = 80 bytes) */
        if (ts->debug) {
            const uint8_t *data = NULL;
            size_t dlen = 0;
            if (!resp && msg->body && msg->body_len > 0) {
                data = msg->body; dlen = msg->body_len;
            } else if (resp && resp->body && resp->body_len > 0) {
                data = resp->body; dlen = resp->body_len;
            }
            if (data && dlen > 0) {
                size_t max = dlen < 80 ? dlen : 80;  /* 5 lines of 16 bytes */
                for (size_t off = 0; off < max; off += 16) {
                    char hline[128];
                    int hp = snprintf(hline, sizeof(hline), "  %04zx  ", off);
                    /* Hex */
                    for (size_t j = 0; j < 16; j++) {
                        if (off + j < max)
                            hp += snprintf(hline + hp, sizeof(hline) - (size_t)hp,
                                          "%02x ", data[off + j]);
                        else
                            hp += snprintf(hline + hp, sizeof(hline) - (size_t)hp, "   ");
                    }
                    hp += snprintf(hline + hp, sizeof(hline) - (size_t)hp, " ");
                    /* Text (. for non-printable) */
                    for (size_t j = 0; j < 16 && off + j < max; j++) {
                        uint8_t c = data[off + j];
                        hline[hp++] = (c >= 32 && c < 127) ? (char)c : '.';
                    }
                    hline[hp++] = '\n';
                    hline[hp] = '\0';
                    (void)write(ts->fd, hline, (size_t)hp);
                }
                if (dlen > 80) {
                    char more[32];
                    int ml = snprintf(more, sizeof(more), "  ... +%zu bytes\n", dlen - 80);
                    (void)write(ts->fd, more, (size_t)ml);
                }
            }
        }
        if (ts->prompt[0])
            (void)write(ts->fd, ts->prompt, strlen(ts->prompt));
        /* Restore editor line buffer and cursor position */
        if (ts->line_buf && ts->line_len && *ts->line_len > 0) {
            (void)write(ts->fd, ts->line_buf, (size_t)*ts->line_len);
            /* Move cursor back if not at end */
            if (ts->cursor_pos && *ts->cursor_pos < *ts->line_len) {
                int back = *ts->line_len - *ts->cursor_pos;
                char esc[32];
                int el = snprintf(esc, sizeof(esc), "\033[%dD", back);
                (void)write(ts->fd, esc, (size_t)el);
            }
        }
    }
}

static int api_timer_add(portal_core_t *core, double interval,
                          portal_timer_fn callback, void *userdata)
{
    portal_instance_t *inst = core->_internal;
    return portal_event_add_timer(&inst->events, interval, callback, userdata);
}

/* --- Observability iterators --- */

static int api_module_iter(portal_core_t *core, portal_module_iter_fn cb, void *ud)
{
    portal_instance_t *inst = core->_internal;
    if (!cb) return -1;
    int n = 0;
    for (int i = 0; i < inst->modules.count; i++) {
        portal_module_entry_t *e = &inst->modules.entries[i];
        const char *name = e->info ? e->info->name : e->name;
        const char *ver  = e->info ? e->info->version : "";
        cb(name, ver, e->loaded, e->msg_count, e->last_msg_us, ud);
        n++;
    }
    return n;
}

typedef struct {
    portal_path_iter_fn cb;
    void *ud;
    int  count;
} path_iter_ctx_t;

static void path_iter_cb(const char *path, const char *module_name, void *userdata)
{
    path_iter_ctx_t *c = userdata;
    c->cb(path, module_name, c->ud);
    c->count++;
}

static int api_path_iter(portal_core_t *core, portal_path_iter_fn cb, void *ud)
{
    portal_instance_t *inst = core->_internal;
    if (!cb) return -1;
    path_iter_ctx_t c = { cb, ud, 0 };
    portal_path_list(&inst->paths, path_iter_cb, &c);
    return c.count;
}

/* --- Instance lifecycle --- */

void portal_instance_setup_api(portal_instance_t *inst)
{
    inst->api.path_register     = api_path_register;
    inst->api.path_unregister   = api_path_unregister;
    inst->api.path_set_access   = api_path_set_access;
    inst->api.path_add_label         = api_path_add_label;
    inst->api.path_remove_label      = api_path_remove_label;
    inst->api.path_set_description   = api_path_set_description;
    inst->api.send              = api_send;
    inst->api.subscribe         = api_subscribe;
    inst->api.unsubscribe       = api_unsubscribe;
    inst->api.event_register    = api_event_register;
    inst->api.event_unregister  = api_event_unregister;
    inst->api.event_emit        = api_event_emit;
    inst->api.storage_register  = api_storage_register;
    inst->api.module_loaded     = api_module_loaded;
    inst->api.module_iter       = api_module_iter;
    inst->api.path_iter         = api_path_iter;
    inst->api.fd_add            = api_fd_add;
    inst->api.fd_del            = api_fd_del;
    inst->api.fd_modify         = api_fd_modify;
    inst->api.ev_loop_get       = api_ev_loop_get;
    inst->api.config_get        = api_config_get;
    inst->api.log               = api_log;
    inst->api.timer_add         = api_timer_add;
    inst->api.trace_add         = api_trace_add;
    inst->api.trace_del         = api_trace_del;
    inst->api.resource_lock     = api_resource_lock;
    inst->api.resource_unlock   = api_resource_unlock;
    inst->api.resource_keepalive = api_resource_keepalive;
    inst->api.resource_locked   = api_resource_locked;
    inst->api.resource_owner    = api_resource_owner;
    inst->api._internal         = inst;
}

void portal_instance_register_core_paths(portal_instance_t *inst)
{
    portal_path_register(&inst->paths, "/core/status", "core");
    portal_path_register(&inst->paths, "/core/modules", "core");
    portal_path_register(&inst->paths, "/core/paths", "core");
    portal_path_register(&inst->paths, "/core/ls", "core");
    portal_path_register(&inst->paths, "/core/resolve", "core");
    portal_path_register(&inst->paths, "/auth/login", "core");
    portal_path_register(&inst->paths, "/auth/logout", "core");
    portal_path_register(&inst->paths, "/auth/whoami", "core");
    portal_path_register(&inst->paths, "/auth/key", "core");
    portal_path_register(&inst->paths, "/auth/key/rotate", "core");
    portal_path_register(&inst->paths, "/events", "core");
    portal_path_register(&inst->paths, "/users", "core");
    portal_path_register(&inst->paths, "/groups", "core");
    portal_path_register(&inst->paths, "/core/storage", "core");
    portal_path_register(&inst->paths, "/core/config/get", "core");
    portal_path_register(&inst->paths, "/core/config/set", "core");
    portal_path_register(&inst->paths, "/core/config/list", "core");
    LOG_DEBUG("core", "Registered internal core paths");
}

int portal_instance_init(portal_instance_t *inst)
{
    memset(inst, 0, sizeof(*inst));
    portal_config_defaults(&inst->config);
    portal_path_init(&inst->paths);
    portal_events_init(&inst->events_reg);
    portal_storage_init(&inst->storage);

    if (portal_event_init(&inst->events) < 0)
        return -1;

    portal_auth_init(&inst->auth);
    portal_instance_setup_api(inst);
    return 0;
}

void portal_instance_destroy(portal_instance_t *inst)
{
    portal_module_registry_destroy(&inst->modules, &inst->api);
    portal_path_destroy(&inst->paths);
    portal_events_destroy(&inst->events_reg);
    portal_event_destroy(&inst->events);
    portal_config_destroy(&inst->config);
}
