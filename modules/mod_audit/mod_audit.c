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
 * mod_audit — Audit trail logging
 *
 * Records all significant events with timestamp, user, path, method.
 * Circular buffer in memory, optionally persisted to file.
 * Searchable by user, path, or time range.
 *
 * Config:
 *   [mod_audit]
 *   max_entries = 10000
 *   log_file = /var/log/portal/audit.log
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "portal/portal.h"

#define AUDIT_MAX_ENTRIES  10000
#define AUDIT_MSG_SIZE     512

typedef struct {
    int64_t timestamp;
    char    user[64];
    char    path[PORTAL_MAX_PATH_LEN];
    char    method[16];
    char    detail[256];
} audit_entry_t;

static portal_core_t *g_core = NULL;
static audit_entry_t *g_entries = NULL;
static int            g_max = AUDIT_MAX_ENTRIES;
static int            g_count = 0;
static int            g_head = 0;   /* next write position (circular) */
static int64_t        g_total = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char           g_log_file[512] = "";
static FILE          *g_log_fp = NULL;

static portal_module_info_t info = {
    .name = "audit", .version = "1.0.0",
    .description = "Audit trail logging",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

static const char *method_str(uint8_t m)
{
    switch (m) {
    case PORTAL_METHOD_GET:   return "GET";
    case PORTAL_METHOD_SET:   return "SET";
    case PORTAL_METHOD_CALL:  return "CALL";
    case PORTAL_METHOD_EVENT: return "EVENT";
    case PORTAL_METHOD_SUB:   return "SUB";
    case PORTAL_METHOD_UNSUB: return "UNSUB";
    case PORTAL_METHOD_META:  return "META";
    default:                  return "?";
    }
}

static void audit_record(const char *user, const char *path,
                          const char *method, const char *detail)
{
    pthread_mutex_lock(&g_lock);
    audit_entry_t *e = &g_entries[g_head];
    e->timestamp = (int64_t)time(NULL);
    snprintf(e->user, sizeof(e->user), "%s", user ? user : "unknown");
    snprintf(e->path, sizeof(e->path), "%s", path ? path : "");
    snprintf(e->method, sizeof(e->method), "%s", method ? method : "");
    snprintf(e->detail, sizeof(e->detail), "%s", detail ? detail : "");

    /* Write to file if configured */
    if (g_log_fp) {
        char ts[32];
        struct tm tm;
        time_t t = (time_t)e->timestamp;
        localtime_r(&t, &tm);
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);
        fprintf(g_log_fp, "%s  %-12s %-6s %s  %s\n",
                ts, e->user, e->method, e->path, e->detail);
        fflush(g_log_fp);
    }

    g_head = (g_head + 1) % g_max;
    if (g_count < g_max) g_count++;
    g_total++;
    pthread_mutex_unlock(&g_lock);
}

/* Event handler: audit all events we subscribe to */
static void audit_event_handler(const portal_msg_t *msg, void *userdata)
{
    (void)userdata;
    const char *user = "system";
    if (msg->ctx && msg->ctx->auth.user)
        user = msg->ctx->auth.user;
    audit_record(user, msg->path, method_str(msg->method), "event");
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_count = 0;
    g_head = 0;
    g_total = 0;

    const char *v;
    if ((v = core->config_get(core, "audit", "max_entries")))
        g_max = atoi(v);
    if (g_max < 100) g_max = 100;

    if ((v = core->config_get(core, "audit", "log_file"))) {
        snprintf(g_log_file, sizeof(g_log_file), "%s", v);
        g_log_fp = fopen(g_log_file, "a");
        if (!g_log_fp)
            core->log(core, PORTAL_LOG_WARN, "audit",
                      "Cannot open log file: %s", g_log_file);
    }

    g_entries = calloc((size_t)g_max, sizeof(audit_entry_t));

    core->path_register(core, "/audit/resources/status", "audit");
    core->path_set_access(core, "/audit/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/audit/resources/status", "Audit trail: entry count, max entries, file path");
    core->path_register(core, "/audit/resources/log", "audit");
    core->path_set_access(core, "/audit/resources/log", PORTAL_ACCESS_READ);
    core->path_register(core, "/audit/functions/search", "audit");
    core->path_set_access(core, "/audit/functions/search", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/audit/functions/search", "Search audit trail. Header: pattern, optional: limit");
    core->path_register(core, "/audit/functions/record", "audit");
    core->path_set_access(core, "/audit/functions/record", PORTAL_ACCESS_RW);
    core->path_register(core, "/audit/functions/clear", "audit");
    core->path_set_access(core, "/audit/functions/clear", PORTAL_ACCESS_RW);
    core->path_add_label(core, "/audit/functions/clear", "admin");

    /* Subscribe to all events for auditing */
    core->subscribe(core, "/events/*", audit_event_handler, NULL);

    core->log(core, PORTAL_LOG_INFO, "audit",
              "Audit trail ready (max: %d entries, file: %s)",
              g_max, g_log_file[0] ? g_log_file : "none");
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->unsubscribe(core, "/events/*", audit_event_handler);
    if (g_log_fp) { fclose(g_log_fp); g_log_fp = NULL; }
    free(g_entries); g_entries = NULL;

    core->path_unregister(core, "/audit/resources/status");
    core->path_unregister(core, "/audit/resources/log");
    core->path_unregister(core, "/audit/functions/search");
    core->path_unregister(core, "/audit/functions/record");
    core->path_unregister(core, "/audit/functions/clear");
    core->log(core, PORTAL_LOG_INFO, "audit", "Audit unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[32768];
    int n;

    /* Record this request itself */
    const char *user = "unknown";
    if (msg->ctx && msg->ctx->auth.user)
        user = msg->ctx->auth.user;
    audit_record(user, msg->path, method_str(msg->method), "request");

    if (strcmp(msg->path, "/audit/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "Audit Trail\n"
            "Entries: %d / %d\n"
            "Total recorded: %lld\n"
            "Log file: %s\n",
            g_count, g_max, (long long)g_total,
            g_log_file[0] ? g_log_file : "(none)");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/audit/resources/log") == 0) {
        const char *limit_s = get_hdr(msg, "limit");
        int limit = limit_s ? atoi(limit_s) : 50;
        if (limit > g_count) limit = g_count;
        if (limit > 200) limit = 200;

        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
            "Audit Log (last %d of %d):\n", limit, g_count);

        pthread_mutex_lock(&g_lock);
        /* Read from most recent backwards */
        for (int i = 0; i < limit && off < sizeof(buf) - 256; i++) {
            int idx = (g_head - 1 - i + g_max) % g_max;
            if (idx < 0 || !g_entries[idx].path[0]) break;
            audit_entry_t *e = &g_entries[idx];
            char ts[32];
            struct tm tm;
            time_t t = (time_t)e->timestamp;
            localtime_r(&t, &tm);
            strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "  %s  %-12s %-6s %s  %s\n",
                ts, e->user, e->method, e->path, e->detail);
        }
        pthread_mutex_unlock(&g_lock);

        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/audit/functions/search") == 0) {
        const char *by_user = get_hdr(msg, "user");
        const char *by_path = get_hdr(msg, "path");
        const char *limit_s = get_hdr(msg, "limit");
        int limit = limit_s ? atoi(limit_s) : 50;
        if (limit > 500) limit = 500;

        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
            "Audit Search (user=%s, path=%s):\n",
            by_user ? by_user : "*", by_path ? by_path : "*");

        pthread_mutex_lock(&g_lock);
        int found = 0;
        for (int i = 0; i < g_count && found < limit && off < sizeof(buf) - 256; i++) {
            int idx = (g_head - 1 - i + g_max) % g_max;
            audit_entry_t *e = &g_entries[idx];
            if (by_user && strcmp(e->user, by_user) != 0) continue;
            if (by_path && strstr(e->path, by_path) == NULL) continue;
            char ts[32];
            struct tm tm;
            time_t t = (time_t)e->timestamp;
            localtime_r(&t, &tm);
            strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "  %s  %-12s %-6s %s  %s\n",
                ts, e->user, e->method, e->path, e->detail);
            found++;
        }
        pthread_mutex_unlock(&g_lock);

        if (found == 0)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (no matches)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/audit/functions/record") == 0) {
        const char *a_user = get_hdr(msg, "user");
        const char *a_path = get_hdr(msg, "path");
        const char *a_method = get_hdr(msg, "method");
        const char *a_detail = get_hdr(msg, "detail");
        if (!a_user) a_user = user;
        audit_record(a_user, a_path ? a_path : "(manual)",
                     a_method ? a_method : "CALL",
                     a_detail ? a_detail : "manual entry");
        core->event_emit(core, "/events/audit/record", a_user, strlen(a_user));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Recorded\n");
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/audit/functions/clear") == 0) {
        pthread_mutex_lock(&g_lock);
        memset(g_entries, 0, (size_t)g_max * sizeof(audit_entry_t));
        g_count = 0;
        g_head = 0;
        pthread_mutex_unlock(&g_lock);
        core->event_emit(core, "/events/audit/clear", "all", 3);
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Audit log cleared (%lld total entries were recorded)\n",
                     (long long)g_total);
        portal_resp_set_body(resp, buf, (size_t)n);
        core->log(core, PORTAL_LOG_WARN, "audit", "Audit log cleared by %s", user);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
