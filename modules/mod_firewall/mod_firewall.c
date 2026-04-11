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
 * mod_firewall — Rate limiting and IP/source filtering
 *
 * Track request rates per source (IP or user).
 * Whitelist/blacklist management.
 * Auto-block sources that exceed rate limits.
 *
 * Config:
 *   [mod_firewall]
 *   max_rules = 256
 *   rate_limit = 100
 *   rate_window = 60
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "portal/portal.h"

#define FW_MAX_RULES     256
#define FW_MAX_TRACKERS  1024
#define FW_RATE_LIMIT    100    /* requests per window */
#define FW_RATE_WINDOW   60     /* seconds */

typedef enum {
    FW_ALLOW = 0,
    FW_DENY  = 1
} fw_action_t;

typedef struct {
    char       source[128];  /* IP or user */
    fw_action_t action;
    char       reason[128];
    int64_t    created;
    int        active;
} fw_rule_t;

typedef struct {
    char    source[128];
    int     count;
    int64_t window_start;
    int     blocked;        /* auto-blocked by rate limit */
} fw_tracker_t;

static portal_core_t  *g_core = NULL;
static fw_rule_t       g_rules[FW_MAX_RULES];
static int             g_rule_count = 0;
static fw_tracker_t    g_trackers[FW_MAX_TRACKERS];
static int             g_tracker_count = 0;
static int             g_rate_limit = FW_RATE_LIMIT;
static int             g_rate_window = FW_RATE_WINDOW;
static int64_t         g_total_checked = 0;
static int64_t         g_total_blocked = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static portal_module_info_t info = {
    .name = "firewall", .version = "1.0.0",
    .description = "Rate limiting and IP/source filtering",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

static fw_tracker_t *find_tracker(const char *source)
{
    for (int i = 0; i < g_tracker_count; i++)
        if (strcmp(g_trackers[i].source, source) == 0)
            return &g_trackers[i];
    return NULL;
}

static fw_rule_t *find_rule(const char *source)
{
    for (int i = 0; i < g_rule_count; i++)
        if (g_rules[i].active && strcmp(g_rules[i].source, source) == 0)
            return &g_rules[i];
    return NULL;
}

/* Check if source is allowed. Updates rate tracker. */
static int check_source(const char *source, char *reason, size_t rlen)
{
    int64_t now = (int64_t)time(NULL);

    pthread_mutex_lock(&g_lock);
    g_total_checked++;

    /* Check explicit rules first */
    fw_rule_t *rule = find_rule(source);
    if (rule) {
        if (rule->action == FW_DENY) {
            g_total_blocked++;
            snprintf(reason, rlen, "Blocked by rule: %s", rule->reason);
            pthread_mutex_unlock(&g_lock);
            return -1;
        }
        /* Explicit allow bypasses rate limit */
        pthread_mutex_unlock(&g_lock);
        snprintf(reason, rlen, "Allowed by rule");
        return 0;
    }

    /* Rate limiting */
    fw_tracker_t *t = find_tracker(source);
    if (!t) {
        if (g_tracker_count < FW_MAX_TRACKERS) {
            t = &g_trackers[g_tracker_count++];
            snprintf(t->source, sizeof(t->source), "%s", source);
            t->count = 0;
            t->window_start = now;
            t->blocked = 0;
        } else {
            pthread_mutex_unlock(&g_lock);
            snprintf(reason, rlen, "Tracker table full");
            return 0; /* fail open */
        }
    }

    /* Reset window if expired */
    if (now - t->window_start >= g_rate_window) {
        t->count = 0;
        t->window_start = now;
        t->blocked = 0;
    }

    t->count++;
    if (t->count > g_rate_limit) {
        t->blocked = 1;
        g_total_blocked++;
        snprintf(reason, rlen, "Rate limit exceeded (%d/%d in %ds)",
                 t->count, g_rate_limit, g_rate_window);
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    pthread_mutex_unlock(&g_lock);
    snprintf(reason, rlen, "OK (%d/%d)", t->count, g_rate_limit);
    return 0;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_rules, 0, sizeof(g_rules));
    memset(g_trackers, 0, sizeof(g_trackers));
    g_rule_count = 0;
    g_tracker_count = 0;
    g_total_checked = 0;
    g_total_blocked = 0;

    const char *v;
    if ((v = core->config_get(core, "firewall", "rate_limit")))
        g_rate_limit = atoi(v);
    if ((v = core->config_get(core, "firewall", "rate_window")))
        g_rate_window = atoi(v);

    core->path_register(core, "/firewall/resources/status", "firewall");
    core->path_set_access(core, "/firewall/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/firewall/resources/status", "Rate limiter status: rules, blocked sources");
    core->path_register(core, "/firewall/resources/rules", "firewall");
    core->path_set_access(core, "/firewall/resources/rules", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/firewall/resources/rules", "List all firewall rules");
    core->path_register(core, "/firewall/resources/blocked", "firewall");
    core->path_set_access(core, "/firewall/resources/blocked", PORTAL_ACCESS_READ);
    core->path_register(core, "/firewall/functions/allow", "firewall");
    core->path_set_access(core, "/firewall/functions/allow", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/firewall/functions/allow", "Allow a source. Header: source");
    core->path_register(core, "/firewall/functions/deny", "firewall");
    core->path_set_access(core, "/firewall/functions/deny", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/firewall/functions/deny", "Block a source. Header: source (IP or pattern)");
    core->path_register(core, "/firewall/functions/remove", "firewall");
    core->path_set_access(core, "/firewall/functions/remove", PORTAL_ACCESS_RW);
    core->path_register(core, "/firewall/functions/check", "firewall");
    core->path_set_access(core, "/firewall/functions/check", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/firewall/functions/check", "Check if source blocked. Header: source");
    core->path_register(core, "/firewall/functions/clear", "firewall");
    core->path_set_access(core, "/firewall/functions/clear", PORTAL_ACCESS_RW);
    core->path_add_label(core, "/firewall/functions/clear", "admin");

    core->log(core, PORTAL_LOG_INFO, "firewall",
              "Firewall ready (rate: %d/%ds)", g_rate_limit, g_rate_window);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/firewall/resources/status");
    core->path_unregister(core, "/firewall/resources/rules");
    core->path_unregister(core, "/firewall/resources/blocked");
    core->path_unregister(core, "/firewall/functions/allow");
    core->path_unregister(core, "/firewall/functions/deny");
    core->path_unregister(core, "/firewall/functions/remove");
    core->path_unregister(core, "/firewall/functions/check");
    core->path_unregister(core, "/firewall/functions/clear");
    core->log(core, PORTAL_LOG_INFO, "firewall", "Firewall unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[8192];
    int n;

    if (strcmp(msg->path, "/firewall/resources/status") == 0) {
        int rules_allow = 0, rules_deny = 0;
        for (int i = 0; i < g_rule_count; i++) {
            if (!g_rules[i].active) continue;
            if (g_rules[i].action == FW_ALLOW) rules_allow++;
            else rules_deny++;
        }
        int rate_blocked = 0;
        pthread_mutex_lock(&g_lock);
        for (int i = 0; i < g_tracker_count; i++)
            if (g_trackers[i].blocked) rate_blocked++;
        pthread_mutex_unlock(&g_lock);

        n = snprintf(buf, sizeof(buf),
            "Firewall\n"
            "Rules: %d allow, %d deny\n"
            "Rate limit: %d requests / %d seconds\n"
            "Rate-blocked sources: %d\n"
            "Total checked: %lld\n"
            "Total blocked: %lld\n",
            rules_allow, rules_deny,
            g_rate_limit, g_rate_window,
            rate_blocked,
            (long long)g_total_checked, (long long)g_total_blocked);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/firewall/resources/rules") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Firewall Rules:\n");
        for (int i = 0; i < g_rule_count; i++) {
            if (!g_rules[i].active) continue;
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "  %-20s %-6s %s\n",
                g_rules[i].source,
                g_rules[i].action == FW_ALLOW ? "ALLOW" : "DENY",
                g_rules[i].reason);
        }
        if (g_rule_count == 0)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/firewall/resources/blocked") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
            "Currently Blocked:\n");
        pthread_mutex_lock(&g_lock);
        for (int i = 0; i < g_tracker_count && off < sizeof(buf) - 128; i++) {
            if (g_trackers[i].blocked) {
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "  %-20s %d requests (rate limit)\n",
                    g_trackers[i].source, g_trackers[i].count);
            }
        }
        /* Also show denied rules */
        for (int i = 0; i < g_rule_count && off < sizeof(buf) - 128; i++) {
            if (g_rules[i].active && g_rules[i].action == FW_DENY) {
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "  %-20s (rule: %s)\n",
                    g_rules[i].source, g_rules[i].reason);
            }
        }
        pthread_mutex_unlock(&g_lock);
        if (off < 30)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/firewall/functions/allow") == 0) {
        const char *source = get_hdr(msg, "source");
        const char *reason = get_hdr(msg, "reason");
        if (!source) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: source header\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        fw_rule_t *r = find_rule(source);
        if (!r) {
            if (g_rule_count >= FW_MAX_RULES) {
                portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
                return -1;
            }
            r = &g_rules[g_rule_count++];
        }
        snprintf(r->source, sizeof(r->source), "%s", source);
        r->action = FW_ALLOW;
        snprintf(r->reason, sizeof(r->reason), "%s", reason ? reason : "manual");
        r->created = (int64_t)time(NULL);
        r->active = 1;

        core->event_emit(core, "/events/firewall/allow", source, strlen(source));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Allowed: %s\n", source);
        portal_resp_set_body(resp, buf, (size_t)n);
        core->log(core, PORTAL_LOG_INFO, "firewall", "ALLOW %s (%s)",
                  source, reason ? reason : "manual");
        return 0;
    }

    if (strcmp(msg->path, "/firewall/functions/deny") == 0) {
        const char *source = get_hdr(msg, "source");
        const char *reason = get_hdr(msg, "reason");
        if (!source) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: source header\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        fw_rule_t *r = find_rule(source);
        if (!r) {
            if (g_rule_count >= FW_MAX_RULES) {
                portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
                return -1;
            }
            r = &g_rules[g_rule_count++];
        }
        snprintf(r->source, sizeof(r->source), "%s", source);
        r->action = FW_DENY;
        snprintf(r->reason, sizeof(r->reason), "%s", reason ? reason : "manual");
        r->created = (int64_t)time(NULL);
        r->active = 1;

        core->event_emit(core, "/events/firewall/deny", source, strlen(source));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Denied: %s\n", source);
        portal_resp_set_body(resp, buf, (size_t)n);
        core->log(core, PORTAL_LOG_WARN, "firewall", "DENY %s (%s)",
                  source, reason ? reason : "manual");
        return 0;
    }

    if (strcmp(msg->path, "/firewall/functions/remove") == 0) {
        const char *source = get_hdr(msg, "source");
        if (!source) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        fw_rule_t *r = find_rule(source);
        if (!r) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        r->active = 0;
        core->event_emit(core, "/events/firewall/remove", source, strlen(source));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Rule removed for %s\n", source);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/firewall/functions/check") == 0) {
        const char *source = get_hdr(msg, "source");
        if (!source) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: source header\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        char reason[256];
        int result = check_source(source, reason, sizeof(reason));
        n = snprintf(buf, sizeof(buf), "%s: %s — %s\n",
                     source, result == 0 ? "ALLOWED" : "BLOCKED", reason);
        portal_resp_set_status(resp, result == 0 ? PORTAL_OK : PORTAL_FORBIDDEN);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/firewall/functions/clear") == 0) {
        pthread_mutex_lock(&g_lock);
        memset(g_rules, 0, sizeof(g_rules));
        memset(g_trackers, 0, sizeof(g_trackers));
        g_rule_count = 0;
        g_tracker_count = 0;
        pthread_mutex_unlock(&g_lock);
        core->event_emit(core, "/events/firewall/clear", "all", 3);
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "All rules and trackers cleared\n");
        portal_resp_set_body(resp, buf, (size_t)n);
        core->log(core, PORTAL_LOG_WARN, "firewall", "All rules cleared");
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
