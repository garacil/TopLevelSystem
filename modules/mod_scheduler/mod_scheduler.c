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
 * mod_scheduler — One-shot delayed task scheduler
 *
 * Schedule path calls at specific times or after delays.
 * Complement to mod_cron (intervals). Tasks execute once.
 *
 * Config:
 *   [mod_scheduler]
 *   max_tasks = 256
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "portal/portal.h"

#define SCHED_MAX_TASKS  256

typedef enum {
    SCHED_PENDING = 0,
    SCHED_RUNNING,
    SCHED_DONE,
    SCHED_FAILED,
    SCHED_CANCELLED
} sched_status_t;

typedef struct {
    int            id;
    char           name[64];
    char           path[PORTAL_MAX_PATH_LEN];
    int64_t        run_at;       /* unix timestamp */
    sched_status_t status;
    int            active;
} sched_task_t;

static portal_core_t *g_core = NULL;
static sched_task_t   g_tasks[SCHED_MAX_TASKS];
static int            g_count = 0;
static int            g_max = SCHED_MAX_TASKS;
static int            g_next_id = 0;
static int64_t        g_executed = 0;

static portal_module_info_t info = {
    .name = "scheduler", .version = "1.0.0",
    .description = "One-shot delayed task scheduler",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

/* Check and execute due tasks */
static void scheduler_tick(void)
{
    int64_t now = (int64_t)time(NULL);
    for (int i = 0; i < g_count; i++) {
        if (!g_tasks[i].active || g_tasks[i].status != SCHED_PENDING)
            continue;
        if (now >= g_tasks[i].run_at) {
            g_tasks[i].status = SCHED_RUNNING;

            portal_msg_t *msg = portal_msg_alloc();
            portal_resp_t *resp = portal_resp_alloc();
            int rc = -1;
            if (msg && resp) {
                portal_msg_set_path(msg, g_tasks[i].path);
                portal_msg_set_method(msg, PORTAL_METHOD_CALL);
                rc = g_core->send(g_core, msg, resp);
                portal_msg_free(msg);
                portal_resp_free(resp);
            }

            g_tasks[i].status = (rc == 0) ? SCHED_DONE : SCHED_FAILED;
            g_executed++;
            g_core->event_emit(g_core, "/events/scheduler/execute",
                               g_tasks[i].name, strlen(g_tasks[i].name));
            g_core->log(g_core, PORTAL_LOG_INFO, "scheduler",
                        "Executed task '%s' → %s (%s)",
                        g_tasks[i].name, g_tasks[i].path,
                        rc == 0 ? "ok" : "failed");
        }
    }
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_tasks, 0, sizeof(g_tasks));
    g_count = 0;
    g_next_id = 0;
    g_executed = 0;

    const char *v;
    if ((v = core->config_get(core, "scheduler", "max_tasks")))
        g_max = atoi(v);

    core->path_register(core, "/scheduler/resources/status", "scheduler");
    core->path_set_access(core, "/scheduler/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/scheduler/resources/tasks", "scheduler");
    core->path_set_access(core, "/scheduler/resources/tasks", PORTAL_ACCESS_READ);
    core->path_register(core, "/scheduler/functions/schedule", "scheduler");
    core->path_set_access(core, "/scheduler/functions/schedule", PORTAL_ACCESS_RW);
    core->path_register(core, "/scheduler/functions/cancel", "scheduler");
    core->path_set_access(core, "/scheduler/functions/cancel", PORTAL_ACCESS_RW);
    core->path_register(core, "/scheduler/functions/check", "scheduler");
    core->path_set_access(core, "/scheduler/functions/check", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "scheduler",
              "One-shot scheduler ready (max: %d tasks)", g_max);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/scheduler/resources/status");
    core->path_unregister(core, "/scheduler/resources/tasks");
    core->path_unregister(core, "/scheduler/functions/schedule");
    core->path_unregister(core, "/scheduler/functions/cancel");
    core->path_unregister(core, "/scheduler/functions/check");
    core->log(core, PORTAL_LOG_INFO, "scheduler", "Scheduler unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[8192];
    int n;

    /* Check due tasks on every request */
    scheduler_tick();

    if (strcmp(msg->path, "/scheduler/resources/status") == 0) {
        int pending = 0, done = 0;
        for (int i = 0; i < g_count; i++) {
            if (!g_tasks[i].active) continue;
            if (g_tasks[i].status == SCHED_PENDING) pending++;
            else done++;
        }
        n = snprintf(buf, sizeof(buf),
            "One-Shot Scheduler\n"
            "Tasks: %d pending, %d completed (max %d)\n"
            "Total executed: %lld\n",
            pending, done, g_max, (long long)g_executed);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/scheduler/resources/tasks") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Scheduled Tasks:\n");
        int64_t now = (int64_t)time(NULL);
        for (int i = 0; i < g_count && off < sizeof(buf) - 256; i++) {
            if (!g_tasks[i].active) continue;
            const char *status = "?";
            switch (g_tasks[i].status) {
            case SCHED_PENDING:   status = "PENDING"; break;
            case SCHED_RUNNING:   status = "RUNNING"; break;
            case SCHED_DONE:      status = "DONE"; break;
            case SCHED_FAILED:    status = "FAILED"; break;
            case SCHED_CANCELLED: status = "CANCELLED"; break;
            }
            int64_t eta = g_tasks[i].run_at - now;
            if (g_tasks[i].status == SCHED_PENDING && eta > 0) {
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "  #%-4d %-16s %-10s → %s (in %llds)\n",
                    g_tasks[i].id, g_tasks[i].name, status,
                    g_tasks[i].path, (long long)eta);
            } else {
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "  #%-4d %-16s %-10s → %s\n",
                    g_tasks[i].id, g_tasks[i].name, status,
                    g_tasks[i].path);
            }
        }
        if (g_count == 0)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/scheduler/functions/schedule") == 0) {
        const char *name = get_hdr(msg, "name");
        const char *path = get_hdr(msg, "path");
        const char *delay_s = get_hdr(msg, "delay");
        const char *at_s = get_hdr(msg, "at");
        if (!name || !path || (!delay_s && !at_s)) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf),
                "Need: name, path, delay (seconds) or at (unix timestamp)\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (g_count >= g_max) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            n = snprintf(buf, sizeof(buf), "Max tasks reached\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        sched_task_t *t = &g_tasks[g_count++];
        t->id = ++g_next_id;
        snprintf(t->name, sizeof(t->name), "%s", name);
        snprintf(t->path, sizeof(t->path), "%s", path);
        if (at_s)
            t->run_at = atoll(at_s);
        else
            t->run_at = (int64_t)time(NULL) + atoll(delay_s);
        t->status = SCHED_PENDING;
        t->active = 1;

        int64_t eta = t->run_at - (int64_t)time(NULL);
        core->event_emit(core, "/events/scheduler/schedule", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_CREATED);
        n = snprintf(buf, sizeof(buf),
            "Task #%d '%s' scheduled → %s (in %llds)\n",
            t->id, name, path, (long long)(eta > 0 ? eta : 0));
        portal_resp_set_body(resp, buf, (size_t)n);
        core->log(core, PORTAL_LOG_INFO, "scheduler",
                  "Scheduled '%s' → %s in %llds", name, path, (long long)eta);
        return 0;
    }

    if (strcmp(msg->path, "/scheduler/functions/cancel") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        for (int i = 0; i < g_count; i++) {
            if (g_tasks[i].active && g_tasks[i].status == SCHED_PENDING &&
                strcmp(g_tasks[i].name, name) == 0) {
                g_tasks[i].status = SCHED_CANCELLED;
                core->event_emit(core, "/events/scheduler/cancel",
                                 name, strlen(name));
                portal_resp_set_status(resp, PORTAL_OK);
                n = snprintf(buf, sizeof(buf), "Cancelled: %s\n", name);
                portal_resp_set_body(resp, buf, (size_t)n);
                return 0;
            }
        }
        portal_resp_set_status(resp, PORTAL_NOT_FOUND);
        return -1;
    }

    if (strcmp(msg->path, "/scheduler/functions/check") == 0) {
        scheduler_tick();
        int pending = 0;
        for (int i = 0; i < g_count; i++)
            if (g_tasks[i].active && g_tasks[i].status == SCHED_PENDING)
                pending++;
        n = snprintf(buf, sizeof(buf), "Checked. Pending: %d\n", pending);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
