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
 * mod_queue — Message Queues
 *
 * Named FIFO queues for producer/consumer patterns.
 * Modules push messages, other modules pop them.
 * Thread-safe, configurable max depth.
 *
 * Config:
 *   [mod_queue]
 *   max_queues = 64
 *   max_depth = 10000
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "portal/portal.h"

#define QUEUE_MAX_QUEUES  64
#define QUEUE_MAX_DEPTH   10000
#define QUEUE_MAX_MSG     8192

typedef struct queue_item {
    char *data;
    size_t len;
    struct queue_item *next;
} queue_item_t;

typedef struct {
    char            name[64];
    queue_item_t   *head;
    queue_item_t   *tail;
    int             depth;
    int             max_depth;
    int64_t         pushed;
    int64_t         popped;
    pthread_mutex_t lock;
    int             active;
} named_queue_t;

static portal_core_t *g_core = NULL;
static named_queue_t  g_queues[QUEUE_MAX_QUEUES];
static int            g_count = 0;
static int            g_default_depth = QUEUE_MAX_DEPTH;

static portal_module_info_t info = {
    .name = "queue", .version = "1.0.0",
    .description = "Message queues (FIFO)",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

static named_queue_t *find_queue(const char *name)
{
    for (int i = 0; i < g_count; i++)
        if (g_queues[i].active && strcmp(g_queues[i].name, name) == 0)
            return &g_queues[i];
    return NULL;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_queues, 0, sizeof(g_queues));
    g_count = 0;

    const char *v = core->config_get(core, "queue", "max_depth");
    if (v) g_default_depth = atoi(v);

    core->path_register(core, "/queue/resources/status", "queue");
    core->path_set_access(core, "/queue/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/queue/resources/list", "queue");
    core->path_set_access(core, "/queue/resources/list", PORTAL_ACCESS_READ);
    core->path_register(core, "/queue/functions/create", "queue");
    core->path_set_access(core, "/queue/functions/create", PORTAL_ACCESS_RW);
    core->path_register(core, "/queue/functions/push", "queue");
    core->path_set_access(core, "/queue/functions/push", PORTAL_ACCESS_RW);
    core->path_register(core, "/queue/functions/pop", "queue");
    core->path_set_access(core, "/queue/functions/pop", PORTAL_ACCESS_RW);
    core->path_register(core, "/queue/functions/peek", "queue");
    core->path_set_access(core, "/queue/functions/peek", PORTAL_ACCESS_RW);
    core->path_register(core, "/queue/functions/destroy", "queue");
    core->path_set_access(core, "/queue/functions/destroy", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "queue",
              "Message queues ready (max depth: %d)", g_default_depth);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    for (int i = 0; i < g_count; i++) {
        if (g_queues[i].active) {
            queue_item_t *item = g_queues[i].head;
            while (item) {
                queue_item_t *next = item->next;
                free(item->data); free(item);
                item = next;
            }
            pthread_mutex_destroy(&g_queues[i].lock);
        }
    }
    core->path_unregister(core, "/queue/resources/status");
    core->path_unregister(core, "/queue/resources/list");
    core->path_unregister(core, "/queue/functions/create");
    core->path_unregister(core, "/queue/functions/push");
    core->path_unregister(core, "/queue/functions/pop");
    core->path_unregister(core, "/queue/functions/peek");
    core->path_unregister(core, "/queue/functions/destroy");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;
    char buf[4096];
    int n;

    if (strcmp(msg->path, "/queue/resources/status") == 0) {
        int active = 0; int64_t tp = 0, tpp = 0;
        for (int i = 0; i < g_count; i++)
            if (g_queues[i].active) { active++; tp += g_queues[i].pushed; tpp += g_queues[i].popped; }
        n = snprintf(buf, sizeof(buf),
            "Message Queues\nQueues: %d\nTotal pushed: %lld\nTotal popped: %lld\n",
            active, (long long)tp, (long long)tpp);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/queue/resources/list") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Queues:\n");
        for (int i = 0; i < g_count; i++) {
            if (g_queues[i].active)
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "  %-20s depth: %d/%d  pushed: %lld  popped: %lld\n",
                    g_queues[i].name, g_queues[i].depth, g_queues[i].max_depth,
                    (long long)g_queues[i].pushed, (long long)g_queues[i].popped);
        }
        if (g_count == 0) off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/queue/functions/create") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        if (find_queue(name) || g_count >= QUEUE_MAX_QUEUES) {
            portal_resp_set_status(resp, PORTAL_CONFLICT); return -1;
        }
        named_queue_t *q = &g_queues[g_count++];
        snprintf(q->name, sizeof(q->name), "%s", name);
        q->head = q->tail = NULL; q->depth = 0;
        q->max_depth = g_default_depth;
        q->pushed = q->popped = 0;
        pthread_mutex_init(&q->lock, NULL);
        q->active = 1;
        n = snprintf(buf, sizeof(buf), "Queue '%s' created\n", name);
        portal_resp_set_status(resp, PORTAL_CREATED);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/queue/functions/push") == 0) {
        const char *name = get_hdr(msg, "name");
        const char *data = get_hdr(msg, "data");
        if (!data && msg->body) data = msg->body;
        if (!name || !data) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        named_queue_t *q = find_queue(name);
        if (!q) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }

        pthread_mutex_lock(&q->lock);
        if (q->depth >= q->max_depth) {
            pthread_mutex_unlock(&q->lock);
            portal_resp_set_status(resp, PORTAL_CONFLICT);
            n = snprintf(buf, sizeof(buf), "Queue full\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        queue_item_t *item = calloc(1, sizeof(*item));
        item->data = strdup(data);
        item->len = strlen(data);
        if (q->tail) q->tail->next = item; else q->head = item;
        q->tail = item;
        q->depth++; q->pushed++;
        core->event_emit(core, "/events/queue/push", name, strlen(name));
        pthread_mutex_unlock(&q->lock);

        n = snprintf(buf, sizeof(buf), "Pushed (depth: %d)\n", q->depth);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/queue/functions/pop") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        named_queue_t *q = find_queue(name);
        if (!q) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }

        pthread_mutex_lock(&q->lock);
        if (!q->head) {
            pthread_mutex_unlock(&q->lock);
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, "(empty)\n", 8);
            return 0;
        }
        queue_item_t *item = q->head;
        q->head = item->next;
        if (!q->head) q->tail = NULL;
        q->depth--; q->popped++;
        core->event_emit(core, "/events/queue/pop", name, strlen(name));
        pthread_mutex_unlock(&q->lock);

        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, item->data, item->len);
        free(item->data); free(item);
        return 0;
    }

    if (strcmp(msg->path, "/queue/functions/peek") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        named_queue_t *q = find_queue(name);
        if (!q) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        pthread_mutex_lock(&q->lock);
        if (q->head) {
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, q->head->data, q->head->len);
        } else {
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, "(empty)\n", 8);
        }
        pthread_mutex_unlock(&q->lock);
        return 0;
    }

    if (strcmp(msg->path, "/queue/functions/destroy") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        named_queue_t *q = find_queue(name);
        if (!q) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        pthread_mutex_lock(&q->lock);
        queue_item_t *item = q->head;
        while (item) { queue_item_t *nx = item->next; free(item->data); free(item); item = nx; }
        q->active = 0;
        pthread_mutex_unlock(&q->lock);
        pthread_mutex_destroy(&q->lock);
        n = snprintf(buf, sizeof(buf), "Queue '%s' destroyed\n", name);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
