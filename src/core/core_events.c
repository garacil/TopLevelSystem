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
 * core_events.c — Event registry with ACL-controlled subscriptions
 *
 * Modules register events, users/modules subscribe with label checks.
 * Events emit to internal callbacks and external fd notifications.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "core_events.h"
#include "core_log.h"

void portal_events_init(portal_event_registry_t *reg)
{
    memset(reg, 0, sizeof(*reg));
}

void portal_events_destroy(portal_event_registry_t *reg)
{
    memset(reg, 0, sizeof(*reg));
}

/* --- Event definitions --- */

int portal_events_register(portal_event_registry_t *reg,
                            const char *path, const char *module,
                            const char *description,
                            const portal_labels_t *labels)
{
    if (portal_events_find(reg, path)) {
        LOG_WARN("events", "Event '%s' already registered", path);
        return -1;
    }

    if (reg->def_count >= EVENT_MAX_DEFS)
        return -1;

    portal_event_def_t *def = &reg->defs[reg->def_count++];
    snprintf(def->path, sizeof(def->path), "%s", path);
    snprintf(def->module, sizeof(def->module), "%s", module);
    snprintf(def->description, sizeof(def->description), "%s",
             description ? description : "");
    if (labels)
        memcpy(&def->labels, labels, sizeof(portal_labels_t));
    def->active = 1;

    LOG_DEBUG("events", "Registered event '%s' [%s]", path, module);
    return 0;
}

int portal_events_unregister(portal_event_registry_t *reg, const char *path)
{
    for (int i = 0; i < reg->def_count; i++) {
        if (reg->defs[i].active && strcmp(reg->defs[i].path, path) == 0) {
            reg->defs[i].active = 0;
            LOG_DEBUG("events", "Unregistered event '%s'", path);
            return 0;
        }
    }
    return -1;
}

int portal_events_unregister_module(portal_event_registry_t *reg,
                                     const char *module)
{
    int count = 0;
    for (int i = 0; i < reg->def_count; i++) {
        if (reg->defs[i].active &&
            strcmp(reg->defs[i].module, module) == 0) {
            reg->defs[i].active = 0;
            count++;
        }
    }
    return count;
}

portal_event_def_t *portal_events_find(portal_event_registry_t *reg,
                                        const char *path)
{
    for (int i = 0; i < reg->def_count; i++) {
        if (reg->defs[i].active && strcmp(reg->defs[i].path, path) == 0)
            return &reg->defs[i];
    }
    return NULL;
}

/* --- Subscriptions --- */

static int check_acl(const portal_event_def_t *def,
                      const portal_labels_t *sub_labels)
{
    /* No labels on event = public */
    if (def->labels.count == 0)
        return 1;

    /* Check if subscriber has root label */
    if (portal_labels_has(sub_labels, "root"))
        return 1;

    /* Intersection check */
    return portal_labels_intersects(&def->labels, sub_labels);
}

int portal_events_subscribe(portal_event_registry_t *reg,
                             const char *event_path,
                             const char *subscriber,
                             const portal_labels_t *subscriber_labels,
                             portal_event_fn handler, void *userdata)
{
    portal_event_def_t *def = portal_events_find(reg, event_path);
    if (!def) {
        LOG_WARN("events", "Subscribe failed: event '%s' not found", event_path);
        return -1;
    }

    if (!check_acl(def, subscriber_labels)) {
        LOG_WARN("events", "Subscribe denied: '%s' lacks labels for '%s'",
                 subscriber, event_path);
        return -1;
    }

    /* Check duplicate */
    for (int i = 0; i < reg->sub_count; i++) {
        if (reg->subs[i].active &&
            strcmp(reg->subs[i].event_path, event_path) == 0 &&
            strcmp(reg->subs[i].subscriber, subscriber) == 0)
            return 0;  /* already subscribed */
    }

    if (reg->sub_count >= EVENT_MAX_SUBS)
        return -1;

    portal_sub_t *sub = &reg->subs[reg->sub_count++];
    snprintf(sub->event_path, sizeof(sub->event_path), "%s", event_path);
    snprintf(sub->subscriber, sizeof(sub->subscriber), "%s", subscriber);
    if (subscriber_labels)
        memcpy(&sub->subscriber_labels, subscriber_labels, sizeof(portal_labels_t));
    sub->handler = handler;
    sub->userdata = userdata;
    sub->notify_fd = -1;
    sub->active = 1;

    LOG_INFO("events", "'%s' subscribed to '%s'", subscriber, event_path);
    return 0;
}

int portal_events_subscribe_fd(portal_event_registry_t *reg,
                                const char *event_path,
                                const char *subscriber,
                                const portal_labels_t *subscriber_labels,
                                const char *token, int notify_fd)
{
    portal_event_def_t *def = portal_events_find(reg, event_path);
    if (!def) return -1;

    if (!check_acl(def, subscriber_labels))
        return -1;

    /* Check duplicate */
    for (int i = 0; i < reg->sub_count; i++) {
        if (reg->subs[i].active &&
            strcmp(reg->subs[i].event_path, event_path) == 0 &&
            strcmp(reg->subs[i].subscriber, subscriber) == 0)
            return 0;
    }

    if (reg->sub_count >= EVENT_MAX_SUBS)
        return -1;

    portal_sub_t *sub = &reg->subs[reg->sub_count++];
    snprintf(sub->event_path, sizeof(sub->event_path), "%s", event_path);
    snprintf(sub->subscriber, sizeof(sub->subscriber), "%s", subscriber);
    if (subscriber_labels)
        memcpy(&sub->subscriber_labels, subscriber_labels, sizeof(portal_labels_t));
    if (token)
        snprintf(sub->token, sizeof(sub->token), "%s", token);
    sub->handler = NULL;
    sub->userdata = NULL;
    sub->notify_fd = notify_fd;
    sub->active = 1;

    LOG_INFO("events", "'%s' subscribed to '%s' (fd=%d)",
             subscriber, event_path, notify_fd);
    return 0;
}

int portal_events_unsubscribe(portal_event_registry_t *reg,
                               const char *event_path,
                               const char *subscriber)
{
    for (int i = 0; i < reg->sub_count; i++) {
        if (reg->subs[i].active &&
            strcmp(reg->subs[i].event_path, event_path) == 0 &&
            strcmp(reg->subs[i].subscriber, subscriber) == 0) {
            reg->subs[i].active = 0;
            LOG_INFO("events", "'%s' unsubscribed from '%s'",
                     subscriber, event_path);
            return 0;
        }
    }
    return -1;
}

int portal_events_unsubscribe_all(portal_event_registry_t *reg,
                                   const char *subscriber)
{
    int count = 0;
    for (int i = 0; i < reg->sub_count; i++) {
        if (reg->subs[i].active &&
            strcmp(reg->subs[i].subscriber, subscriber) == 0) {
            reg->subs[i].active = 0;
            count++;
        }
    }
    return count;
}

/* --- Emit --- */

int portal_events_emit(portal_event_registry_t *reg,
                        const char *event_path,
                        const void *data, size_t data_len)
{
    int delivered = 0;

    /* Build a message for callbacks */
    portal_msg_t msg = {0};
    msg.path = (char *)event_path;
    msg.method = PORTAL_METHOD_EVENT;
    msg.body = (void *)data;
    msg.body_len = data_len;

    for (int i = 0; i < reg->sub_count; i++) {
        portal_sub_t *sub = &reg->subs[i];
        if (!sub->active) continue;
        if (strcmp(sub->event_path, event_path) != 0) continue;

        if (sub->handler) {
            /* Internal module callback */
            sub->handler(&msg, sub->userdata);
            delivered++;
        } else if (sub->notify_fd >= 0) {
            /* External: send text notification over fd */
            char buf[PORTAL_MAX_PATH_LEN + 256];
            int n;
            if (data && data_len > 0)
                n = snprintf(buf, sizeof(buf), "[EVENT] %s: %.*s\n",
                             event_path, (int)data_len, (const char *)data);
            else
                n = snprintf(buf, sizeof(buf), "[EVENT] %s\n", event_path);

            if (write(sub->notify_fd, buf, (size_t)n) < 0) {
                /* Client disconnected — remove subscription */
                sub->active = 0;
                continue;
            }
            delivered++;
        }
    }

    if (delivered > 0)
        LOG_TRACE("events", "Emitted '%s' to %d subscribers", event_path, delivered);
    return delivered;
}

/* --- Listing --- */

void portal_events_list(portal_event_registry_t *reg,
                         portal_event_list_fn callback, void *userdata)
{
    for (int i = 0; i < reg->def_count; i++) {
        if (reg->defs[i].active)
            callback(&reg->defs[i], userdata);
    }
}

void portal_events_list_subs(portal_event_registry_t *reg,
                              const char *subscriber,
                              portal_sub_list_fn callback, void *userdata)
{
    for (int i = 0; i < reg->sub_count; i++) {
        if (reg->subs[i].active &&
            strcmp(reg->subs[i].subscriber, subscriber) == 0)
            callback(&reg->subs[i], userdata);
    }
}

int portal_events_count(portal_event_registry_t *reg)
{
    int n = 0;
    for (int i = 0; i < reg->def_count; i++)
        if (reg->defs[i].active) n++;
    return n;
}

int portal_events_sub_count(portal_event_registry_t *reg)
{
    int n = 0;
    for (int i = 0; i < reg->sub_count; i++)
        if (reg->subs[i].active) n++;
    return n;
}
