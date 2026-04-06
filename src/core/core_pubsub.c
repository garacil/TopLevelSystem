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
 * core_pubsub.c — Publish/Subscribe event dispatching
 *
 * Pattern-based subscription matching (exact, wildcard, global).
 * Internal module callbacks for low-latency event delivery.
 */

#include <stdio.h>
#include <string.h>
#include "core_pubsub.h"
#include "core_log.h"

void portal_pubsub_init(portal_pubsub_t *ps)
{
    memset(ps, 0, sizeof(*ps));
}

void portal_pubsub_destroy(portal_pubsub_t *ps)
{
    memset(ps, 0, sizeof(*ps));
}

/*
 * Pattern matching:
 *   "/events/login"  matches exactly "/events/login"
 *   "/events/ *"     matches any path starting with "/events/"
 *   "*"              matches everything
 */
static int pattern_matches(const char *pattern, const char *path)
{
    size_t plen = strlen(pattern);

    /* Wildcard suffix: "/foo/ *" matches "/foo/bar", "/foo/bar/baz" */
    if (plen >= 2 && pattern[plen - 1] == '*' && pattern[plen - 2] == '/') {
        return strncmp(pattern, path, plen - 1) == 0;
    }

    /* Global wildcard */
    if (strcmp(pattern, "*") == 0)
        return 1;

    /* Exact match */
    return strcmp(pattern, path) == 0;
}

int portal_pubsub_subscribe(portal_pubsub_t *ps, const char *pattern,
                             portal_event_fn handler, void *userdata)
{
    /* Check for duplicate */
    for (int i = 0; i < ps->count; i++) {
        if (ps->entries[i].active &&
            ps->entries[i].handler == handler &&
            strcmp(ps->entries[i].pattern, pattern) == 0)
            return 0;  /* already subscribed */
    }

    /* Find free slot */
    pubsub_entry_t *entry = NULL;
    for (int i = 0; i < ps->count; i++) {
        if (!ps->entries[i].active) {
            entry = &ps->entries[i];
            break;
        }
    }
    if (!entry) {
        if (ps->count >= PUBSUB_MAX_SUBS) return -1;
        entry = &ps->entries[ps->count++];
    }

    snprintf(entry->pattern, sizeof(entry->pattern), "%s", pattern);
    entry->handler = handler;
    entry->userdata = userdata;
    entry->active = 1;

    LOG_DEBUG("pubsub", "Subscribed to '%s'", pattern);
    return 0;
}

int portal_pubsub_unsubscribe(portal_pubsub_t *ps, const char *pattern,
                               portal_event_fn handler)
{
    for (int i = 0; i < ps->count; i++) {
        if (ps->entries[i].active &&
            ps->entries[i].handler == handler &&
            strcmp(ps->entries[i].pattern, pattern) == 0) {
            ps->entries[i].active = 0;
            LOG_DEBUG("pubsub", "Unsubscribed from '%s'", pattern);
            return 0;
        }
    }
    return -1;
}

int portal_pubsub_publish(portal_pubsub_t *ps, const portal_msg_t *msg)
{
    int delivered = 0;

    for (int i = 0; i < ps->count; i++) {
        if (!ps->entries[i].active) continue;
        if (pattern_matches(ps->entries[i].pattern, msg->path)) {
            ps->entries[i].handler(msg, ps->entries[i].userdata);
            delivered++;
        }
    }

    if (delivered > 0)
        LOG_TRACE("pubsub", "Published to %d subscribers on '%s'",
                  delivered, msg->path);
    return delivered;
}

int portal_pubsub_count(portal_pubsub_t *ps)
{
    int n = 0;
    for (int i = 0; i < ps->count; i++)
        if (ps->entries[i].active) n++;
    return n;
}
