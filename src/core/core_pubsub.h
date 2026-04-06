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
 * core_pubsub.h — Pub/sub with exact, wildcard, and global pattern matching
 */

#ifndef CORE_PUBSUB_H
#define CORE_PUBSUB_H

#include "portal/types.h"
#include "portal/core.h"

#define PUBSUB_MAX_SUBS 512

typedef struct {
    char             pattern[PORTAL_MAX_PATH_LEN];
    portal_event_fn  handler;
    void            *userdata;
    char             module[PORTAL_MAX_MODULE_NAME];
    int              active;
} pubsub_entry_t;

typedef struct {
    pubsub_entry_t  entries[PUBSUB_MAX_SUBS];
    int             count;
} portal_pubsub_t;

void portal_pubsub_init(portal_pubsub_t *ps);
void portal_pubsub_destroy(portal_pubsub_t *ps);

int  portal_pubsub_subscribe(portal_pubsub_t *ps, const char *pattern,
                              portal_event_fn handler, void *userdata);
int  portal_pubsub_unsubscribe(portal_pubsub_t *ps, const char *pattern,
                                portal_event_fn handler);

/* Publish: fan out msg to all subscribers whose pattern matches msg->path */
int  portal_pubsub_publish(portal_pubsub_t *ps, const portal_msg_t *msg);

/* Count active subscriptions */
int  portal_pubsub_count(portal_pubsub_t *ps);

#endif /* CORE_PUBSUB_H */
