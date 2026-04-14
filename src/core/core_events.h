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
 * core_events.h — Event registry with ACL-controlled subscriptions and emit
 */

#ifndef CORE_EVENTS_H
#define CORE_EVENTS_H

#include "portal/types.h"
#include "portal/core.h"

#define EVENT_MAX_DEFS  256
#define EVENT_MAX_SUBS  1024
#define AUTH_TOKEN_SIZE 33    /* AUTH_TOKEN_LEN + 1 from core_auth.h */

/* An event declared by a module */
typedef struct {
    char             path[PORTAL_MAX_PATH_LEN];
    char             module[PORTAL_MAX_MODULE_NAME];
    char             description[256];
    portal_labels_t  labels;
    int              active;
} portal_event_def_t;

/* A subscription to an event */
typedef struct {
    char             event_path[PORTAL_MAX_PATH_LEN];
    char             subscriber[PORTAL_MAX_LABEL_LEN];
    char             token[AUTH_TOKEN_SIZE];
    portal_labels_t  subscriber_labels;
    portal_event_fn  handler;       /* internal module callback (NULL for external) */
    void            *userdata;
    int              notify_fd;     /* socket fd for external notification (-1 = none) */
    int              active;
} portal_sub_t;

/* Event registry */
typedef struct {
    portal_event_def_t  defs[EVENT_MAX_DEFS];
    int                 def_count;
    portal_sub_t        subs[EVENT_MAX_SUBS];
    int                 sub_count;
} portal_event_registry_t;

void portal_events_init(portal_event_registry_t *reg);
void portal_events_destroy(portal_event_registry_t *reg);

/* Register an event (modules declare what they will emit) */
int  portal_events_register(portal_event_registry_t *reg,
                             const char *path, const char *module,
                             const char *description,
                             const portal_labels_t *labels);

/* Unregister an event */
int  portal_events_unregister(portal_event_registry_t *reg, const char *path);

/* Unregister all events from a module */
int  portal_events_unregister_module(portal_event_registry_t *reg,
                                      const char *module);

/* Find an event definition */
portal_event_def_t *portal_events_find(portal_event_registry_t *reg,
                                        const char *path);

/* Subscribe: internal module (handler callback, exact-path match).
 * Requires the event to be registered; applies ACL at subscribe time. */
int  portal_events_subscribe(portal_event_registry_t *reg,
                              const char *event_path,
                              const char *subscriber,
                              const portal_labels_t *subscriber_labels,
                              portal_event_fn handler, void *userdata);

/* Subscribe by pattern: supports "/foo/ *" suffix, "*" global, or exact.
 * Does NOT require the event to be pre-registered (for consumers like
 * mod_audit that listen to "/events/ *"). ACL is enforced at emit-time:
 * if the matched event has labels, subscriber_labels must intersect.
 * subscriber_labels == NULL is treated as {"root"} (trusted internal). */
int  portal_events_subscribe_pattern(portal_event_registry_t *reg,
                                      const char *pattern,
                                      const char *subscriber,
                                      const portal_labels_t *subscriber_labels,
                                      portal_event_fn handler, void *userdata);

/* Unsubscribe by (pattern, handler) tuple — matches what api_unsubscribe
 * needs after subscribe_pattern. Returns 0 if one entry was removed. */
int  portal_events_unsubscribe_handler(portal_event_registry_t *reg,
                                        const char *pattern,
                                        portal_event_fn handler);

/* Subscribe: external client (fd notification) */
int  portal_events_subscribe_fd(portal_event_registry_t *reg,
                                 const char *event_path,
                                 const char *subscriber,
                                 const portal_labels_t *subscriber_labels,
                                 const char *token, int notify_fd);

/* Unsubscribe */
int  portal_events_unsubscribe(portal_event_registry_t *reg,
                                const char *event_path,
                                const char *subscriber);

/* Unsubscribe all for a subscriber (cleanup on disconnect/logout) */
int  portal_events_unsubscribe_all(portal_event_registry_t *reg,
                                    const char *subscriber);

/* Emit an event: fan out to all matching subscribers with ACL check */
int  portal_events_emit(portal_event_registry_t *reg,
                         const char *event_path,
                         const void *data, size_t data_len);

/* List all events (calls callback for each) */
typedef void (*portal_event_list_fn)(const portal_event_def_t *def, void *userdata);
void portal_events_list(portal_event_registry_t *reg,
                         portal_event_list_fn callback, void *userdata);

/* List subscriptions for a subscriber */
typedef void (*portal_sub_list_fn)(const portal_sub_t *sub, void *userdata);
void portal_events_list_subs(portal_event_registry_t *reg,
                              const char *subscriber,
                              portal_sub_list_fn callback, void *userdata);

/* Count events and subscriptions */
int  portal_events_count(portal_event_registry_t *reg);
int  portal_events_sub_count(portal_event_registry_t *reg);

#endif /* CORE_EVENTS_H */
