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
 * core.h — The core API struct that every module receives
 *
 * Contains function pointers for path registration, message routing,
 * event management, storage, configuration, and logging.
 */

#ifndef PORTAL_CORE_H
#define PORTAL_CORE_H

#include "types.h"
#include "storage.h"

/* Forward declaration */
typedef struct portal_core portal_core_t;

/* Event handler callback for subscriptions */
typedef void (*portal_event_fn)(const portal_msg_t *msg, void *userdata);

/* Event loop fd callback */
typedef void (*portal_fd_fn)(int fd, uint32_t events, void *userdata);

/* Timer callback */
typedef void (*portal_timer_fn)(void *userdata);

/* The core API — every module receives a pointer to this */
struct portal_core {
    /* Path registration */
    int  (*path_register)(portal_core_t *core, const char *path, const char *module_name);
    int  (*path_unregister)(portal_core_t *core, const char *path);

    /* Send a message to a path (routed through core) */
    int  (*send)(portal_core_t *core, portal_msg_t *msg, portal_resp_t *resp);

    /* Pub/sub events */
    int  (*subscribe)(portal_core_t *core, const char *path_pattern,
                      portal_event_fn handler, void *userdata);
    int  (*unsubscribe)(portal_core_t *core, const char *path_pattern,
                        portal_event_fn handler);

    /* Path access mode (Law 8: R/W/RW) */
    int  (*path_set_access)(portal_core_t *core, const char *path, uint8_t mode);

    /* Path labels (access control) */
    int  (*path_add_label)(portal_core_t *core, const char *path, const char *label);
    int  (*path_remove_label)(portal_core_t *core, const char *path, const char *label);

    /* Module queries */
    int  (*module_loaded)(portal_core_t *core, const char *name);

    /* Event loop fd management — modules register fds they want polled */
    int  (*fd_add)(portal_core_t *core, int fd, uint32_t events,
                   portal_fd_fn callback, void *userdata);
    int  (*fd_del)(portal_core_t *core, int fd);

    /* Event system (modules declare, emit, and subscribe to events) */
    int  (*event_register)(portal_core_t *core, const char *event_path,
                           const char *description, const portal_labels_t *labels);
    int  (*event_unregister)(portal_core_t *core, const char *event_path);
    int  (*event_emit)(portal_core_t *core, const char *event_path,
                       const void *data, size_t data_len);

    /* Storage provider registration (DB backends register here) */
    int  (*storage_register)(portal_core_t *core,
                              portal_storage_provider_t *provider);

    /* Configuration (read module-specific config values) */
    const char *(*config_get)(portal_core_t *core, const char *module,
                               const char *key);

    /* Logging */
    void (*log)(portal_core_t *core, int level, const char *module,
                const char *fmt, ...);

    /* Periodic timer (event loop, no cron dependency) */
    int  (*timer_add)(portal_core_t *core, double interval_sec,
                      portal_timer_fn callback, void *userdata);

    /* Message tracing (verbose from CLI) */
    int  (*trace_add)(portal_core_t *core, int fd, const char *filter,
                      const char *prompt, char *line_buf, int *line_len,
                      int *cursor_pos, int debug);
    int  (*trace_del)(portal_core_t *core, int fd);

    /* Exclusive resource locking (physical resources) */
    int         (*resource_lock)(portal_core_t *core, const char *resource,
                                  const char *owner);
    int         (*resource_unlock)(portal_core_t *core, const char *resource,
                                    const char *owner);
    int         (*resource_keepalive)(portal_core_t *core, const char *resource,
                                      const char *owner);
    int         (*resource_locked)(portal_core_t *core, const char *resource);
    const char *(*resource_owner)(portal_core_t *core, const char *resource);

    /* Opaque internal state — modules must not touch */
    void *_internal;
};

#endif /* PORTAL_CORE_H */
