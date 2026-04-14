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
 * portal_instance.h — Core instance struct holding all subsystems
 */

#ifndef PORTAL_INSTANCE_H
#define PORTAL_INSTANCE_H

#include "portal/core.h"
#include "core_config.h"
#include "core_path.h"
#include "core_module.h"
#include "core_event.h"
#include "core_auth.h"
#include "core_events.h"
#include "core_store.h"

/* Exclusive resource lock (physical resources) */
#define LOCK_MAX          64
#define LOCK_TIMEOUT_SEC  60  /* auto-release after 2 missed keepalives */

typedef struct {
    char   resource[PORTAL_MAX_PATH_LEN]; /* e.g. "/serial/ttyUSB0" */
    char   owner[128];                     /* e.g. "root@cli:5" */
    time_t locked_at;
    time_t last_keepalive;
    int    active;
} resource_lock_t;

/* Message trace subscriber (verbose/debug from CLI) */
#define TRACE_MAX_SUBS 8
typedef struct {
    int   fd;                              /* CLI fd to write to */
    char  filter[PORTAL_MAX_PATH_LEN];     /* path prefix filter ("/" = all) */
    char  prompt[64];                      /* CLI prompt to redraw after trace */
    char *line_buf;                        /* pointer to editor line buffer */
    int  *line_len;                        /* pointer to editor line length */
    int  *cursor_pos;                      /* pointer to editor cursor position */
    int   debug;                           /* 1 = show hex+text dump of body */
    int   active;
} trace_sub_t;

/*
 * The portal instance — holds all core state.
 * This is the _internal pointer inside portal_core_t.
 */
typedef struct {
    portal_config_t          config;
    portal_path_tree_t       paths;
    portal_module_registry_t modules;
    portal_event_loop_t      events;
    portal_auth_registry_t   auth;
    portal_event_registry_t  events_reg;
    portal_store_t           store;
    portal_storage_registry_t storage;  /* multi-provider registry */
    portal_core_t            api;        /* the public API given to modules */
    trace_sub_t              trace_subs[TRACE_MAX_SUBS];
    int                      trace_count;
    resource_lock_t          locks[LOCK_MAX];
    int                      lock_count;
} portal_instance_t;

/* Initialize and destroy the full instance */
int  portal_instance_init(portal_instance_t *inst);
void portal_instance_destroy(portal_instance_t *inst);

/* Wire up the core API function pointers */
void portal_instance_setup_api(portal_instance_t *inst);

/* Register internal core paths */
void portal_instance_register_core_paths(portal_instance_t *inst);

/* Cleanup expired resource locks (called by timer) */
void lock_cleanup(portal_instance_t *inst);

#endif /* PORTAL_INSTANCE_H */
