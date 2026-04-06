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
 * core_module.h — Module registry: load, unload, reload with reference counting
 */

#ifndef CORE_MODULE_H
#define CORE_MODULE_H

#include "portal/module.h"
#include "portal/constants.h"

typedef struct {
    portal_module_entry_t  entries[PORTAL_MAX_MODULES];
    int                    count;
    char                   modules_dir[PORTAL_MAX_PATH_LEN];
} portal_module_registry_t;

void portal_module_registry_init(portal_module_registry_t *reg, const char *modules_dir);
void portal_module_registry_destroy(portal_module_registry_t *reg, portal_core_t *core);

/* Load a module by name (looks for mod_<name>.so in modules_dir) */
int  portal_module_do_load(portal_module_registry_t *reg, const char *name,
                            portal_core_t *core);

/* Unload a module by name */
int  portal_module_do_unload(portal_module_registry_t *reg, const char *name,
                              portal_core_t *core);

/* Find a loaded module entry by name */
portal_module_entry_t *portal_module_find(portal_module_registry_t *reg,
                                           const char *name);

/* Check if a module is loaded */
int  portal_module_is_loaded(portal_module_registry_t *reg, const char *name);

/* Reload a module (atomic unload + load) */
int  portal_module_do_reload(portal_module_registry_t *reg, const char *name,
                              portal_core_t *core);

#endif /* CORE_MODULE_H */
