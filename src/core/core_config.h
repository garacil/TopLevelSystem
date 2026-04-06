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
 * core_config.h — Configuration parser with per-module section support
 */

#ifndef CORE_CONFIG_H
#define CORE_CONFIG_H

#include "portal/constants.h"
#include "core_hashtable.h"

#define PORTAL_MAX_CONFIG_MODULES 64
#define PORTAL_MAX_LINE           512

typedef struct {
    char  modules_dir[PORTAL_MAX_PATH_LEN];
    char  socket_path[PORTAL_MAX_PATH_LEN];
    char  users_file[PORTAL_MAX_PATH_LEN];
    char  pid_file[PORTAL_MAX_PATH_LEN];
    char  data_dir[PORTAL_MAX_PATH_LEN];    /* /etc/portal/<name> (config) */
    char  app_dir[PORTAL_MAX_PATH_LEN];    /* /var/lib/portal/<name> (code+data) */
    char  log_dir[PORTAL_MAX_PATH_LEN];    /* /var/log/portal/<name> (logs) */
    int   tcp_port;       /* core TCP listen port (0 = disabled) */
    int   udp_port;       /* core UDP listen port (0 = disabled) */
    int   log_level;
    int   module_count;
    char  modules[PORTAL_MAX_CONFIG_MODULES][PORTAL_MAX_MODULE_NAME];

    /* All key=value pairs from all sections: "section.key" → "value" */
    portal_ht_t  sections;
} portal_config_t;

/* Parse config file. Returns 0 on success, -1 on error. */
int  portal_config_load(portal_config_t *cfg, const char *path);

/* Scan <data_dir>/modules/ for mod_*.conf files and load them.
 * Each file auto-registers the module for loading. */
int  portal_config_load_modules_dir(portal_config_t *cfg);

/* Fill config with sane defaults */
void portal_config_defaults(portal_config_t *cfg);

/* Destroy config (free hash table) */
void portal_config_destroy(portal_config_t *cfg);

/* Get a config value for a module: config_get("web", "port") reads [mod_web] port= */
const char *portal_config_get(portal_config_t *cfg, const char *section,
                               const char *key);

#endif /* CORE_CONFIG_H */
