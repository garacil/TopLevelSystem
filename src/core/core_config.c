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
 * core_config.c — Portal configuration parser
 *
 * Reads INI-format config files. Stores all key=value pairs
 * in a hash table as "section.key" for per-module config access.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include "core_config.h"
#include "core_log.h"

void portal_config_defaults(portal_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->modules_dir, sizeof(cfg->modules_dir), "%s", PORTAL_DEFAULT_MODULES);
    snprintf(cfg->socket_path, sizeof(cfg->socket_path), "%s", PORTAL_DEFAULT_SOCKET);
    snprintf(cfg->users_file, sizeof(cfg->users_file), "./users.conf");
    snprintf(cfg->pid_file, sizeof(cfg->pid_file), "/var/run/portal.pid");
    snprintf(cfg->data_dir, sizeof(cfg->data_dir), "/etc/portal");
    snprintf(cfg->app_dir, sizeof(cfg->app_dir), "/var/lib/portal");
    snprintf(cfg->log_dir, sizeof(cfg->log_dir), "/var/log/portal");
    cfg->tcp_port = 0;   /* disabled by default */
    cfg->udp_port = 0;   /* disabled by default */
    cfg->log_level = PORTAL_LOG_INFO;
    cfg->module_count = 0;
    portal_ht_init(&cfg->sections, HT_INITIAL_CAPACITY);
}

void portal_config_destroy(portal_config_t *cfg)
{
    /* Free strdup'd values in hash table */
    portal_ht_destroy(&cfg->sections);
}

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

int portal_config_load(portal_config_t *cfg, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_WARN("config", "Config file '%s' not found, using defaults", path);
        return -1;
    }

    char line[PORTAL_MAX_LINE];
    char section[64] = {0};

    while (fgets(line, sizeof(line), f)) {
        char *s = trim(line);

        if (*s == '\0' || *s == '#' || *s == ';')
            continue;

        if (*s == '[') {
            char *end = strchr(s, ']');
            if (end) {
                *end = '\0';
                snprintf(section, sizeof(section), "%s", s + 1);
            }
            continue;
        }

        char *eq = strchr(s, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);

        /* Store ALL key-values in the hash table as "section.key" → "value" */
        char full_key[256];
        snprintf(full_key, sizeof(full_key), "%s.%s", section, key);
        portal_ht_set(&cfg->sections, full_key, strdup(val));

        /* Also parse known [core] and [modules] fields into struct */
        if (strcmp(section, "core") == 0) {
            if (strcmp(key, "modules_dir") == 0)
                snprintf(cfg->modules_dir, sizeof(cfg->modules_dir), "%s", val);
            else if (strcmp(key, "socket_path") == 0)
                snprintf(cfg->socket_path, sizeof(cfg->socket_path), "%s", val);
            else if (strcmp(key, "users_file") == 0)
                snprintf(cfg->users_file, sizeof(cfg->users_file), "%s", val);
            else if (strcmp(key, "pid_file") == 0)
                snprintf(cfg->pid_file, sizeof(cfg->pid_file), "%s", val);
            else if (strcmp(key, "data_dir") == 0)
                snprintf(cfg->data_dir, sizeof(cfg->data_dir), "%s", val);
            else if (strcmp(key, "app_dir") == 0)
                snprintf(cfg->app_dir, sizeof(cfg->app_dir), "%s", val);
            else if (strcmp(key, "log_dir") == 0)
                snprintf(cfg->log_dir, sizeof(cfg->log_dir), "%s", val);
            else if (strcmp(key, "tcp_port") == 0)
                cfg->tcp_port = atoi(val);
            else if (strcmp(key, "udp_port") == 0)
                cfg->udp_port = atoi(val);
            else if (strcmp(key, "log_level") == 0) {
                if (strcmp(val, "error") == 0) cfg->log_level = PORTAL_LOG_ERROR;
                else if (strcmp(val, "warn") == 0)  cfg->log_level = PORTAL_LOG_WARN;
                else if (strcmp(val, "info") == 0)  cfg->log_level = PORTAL_LOG_INFO;
                else if (strcmp(val, "debug") == 0) cfg->log_level = PORTAL_LOG_DEBUG;
                else if (strcmp(val, "trace") == 0) cfg->log_level = PORTAL_LOG_TRACE;
            }
        } else if (strcmp(section, "modules") == 0) {
            if (strcmp(key, "load") == 0 && cfg->module_count < PORTAL_MAX_CONFIG_MODULES) {
                snprintf(cfg->modules[cfg->module_count], PORTAL_MAX_MODULE_NAME, "%s", val);
                cfg->module_count++;
            }
        }
    }

    fclose(f);
    LOG_INFO("config", "Loaded config from '%s'", path);
    return 0;
}

const char *portal_config_get(portal_config_t *cfg, const char *section,
                               const char *key)
{
    char full_key[256];

    /* Try "mod_<section>.<key>" first (from [mod_<name>] sections) */
    snprintf(full_key, sizeof(full_key), "mod_%s.%s", section, key);
    const char *val = portal_ht_get(&cfg->sections, full_key);
    if (val) return val;

    /* Fallback: try "<section>.<key>" (from [<name>] sections) */
    snprintf(full_key, sizeof(full_key), "%s.%s", section, key);
    return portal_ht_get(&cfg->sections, full_key);
}

/*
 * Scan a directory for mod_*.conf files and load them.
 * Each file auto-registers the module for loading.
 *
 * File naming: mod_<name>.conf
 *   - Standard INI config with [mod_<name>] section
 *   - "enabled = true" (default) or "enabled = false" to disable
 *   - All key=value pairs stored in hash table as "section.key"
 */
static int load_module_conf_dir(portal_config_t *cfg, const char *dir,
                                 const char *label)
{
    DIR *d = opendir(dir);
    if (!d) return 0;

    struct dirent *ent;
    int loaded = 0;

    while ((ent = readdir(d)) != NULL) {
        /* Match mod_*.conf */
        if (strncmp(ent->d_name, "mod_", 4) != 0) continue;
        size_t namelen = strlen(ent->d_name);
        if (namelen < 10 || strcmp(ent->d_name + namelen - 5, ".conf") != 0) continue;

        /* Extract module name: mod_<name>.conf -> <name> */
        char mod_name[PORTAL_MAX_MODULE_NAME];
        size_t nlen = namelen - 4 - 5;
        if (nlen >= PORTAL_MAX_MODULE_NAME) nlen = PORTAL_MAX_MODULE_NAME - 1;
        memcpy(mod_name, ent->d_name + 4, nlen);
        mod_name[nlen] = '\0';

        /* Build full path */
        char fpath[PORTAL_MAX_PATH_LEN + 280];
        snprintf(fpath, sizeof(fpath), "%s/%s", dir, ent->d_name);

        /* Parse the module config file */
        FILE *f = fopen(fpath, "r");
        if (!f) continue;

        char line[PORTAL_MAX_LINE];
        char section[128];
        snprintf(section, sizeof(section), "mod_%s", mod_name);
        int enabled = 1;

        while (fgets(line, sizeof(line), f)) {
            char *s = trim(line);
            if (*s == '\0' || *s == '#' || *s == ';') continue;

            if (*s == '[') {
                char *end = strchr(s, ']');
                if (end) { *end = '\0'; snprintf(section, sizeof(section), "%s", s + 1); }
                continue;
            }

            char *eq = strchr(s, '=');
            if (!eq) continue;
            *eq = '\0';
            char *key = trim(s);
            char *val = trim(eq + 1);

            if (strcmp(key, "enabled") == 0) {
                enabled = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0 ||
                           strcmp(val, "yes") == 0);
                continue;
            }

            char full_key[256];
            snprintf(full_key, sizeof(full_key), "%s.%s", section, key);
            portal_ht_set(&cfg->sections, full_key, strdup(val));
        }
        fclose(f);

        if (enabled && cfg->module_count < PORTAL_MAX_CONFIG_MODULES) {
            int already = 0;
            for (int i = 0; i < cfg->module_count; i++) {
                if (strcmp(cfg->modules[i], mod_name) == 0) { already = 1; break; }
            }
            if (!already) {
                snprintf(cfg->modules[cfg->module_count], PORTAL_MAX_MODULE_NAME,
                         "%s", mod_name);
                cfg->module_count++;
            }
        }

        loaded++;
        LOG_DEBUG("config", "  [%s] %s (%s)", label, ent->d_name,
                  enabled ? "enabled" : "disabled");
    }

    closedir(d);
    return loaded;
}

/*
 * Load per-module config files from the instance modules directory.
 *
 * Scan order:
 *   1. <data_dir>/modules/core/   — Infrastructure modules (cli, node, web, ssh, storage)
 *   2. <data_dir>/modules/        — Application modules (everything else)
 *
 * Core modules load first so infrastructure is ready before application modules.
 */
int portal_config_load_modules_dir(portal_config_t *cfg)
{
    int total = 0;

    /* 1. Load core infrastructure modules first */
    char core_dir[PORTAL_MAX_PATH_LEN + 32];
    snprintf(core_dir, sizeof(core_dir), "%s/modules/core", cfg->data_dir);
    int core_count = load_module_conf_dir(cfg, core_dir, "core");
    total += core_count;

    /* 2. Load application modules */
    char mod_dir[PORTAL_MAX_PATH_LEN + 16];
    snprintf(mod_dir, sizeof(mod_dir), "%s/modules", cfg->data_dir);
    int app_count = load_module_conf_dir(cfg, mod_dir, "module");
    total += app_count;

    if (total > 0)
        LOG_INFO("config", "Loaded %d module configs (%d core + %d application)",
                 total, core_count, app_count);
    return total;
}
