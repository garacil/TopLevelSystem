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
 * storage.h — Storage provider interface for multiple backends
 *
 * File, SQLite, PostgreSQL, or any other backend implements this.
 * All providers receive writes. Core reads from first success.
 */

#ifndef PORTAL_STORAGE_H
#define PORTAL_STORAGE_H

#include "types.h"

/*
 * Storage Provider Interface
 *
 * Multiple providers can be active simultaneously (file, psql, sqlite).
 * The core writes to ALL providers and reads from the first that succeeds.
 *
 * Each provider registers under /core/storage/<name>/ with:
 *   /core/storage/<name>/resources/status  → connection info
 *   /core/storage/<name>/resources/tables  → list tables/files
 *   /core/storage/<name>/functions/sync    → force sync
 */

#define STORAGE_MAX_PROVIDERS 8

typedef void (*storage_list_fn)(const char *name, void *userdata);

typedef struct portal_storage_provider {
    const char *name;  /* "psql", "sqlite", etc. */

    /* Users */
    int  (*user_list)(void *ctx, storage_list_fn cb, void *userdata);
    int  (*user_load)(void *ctx, const char *username,
                       char *password, size_t pass_len,
                       char *api_key, size_t key_len,
                       char *groups, size_t groups_len);
    int  (*user_save)(void *ctx, const char *username,
                       const char *password, const char *api_key,
                       const char *groups);
    int  (*user_delete)(void *ctx, const char *username);

    /* Groups */
    int  (*group_list)(void *ctx, storage_list_fn cb, void *userdata);
    int  (*group_load)(void *ctx, const char *name,
                        char *description, size_t desc_len,
                        char *created_by, size_t cb_len);
    int  (*group_save)(void *ctx, const char *name,
                        const char *description, const char *created_by);
    int  (*group_delete)(void *ctx, const char *name);

    /* Module config */
    int  (*config_get)(void *ctx, const char *module, const char *key,
                        char *value, size_t val_len);
    int  (*config_set)(void *ctx, const char *module, const char *key,
                        const char *value);

    /* Status info (human-readable, for /resources/status) */
    int  (*status)(void *ctx, char *buf, size_t buf_len);

    /* Provider context */
    void *ctx;
} portal_storage_provider_t;

/* Multi-provider registry */
typedef struct {
    portal_storage_provider_t *providers[STORAGE_MAX_PROVIDERS];
    int count;
} portal_storage_registry_t;

void portal_storage_init(portal_storage_registry_t *reg);
int  portal_storage_add(portal_storage_registry_t *reg,
                         portal_storage_provider_t *provider);
int  portal_storage_remove(portal_storage_registry_t *reg, const char *name);
portal_storage_provider_t *portal_storage_find(portal_storage_registry_t *reg,
                                                const char *name);

/* Write to ALL providers */
void portal_storage_save_user(portal_storage_registry_t *reg,
                               const char *username, const char *password,
                               const char *api_key, const char *groups);
void portal_storage_save_group(portal_storage_registry_t *reg,
                                const char *name, const char *description,
                                const char *created_by);
void portal_storage_save_config(portal_storage_registry_t *reg,
                                 const char *module, const char *key,
                                 const char *value);

/* Read from first successful provider */
int  portal_storage_get_config(portal_storage_registry_t *reg,
                                const char *module, const char *key,
                                char *value, size_t val_len);

#endif /* PORTAL_STORAGE_H */
