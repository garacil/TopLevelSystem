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
 * core_store.h — File-based persistent storage: users, groups, module configs
 */

#ifndef CORE_STORE_H
#define CORE_STORE_H

#include "portal/constants.h"
#include "core_hashtable.h"

/*
 * Persistent file-based storage layer.
 *
 * Directory layout:
 *   <base_dir>/users/<name>.conf    — one INI file per user
 *   <base_dir>/groups/<name>.conf   — one INI file per group
 *   <base_dir>/modules/<name>.conf  — one INI file per module config
 */

typedef struct {
    char base_dir[PORTAL_MAX_PATH_LEN];
} portal_store_t;

/* Initialize store and create directories if missing */
int  portal_store_init(portal_store_t *store, const char *base_dir);

/* --- Generic INI file operations --- */

/* Load all key=value pairs from a file into a hash table.
 * Values are strdup'd — caller must free via portal_ht_destroy. */
int  portal_store_read_ini(const char *path, portal_ht_t *kv);

/* Write key=value pairs atomically (write to .tmp, rename) */
int  portal_store_write_ini(const char *path, portal_ht_t *kv);

/* Read a single value from an INI file. Returns strdup'd string or NULL. */
char *portal_store_read_value(const char *path, const char *key);

/* Write/update a single key in an INI file (preserves other keys) */
int  portal_store_write_value(const char *path, const char *key, const char *value);

/* --- Directory listing --- */

/* List files in a directory (strips .conf extension).
 * Calls cb(name, userdata) for each. */
typedef void (*portal_store_list_fn)(const char *name, void *userdata);
int  portal_store_list_dir(const char *dir_path, portal_store_list_fn cb,
                            void *userdata);

/* --- Convenience paths --- */

/* Build path: <base_dir>/<subdir>/<name>.conf */
void portal_store_path(const portal_store_t *store, const char *subdir,
                        const char *name, char *out, size_t out_len);

/* Check if a file exists */
int  portal_store_exists(const char *path);

/* Delete a file. Returns 0 on success. */
int  portal_store_delete(const char *path);

#endif /* CORE_STORE_H */
