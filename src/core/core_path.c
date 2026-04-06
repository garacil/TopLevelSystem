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
 * core_path.c — Path registry with label-based ACL
 *
 * Hash table backed O(1) path lookup. Supports label-based
 * access control: paths have labels, users have labels,
 * access = intersection check. Root bypasses all.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "core_path.h"

void portal_path_init(portal_path_tree_t *tree)
{
    memset(tree, 0, sizeof(*tree));
    portal_ht_init(&tree->table, HT_INITIAL_CAPACITY);
}

static void free_entry_cb(const char *key, void *value, void *userdata)
{
    (void)key;
    (void)userdata;
    free(value);
}

void portal_path_destroy(portal_path_tree_t *tree)
{
    portal_ht_iter(&tree->table, free_entry_cb, NULL);
    portal_ht_destroy(&tree->table);
    tree->count = 0;
}

int portal_path_register(portal_path_tree_t *tree, const char *path,
                          const char *module_name)
{
    /* Check if already registered */
    if (portal_ht_get(&tree->table, path))
        return -1;

    path_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry) return -1;

    snprintf(entry->path, sizeof(entry->path), "%s", path);
    snprintf(entry->module_name, sizeof(entry->module_name), "%s", module_name);
    entry->access_mode = PORTAL_ACCESS_RW;  /* default: read/write */

    if (portal_ht_set(&tree->table, path, entry) < 0) {
        free(entry);
        return -1;
    }

    tree->count++;
    return 0;
}

int portal_path_unregister(portal_path_tree_t *tree, const char *path)
{
    path_entry_t *entry = portal_ht_get(&tree->table, path);
    if (!entry) return -1;

    free(entry);
    portal_ht_del(&tree->table, path);
    tree->count--;
    return 0;
}

const char *portal_path_lookup(portal_path_tree_t *tree, const char *path)
{
    path_entry_t *entry = portal_ht_get(&tree->table, path);
    if (!entry) return NULL;
    return entry->module_name;
}

path_entry_t *portal_path_lookup_entry(portal_path_tree_t *tree, const char *path)
{
    return portal_ht_get(&tree->table, path);
}

/* --- Label-based access control --- */

int portal_path_set_labels(portal_path_tree_t *tree, const char *path,
                            const portal_labels_t *labels)
{
    path_entry_t *entry = portal_ht_get(&tree->table, path);
    if (!entry) return -1;

    if (labels)
        memcpy(&entry->labels, labels, sizeof(portal_labels_t));
    else
        portal_labels_clear(&entry->labels);
    return 0;
}

int portal_path_add_label(portal_path_tree_t *tree, const char *path,
                           const char *label)
{
    path_entry_t *entry = portal_ht_get(&tree->table, path);
    if (!entry) return -1;
    return portal_labels_add(&entry->labels, label);
}

int portal_path_remove_label(portal_path_tree_t *tree, const char *path,
                              const char *label)
{
    path_entry_t *entry = portal_ht_get(&tree->table, path);
    if (!entry) return -1;
    return portal_labels_remove(&entry->labels, label);
}

const portal_labels_t *portal_path_get_labels(portal_path_tree_t *tree,
                                               const char *path)
{
    path_entry_t *entry = portal_ht_get(&tree->table, path);
    if (!entry) return NULL;
    return &entry->labels;
}

int portal_path_check_access(portal_path_tree_t *tree, const char *path,
                              const portal_ctx_t *ctx)
{
    path_entry_t *entry = portal_ht_get(&tree->table, path);
    if (!entry)
        return 0;  /* path not found = no access */

    /* Root always has access */
    if (ctx && ctx->auth.user && strcmp(ctx->auth.user, PORTAL_ROOT_USER) == 0)
        return 1;

    /* No labels on path = open access */
    if (entry->labels.count == 0)
        return 1;

    /* No context or no user = deny */
    if (!ctx || !ctx->auth.user)
        return 0;

    /* Check label intersection */
    return portal_labels_intersects(&entry->labels, &ctx->auth.labels);
}

/* --- Listing --- */

typedef struct {
    portal_path_list_fn callback;
    void *userdata;
} list_ctx_t;

static void list_iter_cb(const char *key, void *value, void *userdata)
{
    list_ctx_t *ctx = userdata;
    path_entry_t *entry = value;
    ctx->callback(key, entry->module_name, ctx->userdata);
}

void portal_path_list(portal_path_tree_t *tree, portal_path_list_fn callback,
                       void *userdata)
{
    list_ctx_t ctx = { .callback = callback, .userdata = userdata };
    portal_ht_iter(&tree->table, list_iter_cb, &ctx);
}
