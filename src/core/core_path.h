/*
 * core_path.h — Path registry with hash table lookup and label-based ACL
 */

#ifndef CORE_PATH_H
#define CORE_PATH_H

#include "portal/types.h"
#include "core_hashtable.h"

/* A registered path entry */
typedef struct {
    char             path[PORTAL_MAX_PATH_LEN];
    char             module_name[PORTAL_MAX_MODULE_NAME];
    portal_labels_t  labels;
    uint8_t          access_mode;   /* PORTAL_ACCESS_READ/WRITE/RW (Law 8) */
    char             description[256]; /* Human-readable description for help system */
} path_entry_t;

/* Path registry — hash table for O(1) lookups */
typedef struct {
    portal_ht_t  table;     /* key: path string, value: path_entry_t* */
    int          count;
} portal_path_tree_t;

void portal_path_init(portal_path_tree_t *tree);
void portal_path_destroy(portal_path_tree_t *tree);

/* Register a path → module mapping. Returns 0 on success. */
int  portal_path_register(portal_path_tree_t *tree, const char *path,
                           const char *module_name);

/* Unregister a path. Returns 0 on success. */
int  portal_path_unregister(portal_path_tree_t *tree, const char *path);

/* Lookup which module handles a path. Returns module name or NULL. */
const char *portal_path_lookup(portal_path_tree_t *tree, const char *path);

/* Lookup the full path entry. Returns NULL if not found. */
path_entry_t *portal_path_lookup_entry(portal_path_tree_t *tree, const char *path);

/* Set labels on a path. Returns 0 on success. */
int  portal_path_set_labels(portal_path_tree_t *tree, const char *path,
                             const portal_labels_t *labels);

/* Add a single label to a path. Returns 0 on success. */
int  portal_path_add_label(portal_path_tree_t *tree, const char *path,
                            const char *label);

/* Remove a label from a path. Returns 0 on success. */
int  portal_path_remove_label(portal_path_tree_t *tree, const char *path,
                               const char *label);

/* Set description on a path. Returns 0 on success. */
int  portal_path_set_description(portal_path_tree_t *tree, const char *path,
                                  const char *description);

/* Get labels for a path. Returns pointer to labels or NULL. */
const portal_labels_t *portal_path_get_labels(portal_path_tree_t *tree,
                                               const char *path);

/*
 * Check if a user context has access to a path.
 * Rules:
 *   - root user → always allowed
 *   - path has no labels → open (anyone can access)
 *   - path has labels → user must have at least one matching label
 * Returns 1 if allowed, 0 if denied.
 */
int  portal_path_check_access(portal_path_tree_t *tree, const char *path,
                               const portal_ctx_t *ctx);

/* List all registered paths. Calls callback for each. */
typedef void (*portal_path_list_fn)(const char *path, const char *module_name,
                                     void *userdata);
void portal_path_list(portal_path_tree_t *tree, portal_path_list_fn callback,
                       void *userdata);

#endif /* CORE_PATH_H */
