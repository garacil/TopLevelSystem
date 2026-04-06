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
 * test_path — Unit tests for Portal path trie
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "portal/constants.h"
#include "../src/core/core_path.h"

static int g_list_count;

static void count_cb(const char *path, const char *module_name, void *userdata)
{
    (void)userdata;
    printf("  %-30s → %s\n", path, module_name);
    g_list_count++;
}

static void test_register_and_lookup(void)
{
    printf("test_register_and_lookup... ");
    portal_path_tree_t tree;
    portal_path_init(&tree);

    assert(portal_path_register(&tree, "/cli/command", "cli") == 0);
    assert(portal_path_register(&tree, "/db/mysql/query", "db_mysql") == 0);
    assert(portal_path_register(&tree, "/web/api/v1/users", "web") == 0);

    assert(strcmp(portal_path_lookup(&tree, "/cli/command"), "cli") == 0);
    assert(strcmp(portal_path_lookup(&tree, "/db/mysql/query"), "db_mysql") == 0);
    assert(strcmp(portal_path_lookup(&tree, "/web/api/v1/users"), "web") == 0);

    assert(portal_path_lookup(&tree, "/nonexistent") == NULL);
    assert(portal_path_lookup(&tree, "/cli") == NULL);  /* intermediate node, no handler */

    portal_path_destroy(&tree);
    printf("OK\n");
}

static void test_unregister(void)
{
    printf("test_unregister... ");
    portal_path_tree_t tree;
    portal_path_init(&tree);

    portal_path_register(&tree, "/a/b", "mod_a");
    assert(portal_path_lookup(&tree, "/a/b") != NULL);

    assert(portal_path_unregister(&tree, "/a/b") == 0);
    assert(portal_path_lookup(&tree, "/a/b") == NULL);

    /* Unregister nonexistent */
    assert(portal_path_unregister(&tree, "/a/b") == -1);

    portal_path_destroy(&tree);
    printf("OK\n");
}

static void test_duplicate_register(void)
{
    printf("test_duplicate_register... ");
    portal_path_tree_t tree;
    portal_path_init(&tree);

    assert(portal_path_register(&tree, "/a/b", "mod_a") == 0);
    assert(portal_path_register(&tree, "/a/b", "mod_b") == -1);  /* already taken */

    portal_path_destroy(&tree);
    printf("OK\n");
}

static void test_list(void)
{
    printf("test_list...\n");
    portal_path_tree_t tree;
    portal_path_init(&tree);

    portal_path_register(&tree, "/cli/command", "cli");
    portal_path_register(&tree, "/db/query", "db");
    portal_path_register(&tree, "/web/api", "web");

    g_list_count = 0;
    portal_path_list(&tree, count_cb, NULL);
    assert(g_list_count == 3);

    portal_path_destroy(&tree);
    printf("  OK (%d paths listed)\n", g_list_count);
}

static void test_deep_path(void)
{
    printf("test_deep_path... ");
    portal_path_tree_t tree;
    portal_path_init(&tree);

    assert(portal_path_register(&tree, "/a/b/c/d/e/f", "deep") == 0);
    assert(strcmp(portal_path_lookup(&tree, "/a/b/c/d/e/f"), "deep") == 0);
    assert(portal_path_lookup(&tree, "/a/b/c") == NULL);

    portal_path_destroy(&tree);
    printf("OK\n");
}

int main(void)
{
    printf("=== Portal Path Trie Tests ===\n\n");

    test_register_and_lookup();
    test_unregister();
    test_duplicate_register();
    test_list();
    test_deep_path();

    printf("\nAll tests passed.\n");
    return 0;
}
