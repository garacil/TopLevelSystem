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
 * test_hashtable — Unit tests for Portal hash table
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../src/core/core_hashtable.h"

static void test_basic_set_get(void)
{
    printf("test_basic_set_get... ");
    portal_ht_t ht;
    portal_ht_init(&ht, 16);

    int val1 = 42, val2 = 99;
    assert(portal_ht_set(&ht, "hello", &val1) == 0);
    assert(portal_ht_set(&ht, "world", &val2) == 0);

    assert(portal_ht_get(&ht, "hello") == &val1);
    assert(portal_ht_get(&ht, "world") == &val2);
    assert(portal_ht_get(&ht, "missing") == NULL);

    portal_ht_destroy(&ht);
    printf("OK\n");
}

static void test_overwrite(void)
{
    printf("test_overwrite... ");
    portal_ht_t ht;
    portal_ht_init(&ht, 16);

    int val1 = 1, val2 = 2;
    portal_ht_set(&ht, "key", &val1);
    assert(portal_ht_get(&ht, "key") == &val1);

    portal_ht_set(&ht, "key", &val2);
    assert(portal_ht_get(&ht, "key") == &val2);
    assert(portal_ht_count(&ht) == 1);

    portal_ht_destroy(&ht);
    printf("OK\n");
}

static void test_delete(void)
{
    printf("test_delete... ");
    portal_ht_t ht;
    portal_ht_init(&ht, 16);

    int val = 42;
    portal_ht_set(&ht, "key", &val);
    assert(portal_ht_count(&ht) == 1);

    assert(portal_ht_del(&ht, "key") == 0);
    assert(portal_ht_get(&ht, "key") == NULL);
    assert(portal_ht_count(&ht) == 0);

    /* Delete nonexistent */
    assert(portal_ht_del(&ht, "nope") == -1);

    portal_ht_destroy(&ht);
    printf("OK\n");
}

static void test_delete_then_insert(void)
{
    printf("test_delete_then_insert... ");
    portal_ht_t ht;
    portal_ht_init(&ht, 16);

    int v1 = 1, v2 = 2, v3 = 3;
    portal_ht_set(&ht, "a", &v1);
    portal_ht_set(&ht, "b", &v2);
    portal_ht_del(&ht, "a");

    /* Insert into tombstone slot */
    portal_ht_set(&ht, "c", &v3);
    assert(portal_ht_get(&ht, "a") == NULL);
    assert(portal_ht_get(&ht, "b") == &v2);
    assert(portal_ht_get(&ht, "c") == &v3);

    portal_ht_destroy(&ht);
    printf("OK\n");
}

static void test_resize(void)
{
    printf("test_resize... ");
    portal_ht_t ht;
    portal_ht_init(&ht, 8);  /* small to force resize */

    char keys[100][16];
    int vals[100];

    for (int i = 0; i < 100; i++) {
        snprintf(keys[i], sizeof(keys[i]), "key_%d", i);
        vals[i] = i * 10;
        assert(portal_ht_set(&ht, keys[i], &vals[i]) == 0);
    }

    assert(portal_ht_count(&ht) == 100);

    /* Verify all still accessible */
    for (int i = 0; i < 100; i++) {
        int *v = portal_ht_get(&ht, keys[i]);
        assert(v != NULL);
        assert(*v == i * 10);
    }

    portal_ht_destroy(&ht);
    printf("OK\n");
}

static int g_iter_count;
static void count_cb(const char *key, void *value, void *userdata)
{
    (void)key; (void)value; (void)userdata;
    g_iter_count++;
}

static void test_iterate(void)
{
    printf("test_iterate... ");
    portal_ht_t ht;
    portal_ht_init(&ht, 16);

    int v1 = 1, v2 = 2, v3 = 3;
    portal_ht_set(&ht, "a", &v1);
    portal_ht_set(&ht, "b", &v2);
    portal_ht_set(&ht, "c", &v3);

    g_iter_count = 0;
    portal_ht_iter(&ht, count_cb, NULL);
    assert(g_iter_count == 3);

    portal_ht_destroy(&ht);
    printf("OK\n");
}

static void test_path_like_keys(void)
{
    printf("test_path_like_keys... ");
    portal_ht_t ht;
    portal_ht_init(&ht, 16);

    int v1 = 1, v2 = 2, v3 = 3, v4 = 4;
    portal_ht_set(&ht, "/cli/command", &v1);
    portal_ht_set(&ht, "/db/mysql/query", &v2);
    portal_ht_set(&ht, "/web/api/v1/users", &v3);
    portal_ht_set(&ht, "/serial/com1/read", &v4);

    assert(*(int *)portal_ht_get(&ht, "/cli/command") == 1);
    assert(*(int *)portal_ht_get(&ht, "/db/mysql/query") == 2);
    assert(*(int *)portal_ht_get(&ht, "/web/api/v1/users") == 3);
    assert(*(int *)portal_ht_get(&ht, "/serial/com1/read") == 4);
    assert(portal_ht_get(&ht, "/nonexistent") == NULL);

    portal_ht_destroy(&ht);
    printf("OK\n");
}

int main(void)
{
    printf("=== Portal Hash Table Tests ===\n\n");

    test_basic_set_get();
    test_overwrite();
    test_delete();
    test_delete_then_insert();
    test_resize();
    test_iterate();
    test_path_like_keys();

    printf("\nAll tests passed.\n");
    return 0;
}
