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
 * core_hashtable.h — FNV-1a open-addressing hash table with auto-resize
 */

#ifndef CORE_HASHTABLE_H
#define CORE_HASHTABLE_H

#include <stddef.h>

#define HT_INITIAL_CAPACITY 64
#define HT_LOAD_FACTOR      0.75

typedef struct {
    char   *key;
    void   *value;
    int     occupied;   /* 0=empty, 1=occupied, 2=tombstone */
} ht_entry_t;

typedef struct {
    ht_entry_t *entries;
    size_t      capacity;
    size_t      count;
} portal_ht_t;

void   portal_ht_init(portal_ht_t *ht, size_t initial_capacity);
void   portal_ht_destroy(portal_ht_t *ht);

/* Set a key-value pair. Overwrites if key exists. Returns 0 on success. */
int    portal_ht_set(portal_ht_t *ht, const char *key, void *value);

/* Get value by key. Returns NULL if not found. */
void  *portal_ht_get(portal_ht_t *ht, const char *key);

/* Delete a key. Returns 0 on success, -1 if not found. */
int    portal_ht_del(portal_ht_t *ht, const char *key);

/* Iterate all entries. Calls cb(key, value, userdata) for each. */
typedef void (*portal_ht_iter_fn)(const char *key, void *value, void *userdata);
void   portal_ht_iter(portal_ht_t *ht, portal_ht_iter_fn cb, void *userdata);

/* Number of entries */
size_t portal_ht_count(portal_ht_t *ht);

#endif /* CORE_HASHTABLE_H */
