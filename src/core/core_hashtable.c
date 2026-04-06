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
 * core_hashtable.c — FNV-1a open-addressing hash table
 *
 * O(1) amortized lookup. Auto-resizes at 75% load factor.
 * Used internally for path registry, config storage, etc.
 */

#include <stdlib.h>
#include <string.h>
#include "core_hashtable.h"

/* FNV-1a hash — fast, good distribution for strings */
static size_t fnv1a(const char *key)
{
    size_t hash = 0xcbf29ce484222325ULL;
    while (*key) {
        hash ^= (unsigned char)*key++;
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

void portal_ht_init(portal_ht_t *ht, size_t initial_capacity)
{
    if (initial_capacity < HT_INITIAL_CAPACITY)
        initial_capacity = HT_INITIAL_CAPACITY;

    ht->capacity = initial_capacity;
    ht->count = 0;
    ht->entries = calloc(initial_capacity, sizeof(ht_entry_t));
}

void portal_ht_destroy(portal_ht_t *ht)
{
    if (!ht->entries) return;

    for (size_t i = 0; i < ht->capacity; i++) {
        if (ht->entries[i].occupied == 1)
            free(ht->entries[i].key);
    }
    free(ht->entries);
    ht->entries = NULL;
    ht->capacity = 0;
    ht->count = 0;
}

static int ht_resize(portal_ht_t *ht, size_t new_capacity)
{
    ht_entry_t *old_entries = ht->entries;
    size_t old_capacity = ht->capacity;

    ht->entries = calloc(new_capacity, sizeof(ht_entry_t));
    if (!ht->entries) {
        ht->entries = old_entries;
        return -1;
    }

    ht->capacity = new_capacity;
    ht->count = 0;

    for (size_t i = 0; i < old_capacity; i++) {
        if (old_entries[i].occupied == 1) {
            portal_ht_set(ht, old_entries[i].key, old_entries[i].value);
            free(old_entries[i].key);
        }
    }

    free(old_entries);
    return 0;
}

int portal_ht_set(portal_ht_t *ht, const char *key, void *value)
{
    /* Resize if load factor exceeded */
    if ((double)(ht->count + 1) / ht->capacity > HT_LOAD_FACTOR) {
        if (ht_resize(ht, ht->capacity * 2) < 0)
            return -1;
    }

    size_t idx = fnv1a(key) % ht->capacity;

    for (size_t i = 0; i < ht->capacity; i++) {
        size_t slot = (idx + i) % ht->capacity;
        ht_entry_t *entry = &ht->entries[slot];

        if (entry->occupied == 0 || entry->occupied == 2) {
            /* Empty or tombstone — insert here */
            entry->key = strdup(key);
            entry->value = value;
            entry->occupied = 1;
            ht->count++;
            return 0;
        }

        if (entry->occupied == 1 && strcmp(entry->key, key) == 0) {
            /* Key exists — update value */
            entry->value = value;
            return 0;
        }
    }

    return -1;  /* table full (shouldn't happen with resize) */
}

void *portal_ht_get(portal_ht_t *ht, const char *key)
{
    size_t idx = fnv1a(key) % ht->capacity;

    for (size_t i = 0; i < ht->capacity; i++) {
        size_t slot = (idx + i) % ht->capacity;
        ht_entry_t *entry = &ht->entries[slot];

        if (entry->occupied == 0)
            return NULL;  /* empty slot = not found */

        if (entry->occupied == 1 && strcmp(entry->key, key) == 0)
            return entry->value;

        /* occupied == 2 (tombstone) — keep probing */
    }

    return NULL;
}

int portal_ht_del(portal_ht_t *ht, const char *key)
{
    size_t idx = fnv1a(key) % ht->capacity;

    for (size_t i = 0; i < ht->capacity; i++) {
        size_t slot = (idx + i) % ht->capacity;
        ht_entry_t *entry = &ht->entries[slot];

        if (entry->occupied == 0)
            return -1;  /* not found */

        if (entry->occupied == 1 && strcmp(entry->key, key) == 0) {
            free(entry->key);
            entry->key = NULL;
            entry->value = NULL;
            entry->occupied = 2;  /* tombstone */
            ht->count--;
            return 0;
        }
    }

    return -1;
}

void portal_ht_iter(portal_ht_t *ht, portal_ht_iter_fn cb, void *userdata)
{
    for (size_t i = 0; i < ht->capacity; i++) {
        if (ht->entries[i].occupied == 1)
            cb(ht->entries[i].key, ht->entries[i].value, userdata);
    }
}

size_t portal_ht_count(portal_ht_t *ht)
{
    return ht->count;
}
