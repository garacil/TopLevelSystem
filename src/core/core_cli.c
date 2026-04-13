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
 * core_cli.c — CLI command registration and dispatch
 *
 * Modules register commands with handler + optional tab completion
 * generator. Word-based pattern matching supports exact words and
 * '%' wildcards. Commands auto-unregister when their owning module
 * unloads.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "portal/portal.h"
#include "portal/cli.h"

/* ── Internal state — stored in core._internal via accessor ── */

/* Head of the registered command linked list.
 * Stored as a void* in portal_instance's internal struct.
 * Accessed via portal_cli_head() / portal_cli_set_head(). */

/* We use a simple approach: the linked list head is stored in a
 * well-known slot. Since core._internal is the portal_instance_t,
 * and we can't change that struct from here, we use a static head.
 * This is safe because there is only one core instance per process. */

static portal_cli_entry_t *g_cli_head = NULL;
static int g_cli_count = 0;

/* ── Word matching ── */

/* Split a string into words. Returns word count.
 * words[] pointers are into the original buffer (modified in place). */
static int split_words(char *buf, char **words, int max_words)
{
    int count = 0;
    char *p = buf;
    while (*p && count < max_words) {
        while (*p == ' ') p++;
        if (!*p) break;
        words[count++] = p;
        while (*p && *p != ' ') p++;
        if (*p) *p++ = '\0';
    }
    return count;
}

/* Match a command line against a word pattern.
 * Pattern words: exact string or "%" (any single word).
 * Returns the number of pattern words matched, or 0 if no match.
 * On match, *args_out points to the rest of the line after matched words. */
static int words_match(const char *pattern, const char *line,
                        const char **args_out)
{
    char pbuf[512], lbuf[512];
    snprintf(pbuf, sizeof(pbuf), "%s", pattern);
    snprintf(lbuf, sizeof(lbuf), "%s", line);

    char *pwords[32], *lwords[32];
    int pcount = split_words(pbuf, pwords, 32);
    int lcount = split_words(lbuf, lwords, 32);

    if (pcount == 0) return 0;
    if (lcount < pcount) return 0;

    for (int i = 0; i < pcount; i++) {
        if (strcmp(pwords[i], "%") == 0)
            continue;  /* wildcard matches any word */
        if (strcasecmp(pwords[i], lwords[i]) != 0)
            return 0;  /* mismatch */
    }

    /* Find where args start in the original line */
    if (args_out) {
        const char *p = line;
        for (int i = 0; i < pcount; i++) {
            while (*p == ' ') p++;
            while (*p && *p != ' ') p++;
        }
        while (*p == ' ') p++;
        *args_out = p;
    }

    return pcount;
}

/* ── Public API ── */

int portal_cli_register(portal_core_t *core, portal_cli_entry_t *entry,
                         const char *module_name)
{
    (void)core;
    if (!entry || !entry->words || !entry->handler) return -1;

    entry->module = module_name;
    entry->next = g_cli_head;
    g_cli_head = entry;
    g_cli_count++;
    return 0;
}

int portal_cli_unregister(portal_core_t *core, portal_cli_entry_t *entry)
{
    (void)core;
    portal_cli_entry_t **pp = &g_cli_head;
    while (*pp) {
        if (*pp == entry) {
            *pp = entry->next;
            entry->next = NULL;
            g_cli_count--;
            return 0;
        }
        pp = &(*pp)->next;
    }
    return -1;
}

int portal_cli_unregister_module(portal_core_t *core,
                                  const char *module_name)
{
    (void)core;
    int removed = 0;
    portal_cli_entry_t **pp = &g_cli_head;
    while (*pp) {
        if ((*pp)->module && strcmp((*pp)->module, module_name) == 0) {
            portal_cli_entry_t *del = *pp;
            *pp = del->next;
            del->next = NULL;
            g_cli_count--;
            removed++;
        } else {
            pp = &(*pp)->next;
        }
    }
    return removed;
}

portal_cli_entry_t *portal_cli_find(portal_core_t *core,
                                     const char *line, const char **args)
{
    (void)core;
    portal_cli_entry_t *best = NULL;
    int best_score = 0;

    for (portal_cli_entry_t *e = g_cli_head; e; e = e->next) {
        const char *a = NULL;
        int score = words_match(e->words, line, &a);
        if (score > best_score) {
            best_score = score;
            best = e;
            if (args) *args = a;
        }
    }
    return best;
}

void portal_cli_iter(portal_core_t *core, portal_cli_iter_fn cb,
                     void *userdata)
{
    (void)core;
    for (portal_cli_entry_t *e = g_cli_head; e; e = e->next)
        cb(e, userdata);
}

int portal_cli_count(portal_core_t *core)
{
    (void)core;
    return g_cli_count;
}
