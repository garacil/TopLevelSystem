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
 * cli.h — CLI command registration API
 *
 * Modules register CLI commands with handler + optional tab completion
 * generator. Commands are discovered at runtime; mod_cli dispatches
 * to registered handlers instead of hardcoding every command.
 *
 * Word patterns:
 *   "status"           — exact match
 *   "module load %"    — % matches any single word
 *   "cache set % %"    — multiple wildcards
 */

#ifndef PORTAL_CLI_H
#define PORTAL_CLI_H

#include <stddef.h>

/* Forward declarations */
typedef struct portal_core portal_core_t;
typedef struct portal_cli_entry portal_cli_entry_t;

/* CLI command handler — called when the command matches.
 * fd:   client socket fd for direct writes
 * line: full input line
 * args: pointer to first argument after matched words (may be empty) */
typedef int (*portal_cli_handler_fn)(portal_core_t *core, int fd,
                                      const char *line, const char *args);

/* CLI tab completion generator — returns the nth match for a word.
 * word:     the partial word being completed
 * line:     full input line so far
 * position: which word (0-based) is being completed
 * state:    0 = first call, increments for each subsequent match
 * Returns:  static string of the match, or NULL when no more matches.
 *           Caller must NOT free the returned pointer. */
typedef const char *(*portal_cli_generator_fn)(portal_core_t *core,
                                                const char *word,
                                                const char *line,
                                                int position, int state);

/* CLI command entry — modules fill these and register with the core */
struct portal_cli_entry {
    const char              *words;      /* word pattern: "cache get %" */
    const char              *summary;    /* one-line description */
    const char              *usage;      /* multi-line help (optional) */
    const char              *module;     /* owning module (set by core) */
    portal_cli_handler_fn    handler;    /* command handler */
    portal_cli_generator_fn  generator;  /* tab completion (optional) */

    /* Internal — set by core, do not touch */
    portal_cli_entry_t      *next;
};

/* Iteration callback for walking registered commands */
typedef void (*portal_cli_iter_fn)(const portal_cli_entry_t *entry,
                                    void *userdata);

/* ── Core CLI functions (implemented in core_cli.c) ── */

/* Register a CLI command entry. Module name is auto-set by the core.
 * Returns 0 on success, -1 on error. */
int portal_cli_register(portal_core_t *core, portal_cli_entry_t *entry,
                         const char *module_name);

/* Unregister a CLI command entry. Returns 0 on success. */
int portal_cli_unregister(portal_core_t *core, portal_cli_entry_t *entry);

/* Unregister ALL commands owned by a module (called on module unload). */
int portal_cli_unregister_module(portal_core_t *core,
                                  const char *module_name);

/* Find the best-matching entry for a command line.
 * Sets *args to point past the matched words (into the line buffer).
 * Returns NULL if no match. */
portal_cli_entry_t *portal_cli_find(portal_core_t *core,
                                     const char *line, const char **args);

/* Iterate all registered commands (for help, tab completion). */
void portal_cli_iter(portal_core_t *core, portal_cli_iter_fn cb,
                     void *userdata);

/* Count registered commands. */
int portal_cli_count(portal_core_t *core);

#endif /* PORTAL_CLI_H */
