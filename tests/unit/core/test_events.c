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
 * test_events.c — Unit tests for Portal event system (register, subscribe, ACL, emit)
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "portal/portal.h"
#include "../src/core/core_events.h"

static int g_emit_count;
static char g_emit_path[256];

static void test_handler(const portal_msg_t *msg, void *userdata)
{
    (void)userdata;
    g_emit_count++;
    snprintf(g_emit_path, sizeof(g_emit_path), "%s", msg->path);
}

static void test_register(void)
{
    printf("test_register... ");
    portal_event_registry_t reg;
    portal_events_init(&reg);

    portal_labels_t labels = {0};
    portal_labels_add(&labels, "dev");

    assert(portal_events_register(&reg, "/events/db/done", "db",
                                   "Query completed", &labels) == 0);
    assert(portal_events_count(&reg) == 1);

    portal_event_def_t *def = portal_events_find(&reg, "/events/db/done");
    assert(def != NULL);
    assert(strcmp(def->module, "db") == 0);
    assert(portal_labels_has(&def->labels, "dev"));

    /* Duplicate */
    assert(portal_events_register(&reg, "/events/db/done", "db", "", NULL) == -1);

    portal_events_destroy(&reg);
    printf("OK\n");
}

static void test_subscribe_acl_allow(void)
{
    printf("test_subscribe_acl_allow... ");
    portal_event_registry_t reg;
    portal_events_init(&reg);

    portal_labels_t ev_labels = {0};
    portal_labels_add(&ev_labels, "dev");
    portal_events_register(&reg, "/events/test/x", "test", "desc", &ev_labels);

    /* User with "dev" label = allowed */
    portal_labels_t user_labels = {0};
    portal_labels_add(&user_labels, "dev");
    assert(portal_events_subscribe(&reg, "/events/test/x", "alice",
                                    &user_labels, test_handler, NULL) == 0);
    assert(portal_events_sub_count(&reg) == 1);

    portal_events_destroy(&reg);
    printf("OK\n");
}

static void test_subscribe_acl_deny(void)
{
    printf("test_subscribe_acl_deny... ");
    portal_event_registry_t reg;
    portal_events_init(&reg);

    portal_labels_t ev_labels = {0};
    portal_labels_add(&ev_labels, "admin");
    portal_events_register(&reg, "/events/secret/x", "vault", "desc", &ev_labels);

    /* User with "viewer" label = denied */
    portal_labels_t user_labels = {0};
    portal_labels_add(&user_labels, "viewer");
    assert(portal_events_subscribe(&reg, "/events/secret/x", "bob",
                                    &user_labels, test_handler, NULL) == -1);
    assert(portal_events_sub_count(&reg) == 0);

    portal_events_destroy(&reg);
    printf("OK\n");
}

static void test_subscribe_public(void)
{
    printf("test_subscribe_public... ");
    portal_event_registry_t reg;
    portal_events_init(&reg);

    /* No labels = public */
    portal_events_register(&reg, "/events/pub/x", "pub", "public event", NULL);

    portal_labels_t empty = {0};
    assert(portal_events_subscribe(&reg, "/events/pub/x", "anyone",
                                    &empty, test_handler, NULL) == 0);

    portal_events_destroy(&reg);
    printf("OK\n");
}

static void test_emit(void)
{
    printf("test_emit... ");
    portal_event_registry_t reg;
    portal_events_init(&reg);

    portal_events_register(&reg, "/events/test/ping", "test", "", NULL);

    portal_labels_t labels = {0};
    portal_events_subscribe(&reg, "/events/test/ping", "sub1",
                             &labels, test_handler, NULL);

    g_emit_count = 0;
    portal_events_emit(&reg, "/events/test/ping", "hello", 5);
    assert(g_emit_count == 1);
    assert(strcmp(g_emit_path, "/events/test/ping") == 0);

    portal_events_destroy(&reg);
    printf("OK\n");
}

static void test_unsubscribe(void)
{
    printf("test_unsubscribe... ");
    portal_event_registry_t reg;
    portal_events_init(&reg);

    portal_events_register(&reg, "/events/test/y", "test", "", NULL);

    portal_labels_t labels = {0};
    portal_events_subscribe(&reg, "/events/test/y", "sub1",
                             &labels, test_handler, NULL);
    assert(portal_events_sub_count(&reg) == 1);

    portal_events_unsubscribe(&reg, "/events/test/y", "sub1");
    assert(portal_events_sub_count(&reg) == 0);

    g_emit_count = 0;
    portal_events_emit(&reg, "/events/test/y", NULL, 0);
    assert(g_emit_count == 0);

    portal_events_destroy(&reg);
    printf("OK\n");
}

static void test_unregister_module(void)
{
    printf("test_unregister_module... ");
    portal_event_registry_t reg;
    portal_events_init(&reg);

    portal_events_register(&reg, "/events/db/a", "db", "", NULL);
    portal_events_register(&reg, "/events/db/b", "db", "", NULL);
    portal_events_register(&reg, "/events/web/c", "web", "", NULL);
    assert(portal_events_count(&reg) == 3);

    portal_events_unregister_module(&reg, "db");
    assert(portal_events_count(&reg) == 1);

    portal_events_destroy(&reg);
    printf("OK\n");
}

int main(void)
{
    printf("=== Portal Event System Tests ===\n\n");
    test_register();
    test_subscribe_acl_allow();
    test_subscribe_acl_deny();
    test_subscribe_public();
    test_emit();
    test_unsubscribe();
    test_unregister_module();
    printf("\nAll tests passed.\n");
    return 0;
}
