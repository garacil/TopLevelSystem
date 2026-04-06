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
 * test_pubsub.c — Unit tests for pub/sub pattern matching (exact, wildcard, global)
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "portal/portal.h"
#include "../src/core/core_pubsub.h"

static int g_event_count;
static char g_last_path[256];

static void test_handler(const portal_msg_t *msg, void *userdata)
{
    (void)userdata;
    g_event_count++;
    snprintf(g_last_path, sizeof(g_last_path), "%s", msg->path);
}

static void test_subscribe_exact(void)
{
    printf("test_subscribe_exact... ");
    portal_pubsub_t ps;
    portal_pubsub_init(&ps);

    portal_pubsub_subscribe(&ps, "/events/login", test_handler, NULL);
    assert(portal_pubsub_count(&ps) == 1);

    portal_msg_t msg = {0};
    msg.path = "/events/login";
    g_event_count = 0;
    portal_pubsub_publish(&ps, &msg);
    assert(g_event_count == 1);

    /* Non-matching path */
    msg.path = "/events/logout";
    g_event_count = 0;
    portal_pubsub_publish(&ps, &msg);
    assert(g_event_count == 0);

    portal_pubsub_destroy(&ps);
    printf("OK\n");
}

static void test_subscribe_wildcard(void)
{
    printf("test_subscribe_wildcard... ");
    portal_pubsub_t ps;
    portal_pubsub_init(&ps);

    portal_pubsub_subscribe(&ps, "/events/*", test_handler, NULL);

    portal_msg_t msg = {0};

    msg.path = "/events/login";
    g_event_count = 0;
    portal_pubsub_publish(&ps, &msg);
    assert(g_event_count == 1);

    msg.path = "/events/logout";
    g_event_count = 0;
    portal_pubsub_publish(&ps, &msg);
    assert(g_event_count == 1);

    msg.path = "/other/stuff";
    g_event_count = 0;
    portal_pubsub_publish(&ps, &msg);
    assert(g_event_count == 0);

    portal_pubsub_destroy(&ps);
    printf("OK\n");
}

static void test_subscribe_global(void)
{
    printf("test_subscribe_global... ");
    portal_pubsub_t ps;
    portal_pubsub_init(&ps);

    portal_pubsub_subscribe(&ps, "*", test_handler, NULL);

    portal_msg_t msg = {0};
    msg.path = "/anything/at/all";
    g_event_count = 0;
    portal_pubsub_publish(&ps, &msg);
    assert(g_event_count == 1);

    portal_pubsub_destroy(&ps);
    printf("OK\n");
}

static void test_unsubscribe(void)
{
    printf("test_unsubscribe... ");
    portal_pubsub_t ps;
    portal_pubsub_init(&ps);

    portal_pubsub_subscribe(&ps, "/events/x", test_handler, NULL);
    assert(portal_pubsub_count(&ps) == 1);

    portal_pubsub_unsubscribe(&ps, "/events/x", test_handler);
    assert(portal_pubsub_count(&ps) == 0);

    portal_msg_t msg = {0};
    msg.path = "/events/x";
    g_event_count = 0;
    portal_pubsub_publish(&ps, &msg);
    assert(g_event_count == 0);

    portal_pubsub_destroy(&ps);
    printf("OK\n");
}

static int g_multi_count;
static void handler_a(const portal_msg_t *msg, void *ud) { (void)msg; (void)ud; g_multi_count++; }
static void handler_b(const portal_msg_t *msg, void *ud) { (void)msg; (void)ud; g_multi_count++; }

static void test_multiple_subscribers(void)
{
    printf("test_multiple_subscribers... ");
    portal_pubsub_t ps;
    portal_pubsub_init(&ps);

    portal_pubsub_subscribe(&ps, "/events/*", handler_a, NULL);
    portal_pubsub_subscribe(&ps, "/events/*", handler_b, NULL);

    portal_msg_t msg = {0};
    msg.path = "/events/test";
    g_multi_count = 0;
    portal_pubsub_publish(&ps, &msg);
    assert(g_multi_count == 2);

    portal_pubsub_destroy(&ps);
    printf("OK\n");
}

int main(void)
{
    printf("=== Portal Pub/Sub Tests ===\n\n");
    test_subscribe_exact();
    test_subscribe_wildcard();
    test_subscribe_global();
    test_unsubscribe();
    test_multiple_subscribers();
    printf("\nAll tests passed.\n");
    return 0;
}
