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
 * mod_myapp — Example application module for Portal
 *
 * Demonstrates all key module features:
 * - Resources (GET): data endpoints
 * - Functions (CALL): actions
 * - Events: emit notifications
 * - Soft dependencies: check if other modules are loaded
 * - Config: read module-specific settings
 * - Labels: restrict paths by group
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "portal/portal.h"

static portal_core_t *g_core = NULL;
static int g_counter = 0;
static char g_message[256] = "Hello from MyApp!";

static portal_module_info_t info = {
    .name        = "myapp",
    .version     = "1.0.0",
    .description = "Example application module",
    .soft_deps   = NULL
};

portal_module_info_t *portal_module_info(void) { return &info; }

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_counter = 0;

    /* Read config: [mod_myapp] message = ... */
    const char *msg = core->config_get(core, "myapp", "message");
    if (msg) snprintf(g_message, sizeof(g_message), "%s", msg);

    /* Public resources — anyone can read */
    core->path_register(core, "/myapp/resources/status", "myapp");
    core->path_set_access(core, "/myapp/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/myapp/resources/status", "Example app: version, message, counter, deps");
    core->path_register(core, "/myapp/resources/counter", "myapp");
    core->path_set_access(core, "/myapp/resources/counter", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/myapp/resources/counter", "Current counter value");
    core->path_register(core, "/myapp/resources/message", "myapp");
    core->path_set_access(core, "/myapp/resources/message", PORTAL_ACCESS_READ);

    /* Admin-only function — requires "admin" group */
    core->path_register(core, "/myapp/functions/reset", "myapp");
    core->path_set_access(core, "/myapp/functions/reset", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/myapp/functions/reset", "Reset counter to zero");
    core->path_add_label(core, "/myapp/functions/reset", "admin");

    /* Public function */
    core->path_register(core, "/myapp/functions/increment", "myapp");
    core->path_set_access(core, "/myapp/functions/increment", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/myapp/functions/increment", "Increment counter and return new value");

    /* Register an event that we will emit */
    core->event_register(core, "/events/myapp/counter_changed",
                          "Counter value changed", NULL);

    core->log(core, PORTAL_LOG_INFO, "myapp",
              "MyApp loaded (message: %s)", g_message);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->event_unregister(core, "/events/myapp/counter_changed");
    core->path_unregister(core, "/myapp/resources/status");
    core->path_unregister(core, "/myapp/resources/counter");
    core->path_unregister(core, "/myapp/resources/message");
    core->path_unregister(core, "/myapp/functions/reset");
    core->path_unregister(core, "/myapp/functions/increment");
    core->log(core, PORTAL_LOG_INFO, "myapp", "MyApp unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[512];
    int n;

    /* GET /myapp/resources/status */
    if (strcmp(msg->path, "/myapp/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "MyApp v%s\n"
            "Message: %s\n"
            "Counter: %d\n"
            "Node module: %s\n",
            info.version, g_message, g_counter,
            core->module_loaded(core, "node") ? "available" : "not loaded");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* GET /myapp/resources/counter */
    if (strcmp(msg->path, "/myapp/resources/counter") == 0) {
        n = snprintf(buf, sizeof(buf), "%d\n", g_counter);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* GET /myapp/resources/message */
    if (strcmp(msg->path, "/myapp/resources/message") == 0) {
        n = snprintf(buf, sizeof(buf), "%s\n", g_message);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* CALL /myapp/functions/increment — public */
    if (strcmp(msg->path, "/myapp/functions/increment") == 0) {
        g_counter++;
        n = snprintf(buf, sizeof(buf), "Counter: %d\n", g_counter);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);

        /* Emit event */
        char event_data[64];
        snprintf(event_data, sizeof(event_data), "%d", g_counter);
        core->event_emit(core, "/events/myapp/counter_changed",
                          event_data, strlen(event_data));
        return 0;
    }

    /* CALL /myapp/functions/reset — admin only (label enforced by core) */
    if (strcmp(msg->path, "/myapp/functions/reset") == 0) {
        g_counter = 0;
        portal_resp_set_status(resp, PORTAL_OK);
        const char *ok = "Counter reset to 0\n";
        portal_resp_set_body(resp, ok, strlen(ok));

        core->event_emit(core, "/events/myapp/counter_changed", "0", 1);
        return 0;
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
