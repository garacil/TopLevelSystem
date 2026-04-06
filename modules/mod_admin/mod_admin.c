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
 * mod_admin — Web administration dashboard (SPA)
 *
 * Serves a single-page HTML application that uses the Portal REST API.
 * The HTML file is loaded from <app_dir>/data/admin/admin.html or
 * falls back to a built-in default page.
 *
 * All dynamic data comes from the existing /api/ endpoints via
 * JavaScript fetch() calls. No server-side rendering needed.
 * Hot-reload: PUT /admin/reload to update HTML without restart.
 *
 * Features:
 *   - Login with username/password (Basic Auth)
 *   - Dashboard with metrics (modules, paths, memory, load, uptime)
 *   - Module browser: resources, functions, events per module
 *   - Node federation: peers, ping, location, remote node switching
 *   - User/group management
 *   - Resource locks viewer
 *   - Configuration editor
 *   - Audit log viewer
 *
 * Config:
 *   [mod_admin]
 *   title = Portal Admin
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "portal/portal.h"

static portal_core_t *g_core = NULL;
static char *g_html = NULL;
static size_t g_html_len = 0;

static portal_module_info_t info = {
    .name = "admin", .version = "2.0.0",
    .description = "Web administration dashboard (SPA)",
    .soft_deps = (const char *[]){"web", NULL}
};
portal_module_info_t *portal_module_info(void) { return &info; }

/* Load HTML from file */
static int load_html(portal_core_t *core)
{
    char path[512];
    const char *app_dir = core->config_get(core, "core", "app_dir");
    if (!app_dir) app_dir = core->config_get(core, "core", "data_dir");
    if (!app_dir) return -1;

    snprintf(path, sizeof(path), "%s/data/admin/admin.html", app_dir);
    struct stat st;
    if (stat(path, &st) != 0) {
        /* Try source directory as fallback (development) */
        snprintf(path, sizeof(path), "%s/modules/mod_admin/html/admin.html",
                 core->config_get(core, "core", "modules_dir") ?
                 "/var/www/html/portal" : ".");
        if (stat(path, &st) != 0) return -1;
    }

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    if (g_html) { free(g_html); g_html = NULL; }
    g_html = malloc((size_t)st.st_size + 1);
    if (!g_html) { fclose(f); return -1; }

    g_html_len = fread(g_html, 1, (size_t)st.st_size, f);
    g_html[g_html_len] = '\0';
    fclose(f);

    core->log(core, PORTAL_LOG_INFO, "admin",
              "Loaded admin.html (%zu bytes) from %s", g_html_len, path);
    return 0;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;

    /* Load HTML file */
    if (load_html(core) < 0) {
        core->log(core, PORTAL_LOG_WARN, "admin",
                  "admin.html not found — place in <app_dir>/data/admin/admin.html");
    }

    /* Register paths — all admin paths served as HTML */
    core->path_register(core, "/admin/dashboard", "admin");
    core->path_set_access(core, "/admin/dashboard", PORTAL_ACCESS_READ);
    core->path_register(core, "/admin/*", "admin");
    core->path_set_access(core, "/admin/*", PORTAL_ACCESS_READ);

    core->log(core, PORTAL_LOG_INFO, "admin",
              "Admin panel ready (%zu bytes)", g_html_len);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/admin/dashboard");
    core->path_unregister(core, "/admin/*");
    if (g_html) { free(g_html); g_html = NULL; g_html_len = 0; }
    core->log(core, PORTAL_LOG_INFO, "admin", "Admin panel unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;

    /* Reload command */
    if (strcmp(msg->path, "/admin/reload") == 0) {
        load_html(g_core);
        portal_resp_set_status(resp, PORTAL_OK);
        char buf[64];
        int n = snprintf(buf, sizeof(buf), "Reloaded (%zu bytes)\n", g_html_len);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* Serve HTML for all admin paths */
    if (g_html && g_html_len > 0) {
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, g_html, g_html_len);
    } else {
        portal_resp_set_status(resp, PORTAL_OK);
        const char *fallback =
            "<!DOCTYPE html><html><body style='background:#0d1117;color:#c9d1d9;font-family:sans-serif;padding:40px'>"
            "<h1>Portal Admin</h1>"
            "<p>admin.html not found. Place it in <code>&lt;app_dir&gt;/data/admin/admin.html</code></p>"
            "<p>Or run: <code>cp modules/mod_admin/html/admin.html /var/lib/portal/&lt;instance&gt;/data/admin/</code></p>"
            "</body></html>";
        portal_resp_set_body(resp, fallback, strlen(fallback));
    }
    return 0;
}
