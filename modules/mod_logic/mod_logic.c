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
 * mod_logic — Application Logic Framework
 *
 * The "heart" of Portal. Manages application scripts, routes,
 * event handlers, and cron jobs. Language-agnostic framework —
 * actual script execution is delegated to language handlers
 * (mod_logic_lua, mod_logic_python, etc.).
 *
 * Scripts live in: /etc/portal/<instance>/logic/
 *
 * Config:
 *   [mod_logic]
 *   script_dir = /etc/portal/<instance>/logic
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include "portal/portal.h"

#define LOGIC_MAX_ROUTES   256
#define LOGIC_MAX_HANDLERS 128

/* A registered HTTP/path route */
typedef struct {
    char    method[16];                /* GET, POST, CALL */
    char    path[PORTAL_MAX_PATH_LEN]; /* /app/dashboard */
    char    script[256];               /* which script handles it */
    char    function[128];             /* function name in script */
    char    lang[32];                  /* "lua", "python", "js" */
    int     active;
} logic_route_t;

/* A registered event handler */
typedef struct {
    char    event_path[PORTAL_MAX_PATH_LEN];
    char    script[256];
    char    function[128];
    char    lang[32];
    int     active;
} logic_handler_t;

static portal_core_t  *g_core = NULL;
static logic_route_t   g_routes[LOGIC_MAX_ROUTES];
static int             g_route_count = 0;
static logic_handler_t g_handlers[LOGIC_MAX_HANDLERS];
static int             g_handler_count = 0;
static char            g_script_dir[PORTAL_MAX_PATH_LEN] = "";

static portal_module_info_t info = {
    .name = "logic", .version = "1.0.0",
    .description = "Application logic framework",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

/* --- Route registry (called by language handlers) --- */

int logic_register_route(const char *method, const char *path,
                          const char *script, const char *function,
                          const char *lang)
{
    if (g_route_count >= LOGIC_MAX_ROUTES) return -1;

    logic_route_t *r = &g_routes[g_route_count++];
    snprintf(r->method, sizeof(r->method), "%s", method);
    snprintf(r->path, sizeof(r->path), "%s", path);
    snprintf(r->script, sizeof(r->script), "%s", script);
    snprintf(r->function, sizeof(r->function), "%s", function);
    snprintf(r->lang, sizeof(r->lang), "%s", lang);
    r->active = 1;

    /* Register the path with the core */
    if (g_core) {
        g_core->path_register(g_core, path, "logic");
        g_core->path_set_access(g_core, path, PORTAL_ACCESS_RW);
    }

    return 0;
}

int logic_register_event_handler(const char *event_path, const char *script,
                                  const char *function, const char *lang)
{
    if (g_handler_count >= LOGIC_MAX_HANDLERS) return -1;

    logic_handler_t *h = &g_handlers[g_handler_count++];
    snprintf(h->event_path, sizeof(h->event_path), "%s", event_path);
    snprintf(h->script, sizeof(h->script), "%s", script);
    snprintf(h->function, sizeof(h->function), "%s", function);
    snprintf(h->lang, sizeof(h->lang), "%s", lang);
    h->active = 1;

    return 0;
}

/* Find route for a path */
logic_route_t *logic_find_route(const char *path)
{
    for (int i = 0; i < g_route_count; i++)
        if (g_routes[i].active && strcmp(g_routes[i].path, path) == 0)
            return &g_routes[i];
    return NULL;
}

const char *logic_get_script_dir(void)
{
    return g_script_dir;
}

portal_core_t *logic_get_core(void)
{
    return g_core;
}

/* --- Module lifecycle --- */

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_routes, 0, sizeof(g_routes));
    memset(g_handlers, 0, sizeof(g_handlers));
    g_route_count = 0;
    g_handler_count = 0;

    /* Get script directory */
    const char *dir = core->config_get(core, "logic", "script_dir");
    if (dir) {
        snprintf(g_script_dir, sizeof(g_script_dir), "%s", dir);
    } else {
        const char *data_dir = core->config_get(core, "core", "data_dir");
        if (data_dir)
            snprintf(g_script_dir, sizeof(g_script_dir), "%s/logic", data_dir);
        else
            snprintf(g_script_dir, sizeof(g_script_dir), "/etc/portal/logic");
    }

    /* Create script directory if missing */
    mkdir(g_script_dir, 0755);

    core->path_register(core, "/logic/resources/status", "logic");
    core->path_set_access(core, "/logic/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/logic/resources/routes", "logic");
    core->path_set_access(core, "/logic/resources/routes", PORTAL_ACCESS_READ);
    core->path_register(core, "/logic/resources/scripts", "logic");
    core->path_set_access(core, "/logic/resources/scripts", PORTAL_ACCESS_READ);
    core->path_register(core, "/logic/functions/reload", "logic");
    core->path_set_access(core, "/logic/functions/reload", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "logic",
              "Logic framework ready (scripts: %s)", g_script_dir);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    /* Unregister all dynamic routes */
    for (int i = 0; i < g_route_count; i++)
        if (g_routes[i].active)
            core->path_unregister(core, g_routes[i].path);

    core->path_unregister(core, "/logic/resources/status");
    core->path_unregister(core, "/logic/resources/routes");
    core->path_unregister(core, "/logic/resources/scripts");
    core->path_unregister(core, "/logic/functions/reload");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[8192];
    int n;

    if (strcmp(msg->path, "/logic/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "Logic Framework\n"
            "Script dir: %s\n"
            "Routes: %d\n"
            "Event handlers: %d\n",
            g_script_dir, g_route_count, g_handler_count);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/logic/resources/routes") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Routes:\n");
        for (int i = 0; i < g_route_count; i++) {
            if (g_routes[i].active)
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "  %-6s %-30s → %s:%s [%s]\n",
                    g_routes[i].method, g_routes[i].path,
                    g_routes[i].script, g_routes[i].function,
                    g_routes[i].lang);
        }
        if (g_route_count == 0)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "  (none — load a language module to add routes)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/logic/resources/scripts") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
            "Scripts in %s:\n", g_script_dir);
        DIR *d = opendir(g_script_dir);
        if (d) {
            struct dirent *entry;
            while ((entry = readdir(d)) != NULL) {
                if (entry->d_name[0] == '.') continue;
                char fpath[PORTAL_MAX_PATH_LEN + 256];
                snprintf(fpath, sizeof(fpath), "%s/%s", g_script_dir, entry->d_name);
                struct stat st;
                stat(fpath, &st);
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "  %-30s %ld bytes\n", entry->d_name, (long)st.st_size);
            }
            closedir(d);
        }
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    /* Check if this path matches a logic route */
    logic_route_t *route = logic_find_route(msg->path);
    if (route) {
        /* Delegate to the language handler.
         * The language module must call back through core->send()
         * to /logic_<lang>/functions/execute with the script+function info */
        char exec_path[PORTAL_MAX_PATH_LEN];
        snprintf(exec_path, sizeof(exec_path),
                 "/logic_%s/functions/execute", route->lang);

        portal_msg_t *exec_msg = portal_msg_alloc();
        portal_resp_t *exec_resp = portal_resp_alloc();
        if (exec_msg && exec_resp) {
            portal_msg_set_path(exec_msg, exec_path);
            portal_msg_set_method(exec_msg, PORTAL_METHOD_CALL);
            portal_msg_add_header(exec_msg, "script", route->script);
            portal_msg_add_header(exec_msg, "function", route->function);
            portal_msg_add_header(exec_msg, "request_path", msg->path);
            if (msg->body)
                portal_msg_set_body(exec_msg, msg->body, msg->body_len);

            /* Copy original headers */
            for (uint16_t i = 0; i < msg->header_count; i++)
                portal_msg_add_header(exec_msg, msg->headers[i].key,
                                       msg->headers[i].value);

            core->send(core, exec_msg, exec_resp);

            /* Forward response */
            resp->status = exec_resp->status;
            if (exec_resp->body)
                portal_resp_set_body(resp, exec_resp->body, exec_resp->body_len);

            portal_msg_free(exec_msg);
            portal_resp_free(exec_resp);
            return 0;
        }
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
