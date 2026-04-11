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
 * mod_logic_pascal — Free Pascal Scripting Engine for Portal
 *
 * Compiles Pascal source files (.pas) from the logic directory
 * into shared libraries and loads them. Same approach as mod_logic_c
 * but using Free Pascal Compiler (fpc).
 *
 * Scripts in: /var/lib/portal/<instance>/logic/<appname>/main.pas
 * Compiled to: /var/lib/portal/<instance>/logic/<appname>/.build/app.so
 *
 * Each Pascal app must export:
 *   function app_load(core: Pointer): Integer; cdecl;
 *   function app_handle(core: Pointer; msg: Pointer; resp: Pointer): Integer; cdecl;
 *   function app_unload(core: Pointer): Integer; cdecl;
 *
 * A portal_api.pas unit is provided with helper functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "portal/portal.h"

#define PAS_MAX_APPS 32

typedef int (*app_load_fn)(portal_core_t *core);
typedef int (*app_unload_fn)(portal_core_t *core);
typedef int (*app_handle_fn)(portal_core_t *core, const portal_msg_t *msg,
                              portal_resp_t *resp);

typedef struct {
    char          name[64];
    char          src_dir[2048];
    char          so_path[2048];
    void         *handle;
    app_load_fn   fn_load;
    app_unload_fn fn_unload;
    app_handle_fn fn_handle;
    int           active;
} pas_app_t;

static portal_core_t *g_core = NULL;
static char           g_script_dir[PORTAL_MAX_PATH_LEN] = "";
static pas_app_t      g_apps[PAS_MAX_APPS];
static int            g_app_count = 0;

static portal_module_info_t info = {
    .name = "logic_pascal", .version = "1.0.0",
    .description = "Free Pascal scripting engine",
    .soft_deps = (const char *[]){"logic", NULL}
};
portal_module_info_t *portal_module_info(void) { return &info; }

/* Compile Pascal app: fpc -o<output> main.pas */
static int compile_pas_app(const char *src_dir, const char *so_path,
                            const char *name)
{
    char build_dir[2048];
    snprintf(build_dir, sizeof(build_dir), "%s/.build", src_dir);
    mkdir(build_dir, 0755);

    /* fpc can create shared libraries with -Cg -XS flags */
    char cmd[8192];
    snprintf(cmd, sizeof(cmd),
        "fpc -Cg -XX -Xs "
        "-o%s "
        "-FU%s "
        "-Fu/var/www/html/portal/modules/mod_logic_pascal "
        "%s/main.pas "
        "2>&1",
        so_path, build_dir, src_dir);

    FILE *p = popen(cmd, "r");
    if (!p) return -1;

    char output[4096] = "";
    size_t olen = 0;
    char line[256];
    while (fgets(line, sizeof(line), p))
        olen += (size_t)snprintf(output + olen, sizeof(output) - olen, "%s", line);

    int rc = pclose(p);
    if (rc != 0) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "pascal",
                    "Compile '%s' failed:\n%s", name, output);
        return -1;
    }

    g_core->log(g_core, PORTAL_LOG_INFO, "pascal",
                "Compiled '%s'", name);
    return 0;
}

static int load_pas_app(pas_app_t *app)
{
    app->handle = dlopen(app->so_path, RTLD_NOW);
    if (!app->handle) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "pascal",
                    "dlopen '%s': %s", app->name, dlerror());
        return -1;
    }

    app->fn_load = (app_load_fn)dlsym(app->handle, "app_load");
    app->fn_unload = (app_unload_fn)dlsym(app->handle, "app_unload");
    app->fn_handle = (app_handle_fn)dlsym(app->handle, "app_handle");

    if (!app->fn_load || !app->fn_handle) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "pascal",
                    "App '%s' missing exports", app->name);
        dlclose(app->handle);
        app->handle = NULL;
        return -1;
    }

    if (app->fn_load(g_core) != 0) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "pascal",
                    "App '%s' app_load() failed", app->name);
        dlclose(app->handle);
        app->handle = NULL;
        return -1;
    }

    app->active = 1;

    /* Register wildcard path for this app */
    char app_path[PORTAL_MAX_PATH_LEN];
    snprintf(app_path, sizeof(app_path), "/app/%s/*", app->name);
    g_core->path_register(g_core, app_path, "logic_pascal");
    g_core->path_set_access(g_core, app_path, PORTAL_ACCESS_RW);

    g_core->log(g_core, PORTAL_LOG_INFO, "pascal",
                "Loaded Pascal app: %s → /app/%s/*", app->name, app->name);
    return 0;
}

static int load_pascal_apps(void)
{
    if (g_script_dir[0] == '\0') return 0;

    DIR *d = opendir(g_script_dir);
    if (!d) return 0;

    struct dirent *entry;
    int loaded = 0;

    while ((entry = readdir(d)) != NULL && g_app_count < PAS_MAX_APPS) {
        if (entry->d_name[0] == '.') continue;

        char fpath[2048];
        snprintf(fpath, sizeof(fpath), "%s/%s", g_script_dir, entry->d_name);

        struct stat st;
        if (stat(fpath, &st) < 0 || !S_ISDIR(st.st_mode)) continue;

        /* Check for main.pas */
        char main_pas[4096];
        snprintf(main_pas, sizeof(main_pas), "%s/main.pas", fpath);
        if (access(main_pas, F_OK) != 0) continue;

        pas_app_t *app = &g_apps[g_app_count];
        memset(app, 0, sizeof(*app));
        snprintf(app->name, sizeof(app->name), "%.63s", entry->d_name);
        snprintf(app->src_dir, sizeof(app->src_dir), "%.2047s", fpath);
        snprintf(app->so_path, sizeof(app->so_path),
                 "%.2030s/.build/app.so", fpath);

        if (compile_pas_app(app->src_dir, app->so_path, app->name) != 0)
            continue;

        if (load_pas_app(app) == 0) {
            g_app_count++;
            loaded++;
        }
    }

    closedir(d);
    return loaded;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_apps, 0, sizeof(g_apps));
    g_app_count = 0;

    const char *app_dir = core->config_get(core, "core", "app_dir");
    if (app_dir)
        snprintf(g_script_dir, sizeof(g_script_dir), "%s/logic", app_dir);
    else {
        const char *data_dir = core->config_get(core, "core", "data_dir");
        if (data_dir)
            snprintf(g_script_dir, sizeof(g_script_dir), "%s/logic", data_dir);
    }

    core->path_register(core, "/logic_pascal/resources/status", "logic_pascal");
    core->path_set_access(core, "/logic_pascal/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/logic_pascal/resources/status", "Free Pascal engine: compiled apps");
    core->path_register(core, "/logic_pascal/functions/reload", "logic_pascal");
    core->path_set_access(core, "/logic_pascal/functions/reload", PORTAL_ACCESS_RW);

    int loaded = load_pascal_apps();

    core->log(core, PORTAL_LOG_INFO, "pascal",
              "Pascal engine ready (%d apps)", loaded);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    for (int i = 0; i < g_app_count; i++) {
        if (g_apps[i].active) {
            if (g_apps[i].fn_unload) g_apps[i].fn_unload(core);
            if (g_apps[i].handle) dlclose(g_apps[i].handle);
        }
    }
    g_app_count = 0;
    core->path_unregister(core, "/logic_pascal/resources/status");
    core->path_unregister(core, "/logic_pascal/functions/reload");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[4096];
    int n;

    if (strcmp(msg->path, "/logic_pascal/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "Pascal Scripting Engine\nCompiler: Free Pascal 3.2.2\nApps: %d\nDir: %s\n",
            g_app_count, g_script_dir);
        for (int i = 0; i < g_app_count; i++) {
            if (g_apps[i].active)
                n += snprintf(buf + n, sizeof(buf) - (size_t)n,
                    "  %-20s %s\n", g_apps[i].name, g_apps[i].so_path);
        }
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/logic_pascal/functions/reload") == 0) {
        for (int i = 0; i < g_app_count; i++) {
            if (g_apps[i].active) {
                if (g_apps[i].fn_unload) g_apps[i].fn_unload(core);
                if (g_apps[i].handle) dlclose(g_apps[i].handle);
            }
        }
        g_app_count = 0;
        int loaded = load_pascal_apps();
        n = snprintf(buf, sizeof(buf), "Reloaded %d Pascal apps\n", loaded);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* Route to Pascal app handlers */
    for (int i = 0; i < g_app_count; i++) {
        if (g_apps[i].active && g_apps[i].fn_handle) {
            int rc = g_apps[i].fn_handle(core, msg, resp);
            if (rc == 0) return 0;
        }
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
