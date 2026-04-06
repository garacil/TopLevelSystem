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
 * mod_logic_c — C Scripting Engine for Portal
 *
 * Compiles C source files from the logic directory into shared
 * libraries and loads them as Portal modules. Native C speed
 * with hot-reload capability.
 *
 * Scripts in: /var/lib/portal/<instance>/logic/<appname>/main.c
 * Compiled to: /var/lib/portal/<instance>/logic/<appname>/.build/app.so
 *
 * The C source uses portal.h directly — same API as any module.
 * Each app must export: app_load(portal_core_t *core) and
 * app_handle(portal_core_t *core, const portal_msg_t *msg, portal_resp_t *resp)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "portal/portal.h"

#define LOGIC_C_MAX_APPS   32

typedef int  (*app_load_fn)(portal_core_t *core);
typedef int  (*app_unload_fn)(portal_core_t *core);
typedef int  (*app_handle_fn)(portal_core_t *core, const portal_msg_t *msg,
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
} c_app_t;

static portal_core_t *g_core = NULL;
static char           g_script_dir[PORTAL_MAX_PATH_LEN] = "";
static c_app_t        g_apps[LOGIC_C_MAX_APPS];
static int            g_app_count = 0;

static portal_module_info_t info = {
    .name = "logic_c", .version = "1.0.0",
    .description = "C scripting engine (compile + load)",
    .soft_deps = (const char *[]){"logic", NULL}
};
portal_module_info_t *portal_module_info(void) { return &info; }

/* Compile a C app: gcc -shared -fPIC -o app.so main.c */
static int compile_app(const char *src_dir, const char *so_path, const char *name)
{
    /* Create build directory */
    char build_dir[2048];
    snprintf(build_dir, sizeof(build_dir), "%s/.build", src_dir);
    mkdir(build_dir, 0755);

    /* Find all .c files in the directory */
    char sources[4096] = "";
    DIR *d = opendir(src_dir);
    if (!d) return -1;

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        size_t nlen = strlen(entry->d_name);
        if (nlen > 2 && strcmp(entry->d_name + nlen - 2, ".c") == 0) {
            char fpath[2048];
            snprintf(fpath, sizeof(fpath), "%s/%s ", src_dir, entry->d_name);
            strncat(sources, fpath, sizeof(sources) - strlen(sources) - 1);
        }
    }
    closedir(d);

    if (sources[0] == '\0') return -1;

    /* Compile */
    char cmd[8192];
    snprintf(cmd, sizeof(cmd),
        "gcc -shared -fPIC -Wall -std=c11 -D_GNU_SOURCE "
        "-I/var/www/html/portal/include "
        "-I/var/www/html/portal/src "
        "-I/var/www/html/portal/lib/libev "
        "-I/usr/lib/portal/include "
        "-o %s %s "
        "/var/www/html/portal/src/core/core_message.c "
        "2>&1",
        so_path, sources);

    FILE *p = popen(cmd, "r");
    if (!p) return -1;

    char output[4096] = "";
    size_t olen = 0;
    char line[256];
    while (fgets(line, sizeof(line), p))
        olen += (size_t)snprintf(output + olen, sizeof(output) - olen, "%s", line);

    int rc = pclose(p);
    if (rc != 0) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "c",
                    "Compile '%s' failed:\n%s", name, output);
        return -1;
    }

    g_core->log(g_core, PORTAL_LOG_INFO, "c",
                "Compiled '%s' → %s", name, so_path);
    return 0;
}

/* Load a compiled C app */
static int load_c_app(c_app_t *app)
{
    app->handle = dlopen(app->so_path, RTLD_NOW);
    if (!app->handle) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "c",
                    "dlopen '%s' failed: %s", app->name, dlerror());
        return -1;
    }

    app->fn_load = (app_load_fn)dlsym(app->handle, "app_load");
    app->fn_unload = (app_unload_fn)dlsym(app->handle, "app_unload");
    app->fn_handle = (app_handle_fn)dlsym(app->handle, "app_handle");

    if (!app->fn_load || !app->fn_handle) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "c",
                    "App '%s' missing app_load or app_handle", app->name);
        dlclose(app->handle);
        app->handle = NULL;
        return -1;
    }

    if (app->fn_load(g_core) != 0) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "c",
                    "App '%s' app_load() failed", app->name);
        dlclose(app->handle);
        app->handle = NULL;
        return -1;
    }

    app->active = 1;
    g_core->log(g_core, PORTAL_LOG_INFO, "c",
                "Loaded C app: %s", app->name);
    return 0;
}

/* Scan, compile, and load all C apps */
static int load_c_apps(void)
{
    if (g_script_dir[0] == '\0') return 0;

    DIR *d = opendir(g_script_dir);
    if (!d) return 0;

    struct dirent *entry;
    int loaded = 0;

    while ((entry = readdir(d)) != NULL && g_app_count < LOGIC_C_MAX_APPS) {
        if (entry->d_name[0] == '.') continue;

        char fpath[2048];
        snprintf(fpath, sizeof(fpath), "%s/%s", g_script_dir, entry->d_name);

        struct stat st;
        if (stat(fpath, &st) < 0 || !S_ISDIR(st.st_mode)) continue;

        /* Check for main.c */
        char main_c[4096];
        snprintf(main_c, sizeof(main_c), "%s/main.c", fpath);
        if (access(main_c, F_OK) != 0) continue;

        c_app_t *app = &g_apps[g_app_count];
        memset(app, 0, sizeof(*app));
        snprintf(app->name, sizeof(app->name), "%.63s", entry->d_name);
        snprintf(app->src_dir, sizeof(app->src_dir), "%.2047s", fpath);
        snprintf(app->so_path, sizeof(app->so_path),
                 "%.2030s/.build/app.so", fpath);

        /* Compile */
        if (compile_app(app->src_dir, app->so_path, app->name) != 0)
            continue;

        /* Load */
        if (load_c_app(app) == 0) {
            g_app_count++;
            loaded++;
        }
    }

    closedir(d);
    return loaded;
}

/* --- Module lifecycle --- */

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

    core->path_register(core, "/logic_c/resources/status", "logic_c");
    core->path_set_access(core, "/logic_c/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/logic_c/functions/compile", "logic_c");
    core->path_set_access(core, "/logic_c/functions/compile", PORTAL_ACCESS_RW);
    core->path_register(core, "/logic_c/functions/reload", "logic_c");
    core->path_set_access(core, "/logic_c/functions/reload", PORTAL_ACCESS_RW);

    int loaded = load_c_apps();

    core->log(core, PORTAL_LOG_INFO, "c",
              "C engine ready (%d apps from %s)", loaded, g_script_dir);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    for (int i = 0; i < g_app_count; i++) {
        if (g_apps[i].active) {
            if (g_apps[i].fn_unload)
                g_apps[i].fn_unload(core);
            if (g_apps[i].handle)
                dlclose(g_apps[i].handle);
        }
    }
    g_app_count = 0;
    core->path_unregister(core, "/logic_c/resources/status");
    core->path_unregister(core, "/logic_c/functions/compile");
    core->path_unregister(core, "/logic_c/functions/reload");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[4096];
    int n;

    if (strcmp(msg->path, "/logic_c/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "C Scripting Engine\nApps: %d\nDir: %s\n\n", g_app_count, g_script_dir);
        for (int i = 0; i < g_app_count; i++) {
            if (g_apps[i].active)
                n += snprintf(buf + n, sizeof(buf) - (size_t)n,
                    "  %-20s %s\n", g_apps[i].name, g_apps[i].so_path);
        }
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/logic_c/functions/reload") == 0) {
        /* Unload all, recompile, reload */
        for (int i = 0; i < g_app_count; i++) {
            if (g_apps[i].active) {
                if (g_apps[i].fn_unload) g_apps[i].fn_unload(core);
                if (g_apps[i].handle) dlclose(g_apps[i].handle);
                g_apps[i].active = 0;
            }
        }
        g_app_count = 0;
        int loaded = load_c_apps();
        n = snprintf(buf, sizeof(buf), "Reloaded %d C apps\n", loaded);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* Route to C app handlers */
    for (int i = 0; i < g_app_count; i++) {
        if (g_apps[i].active && g_apps[i].fn_handle) {
            int rc = g_apps[i].fn_handle(core, msg, resp);
            if (rc == 0) return 0;
        }
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
