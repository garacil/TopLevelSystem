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
 * mod_logic_lua — Lua Scripting Engine for Portal
 *
 * Embeds Lua 5.4 interpreter. Loads .lua scripts from the
 * logic directory. Provides the Portal API as Lua functions:
 *
 *   portal.get("/path")
 *   portal.call("/path", {key="value"})
 *   portal.set("/path", data)
 *   portal.log("info", "message")
 *   portal.route("GET", "/app/page", handler_function)
 *   portal.on("/events/x", handler_function)
 *
 * Config:
 *   [mod_logic_lua]
 *   auto_load = true
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include "portal/portal.h"

#define LUA_MAX_SCRIPTS  64

static portal_core_t *g_core = NULL;
static lua_State     *g_L = NULL;
static char           g_script_dir[PORTAL_MAX_PATH_LEN] = "";
static int            g_scripts_loaded = 0;

/* Route table: path → lua function name */
#define MAX_LUA_ROUTES 128
typedef struct {
    char path[PORTAL_MAX_PATH_LEN];
    char func[128];
    int active;
} lua_route_t;

static lua_route_t g_lua_routes[MAX_LUA_ROUTES];
static int g_lua_route_count = 0;

static void register_route_via_core(const char *method, const char *path,
                                     const char *func_name)
{
    (void)method;
    if (g_lua_route_count >= MAX_LUA_ROUTES) return;
    lua_route_t *r = &g_lua_routes[g_lua_route_count++];
    snprintf(r->path, sizeof(r->path), "%s", path);
    snprintf(r->func, sizeof(r->func), "%s", func_name);
    r->active = 1;
    if (g_core) {
        g_core->path_register(g_core, path, "logic_lua");
        g_core->path_set_access(g_core, path, PORTAL_ACCESS_RW);
    }
}

static const char *find_lua_route(const char *path)
{
    for (int i = 0; i < g_lua_route_count; i++)
        if (g_lua_routes[i].active && strcmp(g_lua_routes[i].path, path) == 0)
            return g_lua_routes[i].func;
    return NULL;
}


static portal_module_info_t info = {
    .name = "logic_lua", .version = "1.0.0",
    .description = "Lua scripting engine (PL/Lua)",
    .soft_deps = (const char *[]){"logic", NULL}
};
portal_module_info_t *portal_module_info(void) { return &info; }

/* ============================================= */
/*   Portal API for Lua scripts                  */
/* ============================================= */

/* portal.get("/path") → string */
static int lua_portal_get(lua_State *L)
{
    const char *path = luaL_checkstring(L, 1);

    portal_msg_t *msg = portal_msg_alloc();
    portal_resp_t *resp = portal_resp_alloc();
    if (!msg || !resp) { lua_pushnil(L); return 1; }

    portal_msg_set_path(msg, path);
    portal_msg_set_method(msg, PORTAL_METHOD_GET);
    g_core->send(g_core, msg, resp);

    if (resp->status == PORTAL_OK && resp->body) {
        size_t blen = resp->body_len;
        if (blen > 0 && ((char *)resp->body)[blen-1] == '\0') blen--;
        lua_pushlstring(L, resp->body, blen);
    } else {
        lua_pushnil(L);
    }

    portal_msg_free(msg);
    portal_resp_free(resp);
    return 1;
}

/* portal.call("/path", {key="val", ...}) → string */
static int lua_portal_call(lua_State *L)
{
    const char *path = luaL_checkstring(L, 1);

    portal_msg_t *msg = portal_msg_alloc();
    portal_resp_t *resp = portal_resp_alloc();
    if (!msg || !resp) { lua_pushnil(L); return 1; }

    portal_msg_set_path(msg, path);
    portal_msg_set_method(msg, PORTAL_METHOD_CALL);

    /* Second arg: table of headers */
    if (lua_istable(L, 2)) {
        lua_pushnil(L);
        while (lua_next(L, 2) != 0) {
            const char *k = lua_tostring(L, -2);
            const char *v = lua_tostring(L, -1);
            if (k && v)
                portal_msg_add_header(msg, k, v);
            lua_pop(L, 1);
        }
    }

    /* Third arg: body string */
    if (lua_isstring(L, 3)) {
        size_t blen;
        const char *body = lua_tolstring(L, 3, &blen);
        portal_msg_set_body(msg, body, blen);
    }

    g_core->send(g_core, msg, resp);

    if (resp->body) {
        size_t blen = resp->body_len;
        if (blen > 0 && ((char *)resp->body)[blen-1] == '\0') blen--;
        lua_pushlstring(L, resp->body, blen);
    } else {
        lua_pushnil(L);
    }

    /* Also push status */
    lua_pushinteger(L, resp->status);

    portal_msg_free(msg);
    portal_resp_free(resp);
    return 2;  /* returns: body, status */
}

/* portal.set("/path", data) → status */
static int lua_portal_set(lua_State *L)
{
    const char *path = luaL_checkstring(L, 1);

    portal_msg_t *msg = portal_msg_alloc();
    portal_resp_t *resp = portal_resp_alloc();
    if (!msg || !resp) { lua_pushinteger(L, 500); return 1; }

    portal_msg_set_path(msg, path);
    portal_msg_set_method(msg, PORTAL_METHOD_SET);

    if (lua_istable(L, 2)) {
        lua_pushnil(L);
        while (lua_next(L, 2) != 0) {
            const char *k = lua_tostring(L, -2);
            const char *v = lua_tostring(L, -1);
            if (k && v) portal_msg_add_header(msg, k, v);
            lua_pop(L, 1);
        }
    } else if (lua_isstring(L, 2)) {
        size_t blen;
        const char *body = lua_tolstring(L, 2, &blen);
        portal_msg_set_body(msg, body, blen);
    }

    g_core->send(g_core, msg, resp);
    lua_pushinteger(L, resp->status);

    portal_msg_free(msg);
    portal_resp_free(resp);
    return 1;
}

/* portal.log(level, message) */
static int lua_portal_log(lua_State *L)
{
    const char *level_s = luaL_checkstring(L, 1);
    const char *message = luaL_checkstring(L, 2);

    int level = PORTAL_LOG_INFO;
    if (strcmp(level_s, "error") == 0) level = PORTAL_LOG_ERROR;
    else if (strcmp(level_s, "warn") == 0) level = PORTAL_LOG_WARN;
    else if (strcmp(level_s, "debug") == 0) level = PORTAL_LOG_DEBUG;
    else if (strcmp(level_s, "trace") == 0) level = PORTAL_LOG_TRACE;

    g_core->log(g_core, level, "lua", "%s", message);
    return 0;
}

/* portal.route("GET", "/app/page", function_name_string) */
static int lua_portal_route(lua_State *L)
{
    const char *method = luaL_checkstring(L, 1);
    const char *path = luaL_checkstring(L, 2);
    const char *func_name = luaL_checkstring(L, 3);

    register_route_via_core(method, path, func_name);
    g_core->log(g_core, PORTAL_LOG_INFO, "lua",
                "Route: %s %s → %s()", method, path, func_name);
    return 0;
}

/* portal.on("/events/path", function_name_string) */
static int lua_portal_on(lua_State *L)
{
    const char *event = luaL_checkstring(L, 1);
    const char *func_name = luaL_checkstring(L, 2);

    /* TODO: register event handler via core path system */
    g_core->log(g_core, PORTAL_LOG_INFO, "lua",
                "Event handler: %s → %s()", event, func_name);
    return 0;
}

/* Register the portal table */
static const luaL_Reg portal_lib[] = {
    {"get",   lua_portal_get},
    {"call",  lua_portal_call},
    {"set",   lua_portal_set},
    {"log",   lua_portal_log},
    {"route", lua_portal_route},
    {"on",    lua_portal_on},
    {NULL, NULL}
};

static int luaopen_portal(lua_State *L)
{
    luaL_newlib(L, portal_lib);
    return 1;
}

/* ============================================= */
/*   Script loading                               */
/* ============================================= */

/*
 * Scan logic directory for app subdirectories.
 * Each subdir with main.lua = one logic module.
 * Also loads loose .lua files for backwards compatibility.
 */
static int load_lua_scripts(void)
{
    if (g_script_dir[0] == '\0') return 0;

    DIR *d = opendir(g_script_dir);
    if (!d) return 0;

    struct dirent *entry;
    int loaded = 0;

    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char fpath[2048];
        snprintf(fpath, sizeof(fpath), "%s/%s", g_script_dir, entry->d_name);

        struct stat st;
        if (stat(fpath, &st) < 0) continue;

        if (S_ISDIR(st.st_mode)) {
            /* Directory: look for main.lua */
            char main_lua[4096];
            snprintf(main_lua, sizeof(main_lua), "%s/main.lua", fpath);
            if (access(main_lua, F_OK) != 0) continue;

            /* Set app name as global before loading */
            lua_pushstring(g_L, entry->d_name);
            lua_setglobal(g_L, "APP_NAME");

            /* Add app's directory to Lua package.path */
            char lua_path[4096];
            snprintf(lua_path, sizeof(lua_path),
                "package.path = '%s/?.lua;' .. package.path", fpath);
            (void)luaL_dostring(g_L, lua_path);

            if (luaL_dofile(g_L, main_lua) != LUA_OK) {
                g_core->log(g_core, PORTAL_LOG_ERROR, "lua",
                            "Error loading %s/main.lua: %s",
                            entry->d_name, lua_tostring(g_L, -1));
                lua_pop(g_L, 1);
            } else {
                g_core->log(g_core, PORTAL_LOG_INFO, "lua",
                            "Loaded logic module: %s", entry->d_name);
                loaded++;
            }
        } else if (S_ISREG(st.st_mode)) {
            /* Regular file: load if .lua (backwards compatible) */
            size_t nlen = strlen(entry->d_name);
            if (nlen < 5 || strcmp(entry->d_name + nlen - 4, ".lua") != 0)
                continue;

            if (luaL_dofile(g_L, fpath) != LUA_OK) {
                g_core->log(g_core, PORTAL_LOG_ERROR, "lua",
                            "Error loading %s: %s",
                            entry->d_name, lua_tostring(g_L, -1));
                lua_pop(g_L, 1);
            } else {
                g_core->log(g_core, PORTAL_LOG_INFO, "lua",
                            "Loaded script: %s", entry->d_name);
                loaded++;
            }
        }
    }

    closedir(d);
    g_scripts_loaded = loaded;
    return loaded;
}

/* ============================================= */
/*   Execute a Lua function (called by mod_logic) */
/* ============================================= */

static int execute_lua_function(const char *func_name, const portal_msg_t *msg,
                                 portal_resp_t *resp)
{
    if (!g_L) return -1;

    lua_getglobal(g_L, func_name);
    if (!lua_isfunction(g_L, -1)) {
        lua_pop(g_L, 1);
        portal_resp_set_status(resp, PORTAL_NOT_FOUND);
        char buf[128];
        int n = snprintf(buf, sizeof(buf), "Lua function '%s' not found\n", func_name);
        portal_resp_set_body(resp, buf, (size_t)n);
        return -1;
    }

    /* Pass request info as a table */
    lua_newtable(g_L);
    lua_pushstring(g_L, msg->path);
    lua_setfield(g_L, -2, "path");
    lua_pushinteger(g_L, msg->method);
    lua_setfield(g_L, -2, "method");
    if (msg->body) {
        lua_pushlstring(g_L, msg->body, msg->body_len);
        lua_setfield(g_L, -2, "body");
    }
    /* Headers as subtable */
    lua_newtable(g_L);
    for (uint16_t i = 0; i < msg->header_count; i++) {
        lua_pushstring(g_L, msg->headers[i].value);
        lua_setfield(g_L, -2, msg->headers[i].key);
    }
    lua_setfield(g_L, -2, "headers");

    /* Call: func(request) → response_string */
    if (lua_pcall(g_L, 1, 1, 0) != LUA_OK) {
        const char *err = lua_tostring(g_L, -1);
        g_core->log(g_core, PORTAL_LOG_ERROR, "lua",
                    "Error in %s(): %s", func_name, err);
        portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
        portal_resp_set_body(resp, err, strlen(err));
        lua_pop(g_L, 1);
        return -1;
    }

    /* Get return value */
    if (lua_isstring(g_L, -1)) {
        size_t rlen;
        const char *result = lua_tolstring(g_L, -1, &rlen);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, result, rlen);
    } else {
        portal_resp_set_status(resp, PORTAL_OK);
    }
    lua_pop(g_L, 1);
    return 0;
}

/* ============================================= */
/*   Module lifecycle                             */
/* ============================================= */

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_scripts_loaded = 0;
    memset(g_lua_routes, 0, sizeof(g_lua_routes));
    g_lua_route_count = 0;

    /* Get script dir: app_dir/logic (code lives in /var/lib, not /etc) */
    const char *dir = core->config_get(core, "logic", "script_dir");
    if (dir && dir[0]) {
        snprintf(g_script_dir, sizeof(g_script_dir), "%s", dir);
    } else {
        const char *app_dir = core->config_get(core, "core", "app_dir");
        if (app_dir)
            snprintf(g_script_dir, sizeof(g_script_dir), "%s/logic", app_dir);
        else {
            const char *data_dir = core->config_get(core, "core", "data_dir");
            if (data_dir)
                snprintf(g_script_dir, sizeof(g_script_dir), "%s/logic", data_dir);
        }
    }
    mkdir(g_script_dir, 0755);

    /* Create Lua state */
    g_L = luaL_newstate();
    if (!g_L) {
        core->log(core, PORTAL_LOG_ERROR, "lua", "Failed to create Lua state");
        return PORTAL_MODULE_FAIL;
    }

    luaL_openlibs(g_L);

    /* Register portal.* API */
    luaL_requiref(g_L, "portal", luaopen_portal, 1);
    lua_pop(g_L, 1);

    /* Register paths */
    core->path_register(core, "/logic_lua/resources/status", "logic_lua");
    core->path_set_access(core, "/logic_lua/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/logic_lua/resources/status", "Lua 5.4 engine: version, loaded scripts, routes");
    core->path_register(core, "/logic_lua/functions/execute", "logic_lua");
    core->path_set_access(core, "/logic_lua/functions/execute", PORTAL_ACCESS_RW);
    core->path_register(core, "/logic_lua/functions/eval", "logic_lua");
    core->path_set_access(core, "/logic_lua/functions/eval", PORTAL_ACCESS_RW);
    core->path_register(core, "/logic_lua/functions/reload", "logic_lua");
    core->path_set_access(core, "/logic_lua/functions/reload", PORTAL_ACCESS_RW);

    /* Load all .lua scripts from script directory */
    int loaded = load_lua_scripts();

    core->log(core, PORTAL_LOG_INFO, "lua",
              "Lua %s ready (%d scripts from %s)",
              LUA_RELEASE, loaded, g_script_dir);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    /* Unregister Lua routes */
    for (int i = 0; i < g_lua_route_count; i++)
        if (g_lua_routes[i].active)
            core->path_unregister(core, g_lua_routes[i].path);
    g_lua_route_count = 0;

    if (g_L) { lua_close(g_L); g_L = NULL; }
    core->path_unregister(core, "/logic_lua/resources/status");
    core->path_unregister(core, "/logic_lua/functions/execute");
    core->path_unregister(core, "/logic_lua/functions/eval");
    core->path_unregister(core, "/logic_lua/functions/reload");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;
    char buf[4096];
    int n;

    if (strcmp(msg->path, "/logic_lua/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "Lua Scripting Engine\n"
            "Version: %s\n"
            "Scripts loaded: %d\n"
            "Script dir: %s\n"
            "Memory: %zuKB\n",
            LUA_RELEASE, g_scripts_loaded, g_script_dir,
            g_L ? (size_t)(lua_gc(g_L, LUA_GCCOUNT, 0)) : 0);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* /logic_lua/functions/execute — called by mod_logic to run a function */
    if (strcmp(msg->path, "/logic_lua/functions/execute") == 0) {
        const char *func = get_hdr(msg, "function");
        if (!func) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
        return execute_lua_function(func, msg, resp);
    }

    /* /logic_lua/functions/eval — execute arbitrary Lua code */
    if (strcmp(msg->path, "/logic_lua/functions/eval") == 0) {
        if (!msg->body || !g_L) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }

        /* Capture print output */
        if (luaL_dostring(g_L, msg->body) != LUA_OK) {
            const char *err = lua_tostring(g_L, -1);
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            portal_resp_set_body(resp, err, strlen(err));
            lua_pop(g_L, 1);
        } else {
            /* Return top of stack if string */
            if (lua_isstring(g_L, -1)) {
                size_t rlen;
                const char *result = lua_tolstring(g_L, -1, &rlen);
                portal_resp_set_status(resp, PORTAL_OK);
                portal_resp_set_body(resp, result, rlen);
                lua_pop(g_L, 1);
            } else {
                portal_resp_set_status(resp, PORTAL_OK);
                portal_resp_set_body(resp, "OK\n", 3);
            }
        }
        return 0;
    }

    /* /logic_lua/functions/reload — reload all scripts */
    if (strcmp(msg->path, "/logic_lua/functions/reload") == 0) {
        if (g_L) lua_close(g_L);
        g_L = luaL_newstate();
        luaL_openlibs(g_L);
        luaL_requiref(g_L, "portal", luaopen_portal, 1);
        lua_pop(g_L, 1);
        int loaded = load_lua_scripts();
        n = snprintf(buf, sizeof(buf), "Reloaded %d scripts\n", loaded);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* Check if this path is a Lua-registered route */
    const char *lua_func = find_lua_route(msg->path);
    if (lua_func)
        return execute_lua_function(lua_func, msg, resp);

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
