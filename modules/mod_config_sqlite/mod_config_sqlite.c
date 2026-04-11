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
 * mod_config_sqlite — SQLite Storage Backend for Portal
 *
 * Provides persistent storage for users, groups, and module configs
 * using a local SQLite database file. Registers as a core storage
 * provider — transparent to all other modules.
 *
 * Config:
 *   [mod_config_sqlite]
 *   database = /etc/portal/devtest/portal.db
 *
 * If no database path configured, defaults to <data_dir>/portal.db
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "portal/portal.h"
#include "portal/storage.h"

static portal_core_t *g_core = NULL;
static sqlite3       *g_db   = NULL;
static char           g_db_path[PORTAL_MAX_PATH_LEN] = "";

/* --- Module info --- */

static portal_module_info_t mod_info = {
    .name        = "config_sqlite",
    .version     = "0.6.0",
    .description = "SQLite storage backend",
    .soft_deps   = NULL
};

portal_module_info_t *portal_module_info(void) { return &mod_info; }

/* --- Database setup --- */

static int ensure_tables(void)
{
    const char *ddl[] = {
        "CREATE TABLE IF NOT EXISTS users ("
        "  username TEXT PRIMARY KEY,"
        "  password TEXT DEFAULT '',"
        "  api_key TEXT DEFAULT '',"
        "  groups TEXT DEFAULT '',"
        "  created_at TEXT DEFAULT (datetime('now')),"
        "  updated_at TEXT DEFAULT (datetime('now'))"
        ")",

        "CREATE TABLE IF NOT EXISTS groups ("
        "  name TEXT PRIMARY KEY,"
        "  description TEXT DEFAULT '',"
        "  created_by TEXT DEFAULT '',"
        "  created_at TEXT DEFAULT (datetime('now'))"
        ")",

        "CREATE TABLE IF NOT EXISTS module_configs ("
        "  module TEXT,"
        "  key TEXT,"
        "  value TEXT DEFAULT '',"
        "  PRIMARY KEY (module, key)"
        ")",

        NULL
    };

    char *err = NULL;
    for (int i = 0; ddl[i]; i++) {
        if (sqlite3_exec(g_db, ddl[i], NULL, NULL, &err) != SQLITE_OK) {
            g_core->log(g_core, PORTAL_LOG_ERROR, "sqlite",
                        "SQL error: %s", err);
            sqlite3_free(err);
            return -1;
        }
    }
    return 0;
}

/* --- Storage provider implementation --- */

static int sqlite_user_list(void *ctx, storage_list_fn cb, void *userdata)
{
    (void)ctx;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, "SELECT username FROM users ORDER BY username",
                            -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    int n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cb((const char *)sqlite3_column_text(stmt, 0), userdata);
        n++;
    }
    sqlite3_finalize(stmt);
    return n;
}

static int sqlite_user_load(void *ctx, const char *username,
                             char *password, size_t pass_len,
                             char *api_key, size_t key_len,
                             char *groups, size_t groups_len)
{
    (void)ctx;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db,
        "SELECT password, api_key, groups FROM users WHERE username=?",
        -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    const char *p = (const char *)sqlite3_column_text(stmt, 0);
    const char *k = (const char *)sqlite3_column_text(stmt, 1);
    const char *g = (const char *)sqlite3_column_text(stmt, 2);
    snprintf(password, pass_len, "%s", p ? p : "");
    snprintf(api_key, key_len, "%s", k ? k : "");
    snprintf(groups, groups_len, "%s", g ? g : "");

    sqlite3_finalize(stmt);
    return 0;
}

static int sqlite_user_save(void *ctx, const char *username,
                             const char *password, const char *api_key,
                             const char *groups)
{
    (void)ctx;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db,
        "INSERT OR REPLACE INTO users (username, password, api_key, groups, updated_at) "
        "VALUES (?, ?, ?, ?, datetime('now'))",
        -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password ? password : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, api_key ? api_key : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, groups ? groups : "", -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    return rc;
}

static int sqlite_user_delete(void *ctx, const char *username)
{
    (void)ctx;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, "DELETE FROM users WHERE username=?",
                            -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    return rc;
}

static int sqlite_group_list(void *ctx, storage_list_fn cb, void *userdata)
{
    (void)ctx;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, "SELECT name FROM groups ORDER BY name",
                            -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    int n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cb((const char *)sqlite3_column_text(stmt, 0), userdata);
        n++;
    }
    sqlite3_finalize(stmt);
    return n;
}

static int sqlite_group_load(void *ctx, const char *name,
                              char *description, size_t desc_len,
                              char *created_by, size_t cb_len)
{
    (void)ctx;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db,
        "SELECT description, created_by FROM groups WHERE name=?",
        -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }
    const char *d = (const char *)sqlite3_column_text(stmt, 0);
    const char *c = (const char *)sqlite3_column_text(stmt, 1);
    snprintf(description, desc_len, "%s", d ? d : "");
    snprintf(created_by, cb_len, "%s", c ? c : "");
    sqlite3_finalize(stmt);
    return 0;
}

static int sqlite_group_save(void *ctx, const char *name,
                              const char *description, const char *created_by)
{
    (void)ctx;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db,
        "INSERT OR REPLACE INTO groups (name, description, created_by) "
        "VALUES (?, ?, ?)",
        -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, description ? description : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, created_by ? created_by : "", -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    return rc;
}

static int sqlite_group_delete(void *ctx, const char *name)
{
    (void)ctx;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, "DELETE FROM groups WHERE name=?",
                            -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    return rc;
}

static int sqlite_config_get(void *ctx, const char *module, const char *key,
                              char *value, size_t val_len)
{
    (void)ctx;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db,
        "SELECT value FROM module_configs WHERE module=? AND key=?",
        -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(stmt, 1, module, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, key, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }
    const char *v = (const char *)sqlite3_column_text(stmt, 0);
    snprintf(value, val_len, "%s", v ? v : "");
    sqlite3_finalize(stmt);
    return 0;
}

static int sqlite_config_set(void *ctx, const char *module, const char *key,
                              const char *value)
{
    (void)ctx;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db,
        "INSERT OR REPLACE INTO module_configs (module, key, value) "
        "VALUES (?, ?, ?)",
        -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(stmt, 1, module, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, key, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, value, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    return rc;
}

static int sqlite_status(void *ctx, char *buf, size_t buf_len)
{
    (void)ctx;
    /* Get file size */
    long size = 0;
    FILE *f = fopen(g_db_path, "rb");
    if (f) { fseek(f, 0, SEEK_END); size = ftell(f); fclose(f); }

    snprintf(buf, buf_len,
        "SQLite Storage Backend\n"
        "File: %s\n"
        "Size: %ldKB\n"
        "Status: %s\n",
        g_db_path, size / 1024,
        g_db ? "open" : "closed");
    return 0;
}

static portal_storage_provider_t g_provider = {
    .name         = "sqlite",
    .user_list    = sqlite_user_list,
    .user_load    = sqlite_user_load,
    .user_save    = sqlite_user_save,
    .user_delete  = sqlite_user_delete,
    .group_list   = sqlite_group_list,
    .group_load   = sqlite_group_load,
    .group_save   = sqlite_group_save,
    .group_delete = sqlite_group_delete,
    .config_get   = sqlite_config_get,
    .config_set   = sqlite_config_set,
    .status       = sqlite_status,
    .ctx          = NULL
};

/* --- Module lifecycle --- */

int portal_module_load(portal_core_t *core)
{
    g_core = core;

    /* Read config */
    const char *db_path = core->config_get(core, "config_sqlite", "database");
    if (db_path)
        snprintf(g_db_path, sizeof(g_db_path), "%s", db_path);

    /* Default: <data_dir>/portal.db */
    if (g_db_path[0] == '\0') {
        const char *data_dir = core->config_get(core, "core", "data_dir");
        if (data_dir)
            snprintf(g_db_path, sizeof(g_db_path), "%s/portal.db", data_dir);
        else
            snprintf(g_db_path, sizeof(g_db_path), "/etc/portal/portal.db");
    }

    core->log(core, PORTAL_LOG_INFO, "sqlite", "Opening %s", g_db_path);

    if (sqlite3_open(g_db_path, &g_db) != SQLITE_OK) {
        core->log(core, PORTAL_LOG_ERROR, "sqlite",
                  "Cannot open: %s", sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        g_db = NULL;
        return PORTAL_MODULE_FAIL;
    }

    /* Enable WAL mode for better concurrency */
    sqlite3_exec(g_db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);

    if (ensure_tables() < 0) {
        sqlite3_close(g_db);
        g_db = NULL;
        return PORTAL_MODULE_FAIL;
    }

    /* Register as core storage provider */
    core->storage_register(core, &g_provider);

    core->log(core, PORTAL_LOG_INFO, "sqlite", "SQLite storage backend ready");
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
    }

    core->log(core, PORTAL_LOG_INFO, "sqlite", "SQLite backend closed");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    /* Transparent — no paths */
    (void)core; (void)msg;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
