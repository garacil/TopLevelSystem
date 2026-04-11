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
 * mod_config_psql — PostgreSQL Storage Backend
 *
 * Provides persistent storage for users, groups, and module configs
 * via PostgreSQL. Transparent to the core — registers as a storage
 * provider that the core queries alongside file-based storage.
 *
 * Config:
 *   [mod_config_psql]
 *   host = 192.168.1.87
 *   port = 5433
 *   user = ivoip
 *   password =
 *   database = devportal_conf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libpq-fe.h>

#include "portal/portal.h"
#include "portal/storage.h"

#define PSQL_DEFAULT_HOST "localhost"
#define PSQL_DEFAULT_PORT "5432"
#define PSQL_DEFAULT_USER "portal"
#define PSQL_DEFAULT_DB   "portal_conf"

static portal_core_t *g_core = NULL;
static PGconn        *g_conn = NULL;
static char           g_host[256]  = PSQL_DEFAULT_HOST;
static char           g_port[16]   = PSQL_DEFAULT_PORT;
static char           g_user[128]  = PSQL_DEFAULT_USER;
static char           g_pass[128]  = "";
static char           g_dbname[128] = PSQL_DEFAULT_DB;

static portal_module_info_t mod_info = {
    .name        = "config_psql",
    .version     = "0.5.0",
    .description = "PostgreSQL storage backend",
    .soft_deps   = NULL
};

portal_module_info_t *portal_module_info(void) { return &mod_info; }

/* --- Database helpers --- */

static int pg_exec(const char *sql)
{
    PGresult *res = PQexec(g_conn, sql);
    ExecStatusType status = PQresultStatus(res);
    if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "psql", "SQL error: %s\nQuery: %s",
                    PQerrorMessage(g_conn), sql);
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

static int ensure_database(void)
{
    /* Connect to 'postgres' database first to check/create our database */
    char conninfo[1024];
    if (g_pass[0])
        snprintf(conninfo, sizeof(conninfo),
                 "host=%s port=%s user=%s password=%s dbname=postgres",
                 g_host, g_port, g_user, g_pass);
    else
        snprintf(conninfo, sizeof(conninfo),
                 "host=%s port=%s user=%s dbname=postgres",
                 g_host, g_port, g_user);

    PGconn *admin_conn = PQconnectdb(conninfo);
    if (PQstatus(admin_conn) != CONNECTION_OK) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "psql",
                    "Cannot connect to postgres: %s", PQerrorMessage(admin_conn));
        PQfinish(admin_conn);
        return -1;
    }

    /* Check if database exists */
    char query[256];
    snprintf(query, sizeof(query),
             "SELECT 1 FROM pg_database WHERE datname='%s'", g_dbname);
    PGresult *res = PQexec(admin_conn, query);

    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 0) {
        PQclear(res);
        /* Create database */
        snprintf(query, sizeof(query), "CREATE DATABASE %s", g_dbname);
        res = PQexec(admin_conn, query);
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            g_core->log(g_core, PORTAL_LOG_ERROR, "psql",
                        "Cannot create database: %s", PQerrorMessage(admin_conn));
            PQclear(res);
            PQfinish(admin_conn);
            return -1;
        }
        g_core->log(g_core, PORTAL_LOG_INFO, "psql",
                    "Created database '%s'", g_dbname);
    }
    PQclear(res);
    PQfinish(admin_conn);
    return 0;
}

static int ensure_tables(void)
{
    const char *ddl[] = {
        "CREATE TABLE IF NOT EXISTS users ("
        "  username VARCHAR(64) PRIMARY KEY,"
        "  password VARCHAR(256) DEFAULT '',"
        "  api_key VARCHAR(65) DEFAULT '',"
        "  groups TEXT DEFAULT '',"
        "  created_at TIMESTAMP DEFAULT NOW(),"
        "  updated_at TIMESTAMP DEFAULT NOW()"
        ")",

        "CREATE TABLE IF NOT EXISTS groups ("
        "  name VARCHAR(64) PRIMARY KEY,"
        "  description TEXT DEFAULT '',"
        "  created_by VARCHAR(64) DEFAULT '',"
        "  created_at TIMESTAMP DEFAULT NOW()"
        ")",

        "CREATE TABLE IF NOT EXISTS module_configs ("
        "  module VARCHAR(64),"
        "  key VARCHAR(128),"
        "  value TEXT DEFAULT '',"
        "  PRIMARY KEY (module, key)"
        ")",

        NULL
    };

    for (int i = 0; ddl[i]; i++) {
        if (pg_exec(ddl[i]) < 0)
            return -1;
    }

    g_core->log(g_core, PORTAL_LOG_DEBUG, "psql", "Tables verified");
    return 0;
}

/* --- Storage provider implementation --- */

static int psql_user_list(void *ctx, storage_list_fn cb, void *userdata)
{
    (void)ctx;
    PGresult *res = PQexec(g_conn,
        "SELECT username FROM users ORDER BY username");
    if (PQresultStatus(res) != PGRES_TUPLES_OK) { PQclear(res); return -1; }

    int n = PQntuples(res);
    for (int i = 0; i < n; i++)
        cb(PQgetvalue(res, i, 0), userdata);

    PQclear(res);
    return n;
}

static int psql_user_load(void *ctx, const char *username,
                           char *password, size_t pass_len,
                           char *api_key, size_t key_len,
                           char *groups, size_t groups_len)
{
    (void)ctx;
    const char *params[1] = { username };
    PGresult *res = PQexecParams(g_conn,
        "SELECT password, api_key, groups FROM users WHERE username=$1",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return -1;
    }

    snprintf(password, pass_len, "%s", PQgetvalue(res, 0, 0));
    snprintf(api_key, key_len, "%s", PQgetvalue(res, 0, 1));
    snprintf(groups, groups_len, "%s", PQgetvalue(res, 0, 2));

    PQclear(res);
    return 0;
}

static int psql_user_save(void *ctx, const char *username,
                           const char *password, const char *api_key,
                           const char *groups)
{
    (void)ctx;
    const char *params[4] = { username, password ? password : "",
                               api_key ? api_key : "",
                               groups ? groups : "" };
    PGresult *res = PQexecParams(g_conn,
        "INSERT INTO users (username, password, api_key, groups, updated_at) "
        "VALUES ($1, $2, $3, $4, NOW()) "
        "ON CONFLICT (username) DO UPDATE SET "
        "password=$2, api_key=$3, groups=$4, updated_at=NOW()",
        4, NULL, params, NULL, NULL, 0);

    int ok = PQresultStatus(res) == PGRES_COMMAND_OK;
    PQclear(res);
    return ok ? 0 : -1;
}

static int psql_user_delete(void *ctx, const char *username)
{
    (void)ctx;
    const char *params[1] = { username };
    PGresult *res = PQexecParams(g_conn,
        "DELETE FROM users WHERE username=$1",
        1, NULL, params, NULL, NULL, 0);
    int ok = PQresultStatus(res) == PGRES_COMMAND_OK;
    PQclear(res);
    return ok ? 0 : -1;
}

static int psql_group_list(void *ctx, storage_list_fn cb, void *userdata)
{
    (void)ctx;
    PGresult *res = PQexec(g_conn,
        "SELECT name FROM groups ORDER BY name");
    if (PQresultStatus(res) != PGRES_TUPLES_OK) { PQclear(res); return -1; }

    int n = PQntuples(res);
    for (int i = 0; i < n; i++)
        cb(PQgetvalue(res, i, 0), userdata);

    PQclear(res);
    return n;
}

static int psql_group_load(void *ctx, const char *name,
                            char *description, size_t desc_len,
                            char *created_by, size_t cb_len)
{
    (void)ctx;
    const char *params[1] = { name };
    PGresult *res = PQexecParams(g_conn,
        "SELECT description, created_by FROM groups WHERE name=$1",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return -1;
    }

    snprintf(description, desc_len, "%s", PQgetvalue(res, 0, 0));
    snprintf(created_by, cb_len, "%s", PQgetvalue(res, 0, 1));

    PQclear(res);
    return 0;
}

static int psql_group_save(void *ctx, const char *name,
                            const char *description, const char *created_by)
{
    (void)ctx;
    const char *params[3] = { name, description ? description : "",
                               created_by ? created_by : "" };
    PGresult *res = PQexecParams(g_conn,
        "INSERT INTO groups (name, description, created_by) "
        "VALUES ($1, $2, $3) "
        "ON CONFLICT (name) DO UPDATE SET description=$2",
        3, NULL, params, NULL, NULL, 0);
    int ok = PQresultStatus(res) == PGRES_COMMAND_OK;
    PQclear(res);
    return ok ? 0 : -1;
}

static int psql_group_delete(void *ctx, const char *name)
{
    (void)ctx;
    const char *params[1] = { name };
    PGresult *res = PQexecParams(g_conn,
        "DELETE FROM groups WHERE name=$1",
        1, NULL, params, NULL, NULL, 0);
    int ok = PQresultStatus(res) == PGRES_COMMAND_OK;
    PQclear(res);
    return ok ? 0 : -1;
}

static int psql_config_get(void *ctx, const char *module, const char *key,
                            char *value, size_t val_len)
{
    (void)ctx;
    const char *params[2] = { module, key };
    PGresult *res = PQexecParams(g_conn,
        "SELECT value FROM module_configs WHERE module=$1 AND key=$2",
        2, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return -1;
    }

    snprintf(value, val_len, "%s", PQgetvalue(res, 0, 0));
    PQclear(res);
    return 0;
}

static int psql_config_set(void *ctx, const char *module, const char *key,
                            const char *value)
{
    (void)ctx;
    const char *params[3] = { module, key, value };
    PGresult *res = PQexecParams(g_conn,
        "INSERT INTO module_configs (module, key, value) "
        "VALUES ($1, $2, $3) "
        "ON CONFLICT (module, key) DO UPDATE SET value=$3",
        3, NULL, params, NULL, NULL, 0);
    int ok = PQresultStatus(res) == PGRES_COMMAND_OK;
    PQclear(res);
    return ok ? 0 : -1;
}

static int psql_status(void *ctx, char *buf, size_t buf_len)
{
    (void)ctx;
    snprintf(buf, buf_len,
        "PostgreSQL Storage Backend\n"
        "Host: %s:%s\n"
        "Database: %s\n"
        "User: %s\n"
        "Status: %s\n",
        g_host, g_port, g_dbname, g_user,
        (g_conn && PQstatus(g_conn) == CONNECTION_OK) ? "connected" : "disconnected");
    return 0;
}

/* Storage provider — available for core to query */
portal_storage_provider_t g_provider = {
    .name         = "psql",
    .user_list    = psql_user_list,
    .user_load    = psql_user_load,
    .user_save    = psql_user_save,
    .user_delete  = psql_user_delete,
    .group_list   = psql_group_list,
    .group_load   = psql_group_load,
    .group_save   = psql_group_save,
    .group_delete = psql_group_delete,
    .config_get   = psql_config_get,
    .config_set   = psql_config_set,
    .status       = psql_status,
    .ctx          = NULL
};

/* --- Module lifecycle --- */

int portal_module_load(portal_core_t *core)
{
    g_core = core;

    /* Read config */
    const char *v;
    if ((v = core->config_get(core, "config_psql", "host")))
        snprintf(g_host, sizeof(g_host), "%s", v);
    if ((v = core->config_get(core, "config_psql", "port")))
        snprintf(g_port, sizeof(g_port), "%s", v);
    if ((v = core->config_get(core, "config_psql", "user")))
        snprintf(g_user, sizeof(g_user), "%s", v);
    if ((v = core->config_get(core, "config_psql", "password")))
        snprintf(g_pass, sizeof(g_pass), "%s", v);
    if ((v = core->config_get(core, "config_psql", "database")))
        snprintf(g_dbname, sizeof(g_dbname), "%s", v);

    core->log(core, PORTAL_LOG_INFO, "psql",
              "Connecting to %s:%s/%s as %s", g_host, g_port, g_dbname, g_user);

    /* Ensure database exists */
    if (ensure_database() < 0) {
        core->log(core, PORTAL_LOG_WARN, "psql",
                  "Could not ensure database — trying direct connect");
    }

    /* Connect to our database */
    char conninfo[1024];
    if (g_pass[0])
        snprintf(conninfo, sizeof(conninfo),
                 "host=%s port=%s user=%s password=%s dbname=%s",
                 g_host, g_port, g_user, g_pass, g_dbname);
    else
        snprintf(conninfo, sizeof(conninfo),
                 "host=%s port=%s user=%s dbname=%s",
                 g_host, g_port, g_user, g_dbname);

    g_conn = PQconnectdb(conninfo);
    if (PQstatus(g_conn) != CONNECTION_OK) {
        core->log(core, PORTAL_LOG_ERROR, "psql",
                  "Connection failed: %s", PQerrorMessage(g_conn));
        PQfinish(g_conn);
        g_conn = NULL;
        return PORTAL_MODULE_FAIL;
    }

    core->log(core, PORTAL_LOG_INFO, "psql",
              "Connected to PostgreSQL %s:%s/%s", g_host, g_port, g_dbname);

    /* Create tables */
    if (ensure_tables() < 0) {
        PQfinish(g_conn);
        g_conn = NULL;
        return PORTAL_MODULE_FAIL;
    }

    /* Register as core storage provider (transparent — no own paths) */
    core->storage_register(core, &g_provider);

    core->log(core, PORTAL_LOG_INFO, "psql",
              "PostgreSQL storage backend ready");
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    if (g_conn) {
        PQfinish(g_conn);
        g_conn = NULL;
    }

    /* Deregister as storage provider */
    core->storage_register(core, NULL);

    core->log(core, PORTAL_LOG_INFO, "psql", "PostgreSQL backend disconnected");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    /* This module is transparent — no paths to handle */
    (void)core; (void)msg;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
