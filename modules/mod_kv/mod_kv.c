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
 * mod_kv — Persistent key-value store
 *
 * File-backed key-value store that survives restarts.
 * Keys stored as individual files in a directory.
 * Thread-safe, suitable for configuration and state storage.
 *
 * Config:
 *   [mod_kv]
 *   data_dir = /var/lib/portal/kv
 *   max_key_size = 256
 *   max_value_size = 1048576
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include "portal/portal.h"

#define KV_MAX_KEY     256
#define KV_MAX_VALUE   (1024 * 1024)  /* 1 MB */

static portal_core_t *g_core = NULL;
static char  g_dir[512] = "/var/lib/portal/kv";
static size_t g_max_value = KV_MAX_VALUE;
static int64_t g_gets = 0;
static int64_t g_sets = 0;
static int64_t g_dels = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static portal_module_info_t info = {
    .name = "kv", .version = "1.0.0",
    .description = "Persistent key-value store (file-backed)",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

/* Security: validate key name (no path traversal) */
static int valid_key(const char *key)
{
    if (!key || key[0] == '\0' || strlen(key) > KV_MAX_KEY) return 0;
    if (strstr(key, "..") || strchr(key, '/') || key[0] == '.') return 0;
    return 1;
}

static int kv_path(const char *key, char *out, size_t len)
{
    if (!valid_key(key)) return -1;
    snprintf(out, len, "%s/%s", g_dir, key);
    return 0;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_gets = g_sets = g_dels = 0;

    const char *v;
    if ((v = core->config_get(core, "kv", "data_dir")))
        snprintf(g_dir, sizeof(g_dir), "%s", v);
    if ((v = core->config_get(core, "kv", "max_value_size")))
        g_max_value = (size_t)atol(v);

    mkdir(g_dir, 0755);

    core->path_register(core, "/kv/resources/status", "kv");
    core->path_set_access(core, "/kv/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/kv/resources/status", "Key-value store: key count, storage path");
    core->path_register(core, "/kv/resources/keys", "kv");
    core->path_set_access(core, "/kv/resources/keys", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/kv/resources/keys", "List all persistent keys");
    core->path_register(core, "/kv/functions/get", "kv");
    core->path_set_access(core, "/kv/functions/get", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/kv/functions/get", "Get persistent key. Header: key");
    core->path_register(core, "/kv/functions/set", "kv");
    core->path_set_access(core, "/kv/functions/set", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/kv/functions/set", "Set persistent key. Headers: key, value");
    core->path_register(core, "/kv/functions/del", "kv");
    core->path_set_access(core, "/kv/functions/del", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/kv/functions/del", "Delete persistent key. Header: key");
    core->path_register(core, "/kv/functions/exists", "kv");
    core->path_set_access(core, "/kv/functions/exists", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "kv",
              "KV store ready (dir: %s, max value: %zu bytes)", g_dir, g_max_value);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/kv/resources/status");
    core->path_unregister(core, "/kv/resources/keys");
    core->path_unregister(core, "/kv/functions/get");
    core->path_unregister(core, "/kv/functions/set");
    core->path_unregister(core, "/kv/functions/del");
    core->path_unregister(core, "/kv/functions/exists");
    core->log(core, PORTAL_LOG_INFO, "kv", "KV store unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[8192];
    char fpath[1024];
    int n;

    if (strcmp(msg->path, "/kv/resources/status") == 0) {
        /* Count keys */
        int count = 0;
        DIR *d = opendir(g_dir);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL)
                if (ent->d_name[0] != '.') count++;
            closedir(d);
        }
        n = snprintf(buf, sizeof(buf),
            "KV Store\n"
            "Directory: %s\n"
            "Keys: %d\n"
            "Max value size: %zu bytes\n"
            "Gets: %lld\n"
            "Sets: %lld\n"
            "Deletes: %lld\n",
            g_dir, count, g_max_value,
            (long long)g_gets, (long long)g_sets, (long long)g_dels);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/kv/resources/keys") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Keys:\n");
        DIR *d = opendir(g_dir);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL && off < sizeof(buf) - 256) {
                if (ent->d_name[0] == '.') continue;
                struct stat st;
                char fp[1024];
                snprintf(fp, sizeof(fp), "%s/%s", g_dir, ent->d_name);
                if (stat(fp, &st) == 0 && S_ISREG(st.st_mode)) {
                    off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                        "  %-32s %ld bytes\n", ent->d_name, (long)st.st_size);
                }
            }
            closedir(d);
        }
        if (off < 10)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (empty)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/kv/functions/get") == 0) {
        const char *key = get_hdr(msg, "key");
        if (!key || kv_path(key, fpath, sizeof(fpath)) < 0) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: key header (no . or / or ..)\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        pthread_mutex_lock(&g_lock);
        FILE *f = fopen(fpath, "rb");
        if (!f) {
            pthread_mutex_unlock(&g_lock);
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            n = snprintf(buf, sizeof(buf), "Key not found: %s\n", key);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        char *data = malloc((size_t)sz + 1);
        size_t rd = fread(data, 1, (size_t)sz, f);
        fclose(f);
        pthread_mutex_unlock(&g_lock);
        data[rd] = '\0';
        g_gets++;
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, data, rd);
        free(data);
        return 0;
    }

    if (strcmp(msg->path, "/kv/functions/set") == 0) {
        const char *key = get_hdr(msg, "key");
        const char *value = msg->body ? msg->body : get_hdr(msg, "value");
        if (!key || kv_path(key, fpath, sizeof(fpath)) < 0) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: key header\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (!value) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: value header or body\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        size_t vlen = msg->body ? msg->body_len : strlen(value);
        if (vlen > g_max_value) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Value too large (%zu > %zu)\n",
                         vlen, g_max_value);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        pthread_mutex_lock(&g_lock);
        FILE *f = fopen(fpath, "wb");
        if (!f) {
            pthread_mutex_unlock(&g_lock);
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            n = snprintf(buf, sizeof(buf), "Write error: %s\n", strerror(errno));
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        fwrite(value, 1, vlen, f);
        fclose(f);
        pthread_mutex_unlock(&g_lock);
        g_sets++;
        core->event_emit(core, "/events/kv/set", key, strlen(key));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "OK (%zu bytes)\n", vlen);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/kv/functions/del") == 0) {
        const char *key = get_hdr(msg, "key");
        if (!key || kv_path(key, fpath, sizeof(fpath)) < 0) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
        pthread_mutex_lock(&g_lock);
        int rc = unlink(fpath);
        pthread_mutex_unlock(&g_lock);
        if (rc < 0) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            return -1;
        }
        g_dels++;
        core->event_emit(core, "/events/kv/del", key, strlen(key));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Deleted: %s\n", key);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/kv/functions/exists") == 0) {
        const char *key = get_hdr(msg, "key");
        if (!key || kv_path(key, fpath, sizeof(fpath)) < 0) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
        struct stat st;
        if (stat(fpath, &st) == 0) {
            portal_resp_set_status(resp, PORTAL_OK);
            n = snprintf(buf, sizeof(buf), "true\n");
        } else {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            n = snprintf(buf, sizeof(buf), "false\n");
        }
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
