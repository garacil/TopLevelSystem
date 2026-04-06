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
 * mod_file — Filesystem operations
 *
 * Read, write, list, delete, info for files within a sandboxed base directory.
 * Prevents path traversal attacks (no ..).
 * All operations restricted to the configured base_dir.
 *
 * Config:
 *   [mod_file]
 *   base_dir = /var/lib/portal/files
 *   max_file_size = 10485760
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include "portal/portal.h"

#define FILE_MAX_SIZE    (10 * 1024 * 1024)  /* 10 MB default */
#define FILE_BUF_SIZE    8192

static portal_core_t *g_core = NULL;
static char  g_base_dir[512] = "/var/lib/portal/files";
static size_t g_max_size = FILE_MAX_SIZE;
static int64_t g_reads = 0;
static int64_t g_writes = 0;
static int64_t g_deletes = 0;

static portal_module_info_t info = {
    .name = "file", .version = "1.0.0",
    .description = "Filesystem operations (sandboxed)",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

/* Security: build safe path, reject traversal */
static int safe_path(const char *name, char *out, size_t outlen)
{
    if (!name || name[0] == '\0') return -1;
    if (strstr(name, "..")) return -1;
    if (name[0] == '/') return -1;
    snprintf(out, outlen, "%s/%s", g_base_dir, name);
    return 0;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_reads = g_writes = g_deletes = 0;

    const char *v;
    if ((v = core->config_get(core, "file", "base_dir")))
        snprintf(g_base_dir, sizeof(g_base_dir), "%s", v);
    if ((v = core->config_get(core, "file", "max_file_size")))
        g_max_size = (size_t)atol(v);

    /* Ensure base dir exists */
    mkdir(g_base_dir, 0755);

    core->path_register(core, "/file/resources/status", "file");
    core->path_set_access(core, "/file/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/file/functions/read", "file");
    core->path_set_access(core, "/file/functions/read", PORTAL_ACCESS_RW);
    core->path_register(core, "/file/functions/write", "file");
    core->path_set_access(core, "/file/functions/write", PORTAL_ACCESS_RW);
    core->path_register(core, "/file/functions/list", "file");
    core->path_set_access(core, "/file/functions/list", PORTAL_ACCESS_RW);
    core->path_register(core, "/file/functions/delete", "file");
    core->path_set_access(core, "/file/functions/delete", PORTAL_ACCESS_RW);
    core->path_register(core, "/file/functions/info", "file");
    core->path_set_access(core, "/file/functions/info", PORTAL_ACCESS_RW);
    core->path_register(core, "/file/functions/mkdir", "file");
    core->path_set_access(core, "/file/functions/mkdir", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "file",
              "File module ready (base: %s, max: %zu bytes)",
              g_base_dir, g_max_size);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/file/resources/status");
    core->path_unregister(core, "/file/functions/read");
    core->path_unregister(core, "/file/functions/write");
    core->path_unregister(core, "/file/functions/list");
    core->path_unregister(core, "/file/functions/delete");
    core->path_unregister(core, "/file/functions/info");
    core->path_unregister(core, "/file/functions/mkdir");
    core->log(core, PORTAL_LOG_INFO, "file", "File module unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[FILE_BUF_SIZE];
    char fpath[1024];
    int n;

    if (strcmp(msg->path, "/file/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "File Module\n"
            "Base dir: %s\n"
            "Max file size: %zu bytes\n"
            "Reads: %lld\n"
            "Writes: %lld\n"
            "Deletes: %lld\n",
            g_base_dir, g_max_size,
            (long long)g_reads, (long long)g_writes, (long long)g_deletes);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/file/functions/read") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name || safe_path(name, fpath, sizeof(fpath)) < 0) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: name header (no .. allowed)\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        FILE *f = fopen(fpath, "rb");
        if (!f) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            n = snprintf(buf, sizeof(buf), "File not found: %s\n", name);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (sz < 0 || (size_t)sz > g_max_size) {
            fclose(f);
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "File too large\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        char *data = malloc((size_t)sz + 1);
        size_t rd = fread(data, 1, (size_t)sz, f);
        fclose(f);
        data[rd] = '\0';
        g_reads++;
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, data, rd);
        free(data);
        return 0;
    }

    if (strcmp(msg->path, "/file/functions/write") == 0) {
        const char *name = get_hdr(msg, "name");
        const char *data = msg->body ? msg->body : get_hdr(msg, "data");
        if (!name || safe_path(name, fpath, sizeof(fpath)) < 0) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: name header (no .. allowed)\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (!data) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: body or data header\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        size_t dlen = msg->body ? msg->body_len : strlen(data);
        if (dlen > g_max_size) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Data too large (%zu > %zu)\n",
                         dlen, g_max_size);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        FILE *f = fopen(fpath, "wb");
        if (!f) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            n = snprintf(buf, sizeof(buf), "Cannot write: %s\n", strerror(errno));
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        fwrite(data, 1, dlen, f);
        fclose(f);
        g_writes++;
        core->event_emit(core, "/events/file/write", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Written %zu bytes to %s\n", dlen, name);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/file/functions/list") == 0) {
        const char *dir = get_hdr(msg, "dir");
        char dpath[1024];
        if (dir) {
            if (safe_path(dir, dpath, sizeof(dpath)) < 0) {
                portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
                return -1;
            }
        } else {
            snprintf(dpath, sizeof(dpath), "%s", g_base_dir);
        }
        DIR *d = opendir(dpath);
        if (!d) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            n = snprintf(buf, sizeof(buf), "Cannot open directory\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        size_t off = 0;
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL && off < sizeof(buf) - 256) {
            if (ent->d_name[0] == '.') continue;
            struct stat st;
            char full[1280];
            snprintf(full, sizeof(full), "%s/%s", dpath, ent->d_name);
            if (stat(full, &st) == 0) {
                const char *type = S_ISDIR(st.st_mode) ? "dir" : "file";
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "%-4s %8ld  %s\n", type, (long)st.st_size, ent->d_name);
            }
        }
        closedir(d);
        if (off == 0)
            off = (size_t)snprintf(buf, sizeof(buf), "(empty)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/file/functions/delete") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name || safe_path(name, fpath, sizeof(fpath)) < 0) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
        if (unlink(fpath) < 0) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            n = snprintf(buf, sizeof(buf), "Cannot delete: %s\n", strerror(errno));
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        g_deletes++;
        core->event_emit(core, "/events/file/delete", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Deleted %s\n", name);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/file/functions/info") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name || safe_path(name, fpath, sizeof(fpath)) < 0) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
        struct stat st;
        if (stat(fpath, &st) < 0) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            return -1;
        }
        n = snprintf(buf, sizeof(buf),
            "Name: %s\n"
            "Size: %ld bytes\n"
            "Type: %s\n"
            "Modified: %s"
            "Permissions: %o\n",
            name, (long)st.st_size,
            S_ISDIR(st.st_mode) ? "directory" : "file",
            ctime(&st.st_mtime),
            (unsigned)(st.st_mode & 0777));
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/file/functions/mkdir") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name || safe_path(name, fpath, sizeof(fpath)) < 0) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
        if (mkdir(fpath, 0755) < 0 && errno != EEXIST) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            n = snprintf(buf, sizeof(buf), "Cannot create: %s\n", strerror(errno));
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        core->event_emit(core, "/events/file/mkdir", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_CREATED);
        n = snprintf(buf, sizeof(buf), "Directory created: %s\n", name);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
