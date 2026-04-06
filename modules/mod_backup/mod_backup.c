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
 * mod_backup — Instance backup and restore
 *
 * Create tar.gz backups of instance config, KV data, logic scripts.
 * Restore from backup archives. List available backups.
 *
 * Config:
 *   [mod_backup]
 *   backup_dir = /var/lib/portal/backups
 *   max_backups = 50
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <pthread.h>
#include "portal/portal.h"

#define BACKUP_MAX  50

static portal_core_t *g_core = NULL;
static char  g_dir[512] = "/var/lib/portal/backups";
static int   g_max = BACKUP_MAX;
static int64_t g_created = 0;
static int64_t g_restored = 0;

static portal_module_info_t info = {
    .name = "backup", .version = "1.0.0",
    .description = "Instance backup and restore",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_created = g_restored = 0;

    const char *v;
    if ((v = core->config_get(core, "backup", "backup_dir")))
        snprintf(g_dir, sizeof(g_dir), "%s", v);
    if ((v = core->config_get(core, "backup", "max_backups")))
        g_max = atoi(v);

    mkdir(g_dir, 0755);

    core->path_register(core, "/backup/resources/status", "backup");
    core->path_set_access(core, "/backup/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/backup/resources/list", "backup");
    core->path_set_access(core, "/backup/resources/list", PORTAL_ACCESS_READ);
    core->path_register(core, "/backup/functions/create", "backup");
    core->path_set_access(core, "/backup/functions/create", PORTAL_ACCESS_RW);
    core->path_add_label(core, "/backup/functions/create", "admin");
    core->path_register(core, "/backup/functions/restore", "backup");
    core->path_set_access(core, "/backup/functions/restore", PORTAL_ACCESS_RW);
    core->path_add_label(core, "/backup/functions/restore", "admin");
    core->path_register(core, "/backup/functions/delete", "backup");
    core->path_set_access(core, "/backup/functions/delete", PORTAL_ACCESS_RW);
    core->path_add_label(core, "/backup/functions/delete", "admin");

    core->log(core, PORTAL_LOG_INFO, "backup",
              "Backup module ready (dir: %s, max: %d)", g_dir, g_max);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/backup/resources/status");
    core->path_unregister(core, "/backup/resources/list");
    core->path_unregister(core, "/backup/functions/create");
    core->path_unregister(core, "/backup/functions/restore");
    core->path_unregister(core, "/backup/functions/delete");
    core->log(core, PORTAL_LOG_INFO, "backup", "Backup module unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

/* Background thread: create backup */
static void *backup_create_thread(void *arg)
{
    struct { char fpath[768]; char source[512]; char fname[256]; } *a = arg;
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "tar czf '%s' -C / '%s' 2>&1",
             a->fpath, a->source[0] == '/' ? a->source + 1 : a->source);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        char out[1024] = "";
        size_t rd = fread(out, 1, sizeof(out) - 1, fp);
        out[rd] = '\0';
        int status = pclose(fp);
        if (WEXITSTATUS(status) == 0) {
            g_created++;
            if (g_core) {
                g_core->event_emit(g_core, "/events/backup/create",
                                   a->fname, strlen(a->fname));
                g_core->log(g_core, PORTAL_LOG_INFO, "backup",
                            "Created %s from %s", a->fname, a->source);
            }
        } else if (g_core) {
            g_core->log(g_core, PORTAL_LOG_ERROR, "backup",
                        "Backup failed: %s", out);
        }
    }
    free(a);
    return NULL;
}

/* Background thread: restore backup */
static void *backup_restore_thread(void *arg)
{
    struct { char fpath[768]; char dest[512]; char name[256]; } *a = arg;
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "tar xzf '%s' -C '%s' 2>&1", a->fpath, a->dest);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        char out[1024] = "";
        size_t rd = fread(out, 1, sizeof(out) - 1, fp);
        out[rd] = '\0';
        int status = pclose(fp);
        if (WEXITSTATUS(status) == 0) {
            g_restored++;
            if (g_core) {
                g_core->event_emit(g_core, "/events/backup/restore",
                                   a->name, strlen(a->name));
                g_core->log(g_core, PORTAL_LOG_INFO, "backup",
                            "Restored %s to %s", a->name, a->dest);
            }
        } else if (g_core) {
            g_core->log(g_core, PORTAL_LOG_ERROR, "backup",
                        "Restore failed: %s", out);
        }
    }
    free(a);
    return NULL;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[8192];
    int n;

    if (strcmp(msg->path, "/backup/resources/status") == 0) {
        int count = 0;
        DIR *d = opendir(g_dir);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL)
                if (strstr(ent->d_name, ".tar.gz")) count++;
            closedir(d);
        }
        n = snprintf(buf, sizeof(buf),
            "Backup Module\n"
            "Directory: %s\n"
            "Backups: %d (max %d)\n"
            "Created: %lld\n"
            "Restored: %lld\n",
            g_dir, count, g_max,
            (long long)g_created, (long long)g_restored);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/backup/resources/list") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Backups:\n");
        DIR *d = opendir(g_dir);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL && off < sizeof(buf) - 256) {
                if (!strstr(ent->d_name, ".tar.gz")) continue;
                char full[768];
                snprintf(full, sizeof(full), "%s/%s", g_dir, ent->d_name);
                struct stat st;
                if (stat(full, &st) == 0) {
                    char ts[32];
                    struct tm tm;
                    localtime_r(&st.st_mtime, &tm);
                    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M", &tm);
                    off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                        "  %-40s %8ld bytes  %s\n",
                        ent->d_name, (long)st.st_size, ts);
                }
            }
            closedir(d);
        }
        if (off < 20)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/backup/functions/create") == 0) {
        const char *name = get_hdr(msg, "name");
        const char *source = get_hdr(msg, "source");

        char ts[32];
        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);
        strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", &tm);

        typedef struct { char fpath[768]; char source[512]; char fname[256]; } backup_arg_t;
        backup_arg_t *a = malloc(sizeof(*a));
        if (name) snprintf(a->fname, sizeof(a->fname), "%s.tar.gz", name);
        else snprintf(a->fname, sizeof(a->fname), "backup_%s.tar.gz", ts);
        if (!source) source = "/etc/portal";
        snprintf(a->source, sizeof(a->source), "%s", source);
        snprintf(a->fpath, sizeof(a->fpath), "%s/%s", g_dir, a->fname);

        pthread_t th;
        pthread_create(&th, NULL, backup_create_thread, a);
        pthread_detach(th);
        n = snprintf(buf, sizeof(buf), "Creating backup %s in background...\n", a->fname);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/backup/functions/restore") == 0) {
        const char *name = get_hdr(msg, "name");
        const char *dest = get_hdr(msg, "dest");
        if (!name) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: name header\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (strstr(name, "..")) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        if (!dest) dest = "/";

        char fpath[768];
        snprintf(fpath, sizeof(fpath), "%s/%s", g_dir, name);
        struct stat st;
        if (stat(fpath, &st) < 0) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            n = snprintf(buf, sizeof(buf), "Backup not found: %s\n", name);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        typedef struct { char fpath[768]; char dest[512]; char name[256]; } restore_arg_t;
        restore_arg_t *a = malloc(sizeof(*a));
        snprintf(a->fpath, sizeof(a->fpath), "%s", fpath);
        snprintf(a->dest, sizeof(a->dest), "%s", dest);
        snprintf(a->name, sizeof(a->name), "%s", name);

        pthread_t th;
        pthread_create(&th, NULL, backup_restore_thread, a);
        pthread_detach(th);
        n = snprintf(buf, sizeof(buf), "Restoring %s in background...\n", name);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/backup/functions/delete") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name || strstr(name, "..")) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
        char fpath[768];
        snprintf(fpath, sizeof(fpath), "%s/%s", g_dir, name);
        if (unlink(fpath) < 0) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            return -1;
        }
        core->event_emit(core, "/events/backup/delete", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Deleted: %s\n", name);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
