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
 * mod_log — Log viewer and searcher
 *
 * Access Portal instance logs via the path system.
 * Tail, search by pattern, list log files, rotate.
 *
 * Config:
 *   [mod_log]
 *   log_dir = /var/log/portal
 *   max_lines = 500
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include "portal/portal.h"

#define LOG_MAX_LINES  500
#define LOG_LINE_SIZE  1024

static portal_core_t *g_core = NULL;
static char  g_dir[512] = "/var/log/portal";
static int   g_max_lines = LOG_MAX_LINES;
static int64_t g_queries = 0;

static portal_module_info_t info = {
    .name = "log", .version = "1.0.0",
    .description = "Log viewer and searcher",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

/* Tail last N lines of a file */
static size_t tail_file(const char *path, int lines, char *out, size_t outlen)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    /* Count total lines */
    int total = 0;
    char line[LOG_LINE_SIZE];
    while (fgets(line, sizeof(line), f)) total++;

    int skip = total - lines;
    if (skip < 0) skip = 0;

    fseek(f, 0, SEEK_SET);
    int cur = 0;
    size_t off = 0;
    while (fgets(line, sizeof(line), f)) {
        if (cur++ < skip) continue;
        size_t ll = strlen(line);
        if (off + ll >= outlen - 1) break;
        memcpy(out + off, line, ll);
        off += ll;
    }
    fclose(f);
    out[off] = '\0';
    return off;
}

/* Search for pattern in file */
static size_t search_file(const char *path, const char *pattern,
                           int max, char *out, size_t outlen)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    size_t off = 0;
    int found = 0;
    char line[LOG_LINE_SIZE];
    while (fgets(line, sizeof(line), f) && found < max) {
        if (strstr(line, pattern)) {
            size_t ll = strlen(line);
            if (off + ll >= outlen - 1) break;
            memcpy(out + off, line, ll);
            off += ll;
            found++;
        }
    }
    fclose(f);
    out[off] = '\0';
    return off;
}

/* Find latest log file in directory */
static int find_latest_log(char *path, size_t plen)
{
    DIR *d = opendir(g_dir);
    if (!d) return -1;

    time_t newest = 0;
    char best[256] = "";
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char full[768];
        snprintf(full, sizeof(full), "%s/%s", g_dir, ent->d_name);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISREG(st.st_mode) && st.st_mtime > newest) {
            newest = st.st_mtime;
            snprintf(best, sizeof(best), "%s", ent->d_name);
        }
    }
    closedir(d);
    if (best[0]) { snprintf(path, plen, "%s/%s", g_dir, best); return 0; }
    return -1;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_queries = 0;

    const char *v;
    if ((v = core->config_get(core, "log", "log_dir")))
        snprintf(g_dir, sizeof(g_dir), "%s", v);
    if ((v = core->config_get(core, "log", "max_lines")))
        g_max_lines = atoi(v);

    core->path_register(core, "/log/resources/status", "log");
    core->path_set_access(core, "/log/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/log/resources/tail", "log");
    core->path_set_access(core, "/log/resources/tail", PORTAL_ACCESS_READ);
    core->path_register(core, "/log/resources/files", "log");
    core->path_set_access(core, "/log/resources/files", PORTAL_ACCESS_READ);
    core->path_register(core, "/log/functions/search", "log");
    core->path_set_access(core, "/log/functions/search", PORTAL_ACCESS_RW);
    core->path_register(core, "/log/functions/rotate", "log");
    core->path_set_access(core, "/log/functions/rotate", PORTAL_ACCESS_RW);
    core->path_add_label(core, "/log/functions/rotate", "admin");

    core->log(core, PORTAL_LOG_INFO, "log",
              "Log viewer ready (dir: %s, max: %d lines)", g_dir, g_max_lines);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/log/resources/status");
    core->path_unregister(core, "/log/resources/tail");
    core->path_unregister(core, "/log/resources/files");
    core->path_unregister(core, "/log/functions/search");
    core->path_unregister(core, "/log/functions/rotate");
    core->log(core, PORTAL_LOG_INFO, "log", "Log viewer unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[65536];
    int n;
    g_queries++;

    if (strcmp(msg->path, "/log/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "Log Viewer\nDirectory: %s\nMax lines: %d\nQueries: %lld\n",
            g_dir, g_max_lines, (long long)g_queries);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/log/resources/files") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Log Files:\n");
        DIR *d = opendir(g_dir);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL && off < sizeof(buf) - 256) {
                if (ent->d_name[0] == '.') continue;
                char full[768];
                snprintf(full, sizeof(full), "%s/%s", g_dir, ent->d_name);
                struct stat st;
                if (stat(full, &st) == 0 && S_ISREG(st.st_mode)) {
                    char ts[32];
                    struct tm tm;
                    localtime_r(&st.st_mtime, &tm);
                    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M", &tm);
                    off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                        "  %-30s %8ld bytes  %s\n",
                        ent->d_name, (long)st.st_size, ts);
                }
            }
            closedir(d);
        }
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/log/resources/tail") == 0) {
        const char *file = get_hdr(msg, "file");
        const char *lines_s = get_hdr(msg, "lines");
        int lines = lines_s ? atoi(lines_s) : 50;
        if (lines > g_max_lines) lines = g_max_lines;

        char path[768];
        if (file) {
            if (strstr(file, "..")) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
            snprintf(path, sizeof(path), "%s/%s", g_dir, file);
        } else {
            if (find_latest_log(path, sizeof(path)) < 0) {
                portal_resp_set_status(resp, PORTAL_NOT_FOUND);
                n = snprintf(buf, sizeof(buf), "No log files found in %s\n", g_dir);
                portal_resp_set_body(resp, buf, (size_t)n);
                return -1;
            }
        }

        size_t len = tail_file(path, lines, buf, sizeof(buf));
        if (len == 0) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            n = snprintf(buf, sizeof(buf), "Log file empty or not found\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, len);
        return 0;
    }

    if (strcmp(msg->path, "/log/functions/search") == 0) {
        const char *pattern = get_hdr(msg, "pattern");
        const char *file = get_hdr(msg, "file");
        const char *max_s = get_hdr(msg, "max");
        if (!pattern) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: pattern header\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        int max = max_s ? atoi(max_s) : 100;

        char path[768];
        if (file) {
            if (strstr(file, "..")) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
            snprintf(path, sizeof(path), "%s/%s", g_dir, file);
        } else {
            if (find_latest_log(path, sizeof(path)) < 0) {
                portal_resp_set_status(resp, PORTAL_NOT_FOUND);
                return -1;
            }
        }

        size_t len = search_file(path, pattern, max, buf, sizeof(buf));
        if (len == 0) {
            n = snprintf(buf, sizeof(buf), "No matches for '%s'\n", pattern);
            len = (size_t)n;
        }
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, len);
        return 0;
    }

    if (strcmp(msg->path, "/log/functions/rotate") == 0) {
        char path[768];
        if (find_latest_log(path, sizeof(path)) < 0) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            return -1;
        }
        char newpath[1024];
        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);
        char ts[32];
        strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", &tm);
        snprintf(newpath, sizeof(newpath), "%s.%s", path, ts);
        if (rename(path, newpath) == 0) {
            core->event_emit(core, "/events/log/rotate", newpath, strlen(newpath));
            n = snprintf(buf, sizeof(buf), "Rotated → %s\n", newpath);
            portal_resp_set_status(resp, PORTAL_OK);
        } else {
            n = snprintf(buf, sizeof(buf), "Rotate failed\n");
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
        }
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
