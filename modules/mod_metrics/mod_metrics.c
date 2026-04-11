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
 * mod_metrics — System metrics collection
 *
 * Reads system metrics from /proc on Linux:
 * CPU usage, memory, disk, load average, uptime.
 * All exposed as read-only resources.
 *
 * Config:
 *   [mod_metrics]
 *   (none required)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include "portal/portal.h"

static portal_core_t *g_core = NULL;
static int64_t g_queries = 0;

static portal_module_info_t info = {
    .name = "metrics", .version = "1.0.0",
    .description = "System metrics (CPU, memory, disk, load)",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static int read_proc_file(const char *path, char *out, size_t outlen)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t rd = fread(out, 1, outlen - 1, f);
    fclose(f);
    out[rd] = '\0';
    return (int)rd;
}

static void get_cpu_info(char *buf, size_t buflen)
{
    char raw[2048];
    size_t off = 0;

    off += (size_t)snprintf(buf + off, buflen - off, "CPU Info:\n");

    if (read_proc_file("/proc/stat", raw, sizeof(raw)) > 0) {
        unsigned long long user, nice, system, idle, iowait, irq, softirq;
        if (sscanf(raw, "cpu %llu %llu %llu %llu %llu %llu %llu",
                   &user, &nice, &system, &idle, &iowait, &irq, &softirq) == 7) {
            unsigned long long total = user + nice + system + idle + iowait + irq + softirq;
            unsigned long long busy = total - idle - iowait;
            double pct = total > 0 ? (double)busy / (double)total * 100.0 : 0.0;
            off += (size_t)snprintf(buf + off, buflen - off,
                "  Usage: %.1f%%\n"
                "  User: %llu  System: %llu  Idle: %llu  IOWait: %llu\n",
                pct, user, system, idle, iowait);
        }
    }

    /* CPU count */
    if (read_proc_file("/proc/cpuinfo", raw, sizeof(raw)) > 0) {
        int cores = 0;
        char *p = raw;
        while ((p = strstr(p, "processor")) != NULL) { cores++; p++; }
        off += (size_t)snprintf(buf + off, buflen - off, "  Cores: %d\n", cores);
    }
    (void)off;
}

static void get_memory_info(char *buf, size_t buflen)
{
    char raw[2048];
    size_t off = 0;

    off += (size_t)snprintf(buf + off, buflen - off, "Memory Info:\n");

    if (read_proc_file("/proc/meminfo", raw, sizeof(raw)) > 0) {
        unsigned long total = 0, free_m = 0, avail = 0, buffers = 0, cached = 0;
        unsigned long swap_total = 0, swap_free = 0;
        char *line = raw;
        char key[64];
        unsigned long val;
        while (line && *line) {
            if (sscanf(line, "%63[^:]: %lu", key, &val) == 2) {
                if (strcmp(key, "MemTotal") == 0) total = val;
                else if (strcmp(key, "MemFree") == 0) free_m = val;
                else if (strcmp(key, "MemAvailable") == 0) avail = val;
                else if (strcmp(key, "Buffers") == 0) buffers = val;
                else if (strcmp(key, "Cached") == 0) cached = val;
                else if (strcmp(key, "SwapTotal") == 0) swap_total = val;
                else if (strcmp(key, "SwapFree") == 0) swap_free = val;
            }
            line = strchr(line, '\n');
            if (line) line++;
        }
        unsigned long used = total - free_m - buffers - cached;
        double pct = total > 0 ? (double)used / (double)total * 100.0 : 0.0;
        off += (size_t)snprintf(buf + off, buflen - off,
            "  Total: %lu kB\n"
            "  Used: %lu kB (%.1f%%)\n"
            "  Free: %lu kB\n"
            "  Available: %lu kB\n"
            "  Buffers: %lu kB\n"
            "  Cached: %lu kB\n"
            "  Swap: %lu / %lu kB\n",
            total, used, pct, free_m, avail, buffers, cached,
            swap_total - swap_free, swap_total);
    }
    (void)off;
}

static void get_disk_info(char *buf, size_t buflen)
{
    size_t off = 0;
    off += (size_t)snprintf(buf + off, buflen - off, "Disk Info:\n");

    const char *paths[] = {"/", "/var", "/tmp", NULL};
    for (int i = 0; paths[i]; i++) {
        struct statvfs st;
        if (statvfs(paths[i], &st) == 0) {
            unsigned long long total = (unsigned long long)st.f_blocks * st.f_frsize;
            unsigned long long free_d = (unsigned long long)st.f_bfree * st.f_frsize;
            unsigned long long used = total - free_d;
            double pct = total > 0 ? (double)used / (double)total * 100.0 : 0.0;
            off += (size_t)snprintf(buf + off, buflen - off,
                "  %-8s total: %llu MB  used: %llu MB (%.1f%%)  free: %llu MB\n",
                paths[i],
                total / (1024 * 1024), used / (1024 * 1024), pct,
                free_d / (1024 * 1024));
        }
    }
    (void)off;
}

static void get_load_info(char *buf, size_t buflen)
{
    char raw[256];
    size_t off = 0;
    off += (size_t)snprintf(buf + off, buflen - off, "Load Average:\n");

    if (read_proc_file("/proc/loadavg", raw, sizeof(raw)) > 0) {
        double l1, l5, l15;
        int running, total;
        if (sscanf(raw, "%lf %lf %lf %d/%d", &l1, &l5, &l15, &running, &total) == 5) {
            off += (size_t)snprintf(buf + off, buflen - off,
                "  1min: %.2f  5min: %.2f  15min: %.2f\n"
                "  Running: %d / %d processes\n",
                l1, l5, l15, running, total);
        }
    }

    if (read_proc_file("/proc/uptime", raw, sizeof(raw)) > 0) {
        double up, idle;
        if (sscanf(raw, "%lf %lf", &up, &idle) == 2) {
            int days = (int)(up / 86400);
            int hours = (int)((up - days * 86400) / 3600);
            int mins = (int)((up - days * 86400 - hours * 3600) / 60);
            off += (size_t)snprintf(buf + off, buflen - off,
                "  Uptime: %dd %dh %dm\n", days, hours, mins);
        }
    }
    (void)off;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_queries = 0;

    core->path_register(core, "/metrics/resources/status", "metrics");
    core->path_set_access(core, "/metrics/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/metrics/resources/status", "System metrics overview");
    core->path_register(core, "/metrics/resources/cpu", "metrics");
    core->path_set_access(core, "/metrics/resources/cpu", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/metrics/resources/cpu", "CPU usage: user, system, idle %");
    core->path_register(core, "/metrics/resources/memory", "metrics");
    core->path_set_access(core, "/metrics/resources/memory", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/metrics/resources/memory", "Memory: total, used, free, cached, available");
    core->path_register(core, "/metrics/resources/disk", "metrics");
    core->path_set_access(core, "/metrics/resources/disk", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/metrics/resources/disk", "Disk usage per mount point");
    core->path_register(core, "/metrics/resources/load", "metrics");
    core->path_set_access(core, "/metrics/resources/load", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/metrics/resources/load", "Load averages: 1min, 5min, 15min");
    core->path_register(core, "/metrics/resources/all", "metrics");
    core->path_set_access(core, "/metrics/resources/all", PORTAL_ACCESS_READ);

    core->log(core, PORTAL_LOG_INFO, "metrics", "System metrics ready");
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/metrics/resources/status");
    core->path_unregister(core, "/metrics/resources/cpu");
    core->path_unregister(core, "/metrics/resources/memory");
    core->path_unregister(core, "/metrics/resources/disk");
    core->path_unregister(core, "/metrics/resources/load");
    core->path_unregister(core, "/metrics/resources/all");
    core->log(core, PORTAL_LOG_INFO, "metrics", "Metrics unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;
    char buf[8192];
    int n;
    g_queries++;

    if (strcmp(msg->path, "/metrics/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "Metrics Module\nQueries: %lld\n", (long long)g_queries);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/metrics/resources/cpu") == 0) {
        get_cpu_info(buf, sizeof(buf));
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, strlen(buf));
        return 0;
    }

    if (strcmp(msg->path, "/metrics/resources/memory") == 0) {
        get_memory_info(buf, sizeof(buf));
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, strlen(buf));
        return 0;
    }

    if (strcmp(msg->path, "/metrics/resources/disk") == 0) {
        get_disk_info(buf, sizeof(buf));
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, strlen(buf));
        return 0;
    }

    if (strcmp(msg->path, "/metrics/resources/load") == 0) {
        get_load_info(buf, sizeof(buf));
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, strlen(buf));
        return 0;
    }

    if (strcmp(msg->path, "/metrics/resources/all") == 0) {
        size_t off = 0;
        get_cpu_info(buf, sizeof(buf));
        off = strlen(buf);
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "\n");
        get_memory_info(buf + off, sizeof(buf) - off);
        off = strlen(buf);
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "\n");
        get_disk_info(buf + off, sizeof(buf) - off);
        off = strlen(buf);
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "\n");
        get_load_info(buf + off, sizeof(buf) - off);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, strlen(buf));
        return 0;
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
