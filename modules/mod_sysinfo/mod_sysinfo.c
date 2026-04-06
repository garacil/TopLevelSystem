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
 * mod_sysinfo — System information
 *
 * Exposes hostname, OS details, kernel version,
 * network interfaces, and environment variables.
 * All read-only resources.
 *
 * Config:
 *   [mod_sysinfo]
 *   (none required)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "portal/portal.h"

extern char **environ;

static portal_core_t *g_core = NULL;

static portal_module_info_t info = {
    .name = "sysinfo", .version = "1.0.0",
    .description = "System information (OS, network, env)",
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

    core->path_register(core, "/sysinfo/resources/status", "sysinfo");
    core->path_set_access(core, "/sysinfo/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/sysinfo/resources/os", "sysinfo");
    core->path_set_access(core, "/sysinfo/resources/os", PORTAL_ACCESS_READ);
    core->path_register(core, "/sysinfo/resources/network", "sysinfo");
    core->path_set_access(core, "/sysinfo/resources/network", PORTAL_ACCESS_READ);
    core->path_register(core, "/sysinfo/resources/env", "sysinfo");
    core->path_set_access(core, "/sysinfo/resources/env", PORTAL_ACCESS_READ);
    core->path_add_label(core, "/sysinfo/resources/env", "admin");
    core->path_register(core, "/sysinfo/resources/all", "sysinfo");
    core->path_set_access(core, "/sysinfo/resources/all", PORTAL_ACCESS_READ);

    core->log(core, PORTAL_LOG_INFO, "sysinfo", "System info module ready");
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/sysinfo/resources/status");
    core->path_unregister(core, "/sysinfo/resources/os");
    core->path_unregister(core, "/sysinfo/resources/network");
    core->path_unregister(core, "/sysinfo/resources/env");
    core->path_unregister(core, "/sysinfo/resources/all");
    core->log(core, PORTAL_LOG_INFO, "sysinfo", "System info unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

static size_t write_os_info(char *buf, size_t buflen)
{
    size_t off = 0;
    struct utsname uts;
    char hostname[256];

    off += (size_t)snprintf(buf + off, buflen - off, "OS Information:\n");

    if (gethostname(hostname, sizeof(hostname)) == 0)
        off += (size_t)snprintf(buf + off, buflen - off,
            "  Hostname: %s\n", hostname);

    if (uname(&uts) == 0) {
        off += (size_t)snprintf(buf + off, buflen - off,
            "  System: %s%s\n"
            "  Node: %s\n"
            "  Release: %s\n"
            "  Version: %s\n"
            "  Machine: %s\n",
            strcmp(uts.sysname,"Linux")==0?"GNU/":"", uts.sysname,
            uts.nodename, uts.release, uts.version, uts.machine);
    }

    /* CPU count */
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    if (nproc > 0)
        off += (size_t)snprintf(buf + off, buflen - off,
            "  CPUs: %ld\n", nproc);

    /* Page size */
    long pgsz = sysconf(_SC_PAGESIZE);
    if (pgsz > 0)
        off += (size_t)snprintf(buf + off, buflen - off,
            "  Page size: %ld bytes\n", pgsz);

    return off;
}

static size_t write_network_info(char *buf, size_t buflen)
{
    size_t off = 0;
    off += (size_t)snprintf(buf + off, buflen - off, "Network Interfaces:\n");

    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        off += (size_t)snprintf(buf + off, buflen - off,
            "  (cannot enumerate interfaces)\n");
        return off;
    }

    for (ifa = ifaddr; ifa != NULL && off < buflen - 128; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;

        int family = ifa->ifa_addr->sa_family;
        if (family == AF_INET) {
            char ip[INET_ADDRSTRLEN];
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
            const char *flags = (ifa->ifa_flags & IFF_UP) ? "UP" : "DOWN";
            off += (size_t)snprintf(buf + off, buflen - off,
                "  %-12s IPv4: %-16s %s\n", ifa->ifa_name, ip, flags);
        } else if (family == AF_INET6) {
            char ip[INET6_ADDRSTRLEN];
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ifa->ifa_addr;
            inet_ntop(AF_INET6, &sa->sin6_addr, ip, sizeof(ip));
            off += (size_t)snprintf(buf + off, buflen - off,
                "  %-12s IPv6: %s\n", ifa->ifa_name, ip);
        }
    }
    freeifaddrs(ifaddr);
    return off;
}

static size_t write_env_info(char *buf, size_t buflen, const char *filter)
{
    size_t off = 0;
    off += (size_t)snprintf(buf + off, buflen - off, "Environment:\n");

    for (char **env = environ; *env && off < buflen - 256; env++) {
        if (filter && strstr(*env, filter) == NULL) continue;
        /* Truncate long values */
        char line[512];
        snprintf(line, sizeof(line), "%s", *env);
        if (strlen(line) > 200) {
            line[197] = '.'; line[198] = '.'; line[199] = '.'; line[200] = '\0';
        }
        off += (size_t)snprintf(buf + off, buflen - off, "  %s\n", line);
    }
    return off;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;
    char buf[16384];

    if (strcmp(msg->path, "/sysinfo/resources/status") == 0) {
        struct utsname uts;
        char hostname[256];
        gethostname(hostname, sizeof(hostname));
        uname(&uts);
        int n = snprintf(buf, sizeof(buf),
            "System Info Module\nHostname: %s\nOS: %s%s %s %s\n",
            hostname, strcmp(uts.sysname,"Linux")==0?"GNU/":"",
            uts.sysname, uts.release, uts.machine);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/sysinfo/resources/os") == 0) {
        size_t len = write_os_info(buf, sizeof(buf));
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, len);
        return 0;
    }

    if (strcmp(msg->path, "/sysinfo/resources/network") == 0) {
        size_t len = write_network_info(buf, sizeof(buf));
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, len);
        return 0;
    }

    if (strcmp(msg->path, "/sysinfo/resources/env") == 0) {
        const char *filter = get_hdr(msg, "filter");
        size_t len = write_env_info(buf, sizeof(buf), filter);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, len);
        return 0;
    }

    if (strcmp(msg->path, "/sysinfo/resources/all") == 0) {
        size_t off = 0;
        off += write_os_info(buf + off, sizeof(buf) - off);
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "\n");
        off += write_network_info(buf + off, sizeof(buf) - off);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
