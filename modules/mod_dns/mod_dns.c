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
 * mod_dns — DNS resolver utility
 *
 * Resolve hostnames (A records), reverse lookup (PTR),
 * and basic record queries via getaddrinfo/gethostbyname.
 *
 * Config:
 *   [mod_dns]
 *   (none required)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "portal/portal.h"

static portal_core_t *g_core = NULL;
static int64_t g_lookups = 0;
static int64_t g_reverse = 0;
static int64_t g_errors = 0;

static portal_module_info_t info = {
    .name = "dns", .version = "1.0.0",
    .description = "DNS resolver utility",
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
    g_lookups = g_reverse = g_errors = 0;

    core->path_register(core, "/dns/resources/status", "dns");
    core->path_set_access(core, "/dns/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/dns/resources/status", "DNS resolver status");
    core->path_register(core, "/dns/functions/resolve", "dns");
    core->path_set_access(core, "/dns/functions/resolve", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/dns/functions/resolve", "Resolve hostname to IP. Header: host");
    core->path_register(core, "/dns/functions/reverse", "dns");
    core->path_set_access(core, "/dns/functions/reverse", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/dns/functions/reverse", "Reverse DNS lookup. Header: ip");
    core->path_register(core, "/dns/functions/lookup", "dns");
    core->path_set_access(core, "/dns/functions/lookup", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "dns", "DNS resolver ready");
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/dns/resources/status");
    core->path_unregister(core, "/dns/functions/resolve");
    core->path_unregister(core, "/dns/functions/reverse");
    core->path_unregister(core, "/dns/functions/lookup");
    core->log(core, PORTAL_LOG_INFO, "dns", "DNS resolver unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[8192];
    int n;

    if (strcmp(msg->path, "/dns/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "DNS Resolver\n"
            "Lookups: %lld\n"
            "Reverse: %lld\n"
            "Errors: %lld\n",
            (long long)g_lookups, (long long)g_reverse, (long long)g_errors);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/dns/functions/resolve") == 0) {
        const char *host = get_hdr(msg, "host");
        if (!host) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: host header\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        struct addrinfo hints = {0}, *res, *rp;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        int rc = getaddrinfo(host, NULL, &hints, &res);
        if (rc != 0) {
            g_errors++;
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            n = snprintf(buf, sizeof(buf), "DNS error: %s\n", gai_strerror(rc));
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
            "DNS resolve: %s\n", host);
        for (rp = res; rp != NULL && off < sizeof(buf) - 128; rp = rp->ai_next) {
            char ipstr[INET6_ADDRSTRLEN];
            if (rp->ai_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)rp->ai_addr;
                inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof(ipstr));
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "  A     %s\n", ipstr);
            } else if (rp->ai_family == AF_INET6) {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)rp->ai_addr;
                inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof(ipstr));
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "  AAAA  %s\n", ipstr);
            }
        }
        freeaddrinfo(res);
        g_lookups++;
        core->event_emit(core, "/events/dns/resolve", host, strlen(host));
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/dns/functions/reverse") == 0) {
        const char *ip = get_hdr(msg, "ip");
        if (!ip) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: ip header\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET;
        if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Invalid IP: %s\n", ip);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        char hostname[NI_MAXHOST];
        int rc = getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                             hostname, sizeof(hostname), NULL, 0, 0);
        if (rc != 0) {
            g_errors++;
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            n = snprintf(buf, sizeof(buf), "Reverse DNS failed: %s\n",
                         gai_strerror(rc));
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        g_reverse++;
        core->event_emit(core, "/events/dns/reverse", ip, strlen(ip));
        n = snprintf(buf, sizeof(buf), "Reverse DNS: %s → %s\n", ip, hostname);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/dns/functions/lookup") == 0) {
        const char *host = get_hdr(msg, "host");
        if (!host) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: host header\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
            "Full lookup: %s\n", host);

        /* A/AAAA records */
        struct addrinfo hints = {0}, *res, *rp;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host, NULL, &hints, &res) == 0) {
            for (rp = res; rp && off < sizeof(buf) - 128; rp = rp->ai_next) {
                char ipstr[INET6_ADDRSTRLEN];
                if (rp->ai_family == AF_INET) {
                    struct sockaddr_in *s = (struct sockaddr_in *)rp->ai_addr;
                    inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof(ipstr));
                    off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                        "  A     %s\n", ipstr);
                } else if (rp->ai_family == AF_INET6) {
                    struct sockaddr_in6 *s = (struct sockaddr_in6 *)rp->ai_addr;
                    inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof(ipstr));
                    off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                        "  AAAA  %s\n", ipstr);
                }
            }
            freeaddrinfo(res);
        }

        /* MX records via gethostbyname (basic) */
        struct hostent *he = gethostbyname(host);
        if (he) {
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "  Host: %s\n", he->h_name);
            for (int i = 0; he->h_aliases[i] && off < sizeof(buf) - 128; i++)
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "  Alias: %s\n", he->h_aliases[i]);
        }

        g_lookups++;
        core->event_emit(core, "/events/dns/lookup", host, strlen(host));
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
