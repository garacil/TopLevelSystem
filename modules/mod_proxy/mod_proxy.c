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
 * mod_proxy — HTTP reverse proxy
 *
 * Forward requests to upstream HTTP servers.
 * Named routes map portal paths to upstream URLs.
 * Supports connection reuse and timeout configuration.
 *
 * Config:
 *   [mod_proxy]
 *   max_routes = 64
 *   timeout = 10
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "portal/portal.h"

#define PROXY_MAX_ROUTES  64
#define PROXY_BUF_SIZE    65536
#define PROXY_TIMEOUT     10

typedef struct {
    char  name[64];
    char  upstream[512];    /* http://host:port/path */
    char  host[256];
    int   port;
    char  path_prefix[256];
    int   active;
    int64_t forwarded;
    int64_t errors;
} proxy_route_t;

static portal_core_t *g_core = NULL;
static proxy_route_t  g_routes[PROXY_MAX_ROUTES];
static int            g_count = 0;
static int            g_max = PROXY_MAX_ROUTES;
static int            g_timeout = PROXY_TIMEOUT;

static portal_module_info_t info = {
    .name = "proxy", .version = "1.0.0",
    .description = "HTTP reverse proxy",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

static proxy_route_t *find_route(const char *name)
{
    for (int i = 0; i < g_count; i++)
        if (g_routes[i].active && strcmp(g_routes[i].name, name) == 0)
            return &g_routes[i];
    return NULL;
}

/* Parse URL: http://host:port/path */
static int parse_url(const char *url, char *host, size_t hlen,
                     int *port, char *path, size_t plen)
{
    const char *p = url;
    if (strncmp(p, "http://", 7) == 0) p += 7;
    else if (strncmp(p, "https://", 8) == 0) p += 8;

    const char *colon = strchr(p, ':');
    const char *slash = strchr(p, '/');

    if (colon && (!slash || colon < slash)) {
        size_t hl = (size_t)(colon - p);
        if (hl >= hlen) hl = hlen - 1;
        memcpy(host, p, hl);
        host[hl] = '\0';
        *port = atoi(colon + 1);
    } else if (slash) {
        size_t hl = (size_t)(slash - p);
        if (hl >= hlen) hl = hlen - 1;
        memcpy(host, p, hl);
        host[hl] = '\0';
        *port = 80;
    } else {
        snprintf(host, hlen, "%s", p);
        *port = 80;
    }

    if (slash) snprintf(path, plen, "%s", slash);
    else snprintf(path, plen, "/");
    return 0;
}

/* Simple HTTP GET to upstream */
static int proxy_forward(proxy_route_t *route, const char *uri,
                          char *out, size_t outlen)
{
    struct hostent *he = gethostbyname(route->host);
    if (!he) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = {g_timeout, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)route->port);
    memcpy(&addr.sin_addr, he->h_addr, (size_t)he->h_length);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    /* Build HTTP request */
    char req[4096];
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s",
             route->path_prefix, uri ? uri : "");
    int rlen = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "User-Agent: Portal-Proxy/1.0\r\n"
        "\r\n",
        full_path, route->host);

    if (write(fd, req, (size_t)rlen) < 0) {
        close(fd);
        return -1;
    }

    /* Read response */
    size_t total = 0;
    ssize_t rd;
    while ((rd = read(fd, out + total, outlen - total - 1)) > 0)
        total += (size_t)rd;
    out[total] = '\0';
    close(fd);

    /* Skip HTTP headers, find body */
    char *body = strstr(out, "\r\n\r\n");
    if (body) {
        body += 4;
        size_t blen = total - (size_t)(body - out);
        memmove(out, body, blen);
        out[blen] = '\0';
        return (int)blen;
    }
    return (int)total;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_routes, 0, sizeof(g_routes));
    g_count = 0;

    const char *v;
    if ((v = core->config_get(core, "proxy", "max_routes")))
        g_max = atoi(v);
    if ((v = core->config_get(core, "proxy", "timeout")))
        g_timeout = atoi(v);

    core->path_register(core, "/proxy/resources/status", "proxy");
    core->path_set_access(core, "/proxy/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/proxy/resources/routes", "proxy");
    core->path_set_access(core, "/proxy/resources/routes", PORTAL_ACCESS_READ);
    core->path_register(core, "/proxy/functions/add", "proxy");
    core->path_set_access(core, "/proxy/functions/add", PORTAL_ACCESS_RW);
    core->path_register(core, "/proxy/functions/remove", "proxy");
    core->path_set_access(core, "/proxy/functions/remove", PORTAL_ACCESS_RW);
    core->path_register(core, "/proxy/functions/forward", "proxy");
    core->path_set_access(core, "/proxy/functions/forward", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "proxy",
              "Reverse proxy ready (max: %d routes, timeout: %ds)",
              g_max, g_timeout);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/proxy/resources/status");
    core->path_unregister(core, "/proxy/resources/routes");
    core->path_unregister(core, "/proxy/functions/add");
    core->path_unregister(core, "/proxy/functions/remove");
    core->path_unregister(core, "/proxy/functions/forward");
    core->log(core, PORTAL_LOG_INFO, "proxy", "Proxy unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[PROXY_BUF_SIZE];
    int n;

    if (strcmp(msg->path, "/proxy/resources/status") == 0) {
        int active = 0;
        int64_t tf = 0, te = 0;
        for (int i = 0; i < g_count; i++) {
            if (!g_routes[i].active) continue;
            active++;
            tf += g_routes[i].forwarded;
            te += g_routes[i].errors;
        }
        n = snprintf(buf, sizeof(buf),
            "Reverse Proxy\n"
            "Routes: %d (max %d)\n"
            "Timeout: %ds\n"
            "Total forwarded: %lld\n"
            "Total errors: %lld\n",
            active, g_max, g_timeout,
            (long long)tf, (long long)te);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/proxy/resources/routes") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Proxy Routes:\n");
        for (int i = 0; i < g_count; i++) {
            if (!g_routes[i].active) continue;
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "  %-16s → %s:%d%s  (fwd: %lld, err: %lld)\n",
                g_routes[i].name, g_routes[i].host, g_routes[i].port,
                g_routes[i].path_prefix,
                (long long)g_routes[i].forwarded,
                (long long)g_routes[i].errors);
        }
        if (g_count == 0)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/proxy/functions/add") == 0) {
        const char *name = get_hdr(msg, "name");
        const char *upstream = get_hdr(msg, "upstream");
        if (!name || !upstream) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf),
                "Need: name, upstream headers (e.g. upstream=http://host:port/path)\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (find_route(name)) {
            portal_resp_set_status(resp, PORTAL_CONFLICT);
            n = snprintf(buf, sizeof(buf), "Route '%s' already exists\n", name);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (g_count >= g_max) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            return -1;
        }

        proxy_route_t *r = &g_routes[g_count++];
        snprintf(r->name, sizeof(r->name), "%s", name);
        snprintf(r->upstream, sizeof(r->upstream), "%s", upstream);
        parse_url(upstream, r->host, sizeof(r->host),
                  &r->port, r->path_prefix, sizeof(r->path_prefix));
        r->active = 1;
        r->forwarded = 0;
        r->errors = 0;

        core->event_emit(core, "/events/proxy/add", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_CREATED);
        n = snprintf(buf, sizeof(buf), "Route '%s' → %s:%d%s\n",
                     name, r->host, r->port, r->path_prefix);
        portal_resp_set_body(resp, buf, (size_t)n);
        core->log(core, PORTAL_LOG_INFO, "proxy", "Added route '%s' → %s",
                  name, upstream);
        return 0;
    }

    if (strcmp(msg->path, "/proxy/functions/remove") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        proxy_route_t *r = find_route(name);
        if (!r) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        r->active = 0;
        core->event_emit(core, "/events/proxy/remove", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Route '%s' removed\n", name);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/proxy/functions/forward") == 0) {
        const char *name = get_hdr(msg, "route");
        const char *uri = get_hdr(msg, "uri");
        if (!name) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: route header, optional uri header\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        proxy_route_t *r = find_route(name);
        if (!r) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            return -1;
        }

        char *rbuf = malloc(PROXY_BUF_SIZE);
        int rlen = proxy_forward(r, uri, rbuf, PROXY_BUF_SIZE);
        if (rlen >= 0) {
            r->forwarded++;
            core->event_emit(core, "/events/proxy/forward", name, strlen(name));
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, rbuf, (size_t)rlen);
        } else {
            r->errors++;
            portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
            n = snprintf(buf, sizeof(buf), "Upstream %s:%d unreachable\n",
                         r->host, r->port);
            portal_resp_set_body(resp, buf, (size_t)n);
        }
        free(rbuf);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
