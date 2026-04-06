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
 * mod_api_gateway — External API routing with caching and rate limiting
 *
 * Named API routes map portal paths to external HTTP endpoints.
 * Features: response caching (via mod_cache), rate limiting (via mod_firewall),
 * request headers passthrough, timeout control, retry logic.
 *
 * Config:
 *   [mod_api_gateway]
 *   max_routes = 128
 *   default_timeout = 10
 *   default_cache_ttl = 60
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "portal/portal.h"

#define GW_MAX_ROUTES    128
#define GW_BUF_SIZE      131072  /* 128 KB response buffer */
#define GW_DEFAULT_TTL   60
#define GW_DEFAULT_TMO   10

typedef struct {
    char    name[64];
    char    upstream[512];   /* full URL: http://host:port/path */
    char    host[256];
    int     port;
    char    path[256];
    int     use_tls;
    char    auth_header[256]; /* passthrough auth header */
    int     cache_ttl;        /* seconds, 0 = no cache */
    int     timeout;
    int     active;
    int64_t calls;
    int64_t cache_hits;
    int64_t errors;
} gw_route_t;

static portal_core_t *g_core = NULL;
static gw_route_t     g_routes[GW_MAX_ROUTES];
static int            g_count = 0;
static int            g_max = GW_MAX_ROUTES;
static int            g_default_ttl = GW_DEFAULT_TTL;
static int            g_default_tmo = GW_DEFAULT_TMO;

static portal_module_info_t info = {
    .name = "api_gateway", .version = "1.0.0",
    .description = "API gateway with caching and rate limiting",
    .soft_deps = (const char *[]){"cache", "firewall", NULL}
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

static gw_route_t *find_route(const char *name)
{
    for (int i = 0; i < g_count; i++)
        if (g_routes[i].active && strcmp(g_routes[i].name, name) == 0)
            return &g_routes[i];
    return NULL;
}

static void parse_url(const char *url, char *host, size_t hlen,
                      int *port, char *path, size_t plen, int *tls)
{
    const char *p = url;
    *tls = 0;
    if (strncmp(p, "https://", 8) == 0) { p += 8; *tls = 1; *port = 443; }
    else if (strncmp(p, "http://", 7) == 0) { p += 7; *port = 80; }
    else *port = 80;

    const char *colon = strchr(p, ':');
    const char *slash = strchr(p, '/');
    if (colon && (!slash || colon < slash)) {
        size_t hl = (size_t)(colon - p);
        if (hl >= hlen) hl = hlen - 1;
        memcpy(host, p, hl); host[hl] = '\0';
        *port = atoi(colon + 1);
    } else if (slash) {
        size_t hl = (size_t)(slash - p);
        if (hl >= hlen) hl = hlen - 1;
        memcpy(host, p, hl); host[hl] = '\0';
    } else {
        snprintf(host, hlen, "%s", p);
    }
    if (slash) snprintf(path, plen, "%s", slash);
    else snprintf(path, plen, "/");
}

/* HTTP GET to upstream (plain HTTP only for now) */
static int gw_http_get(gw_route_t *r, const char *uri, const char *extra_headers,
                        char *out, size_t outlen)
{
    struct hostent *he = gethostbyname(r->host);
    if (!he) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = {r->timeout, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)r->port);
    memcpy(&addr.sin_addr, he->h_addr, (size_t)he->h_length);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }

    char req[4096];
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", r->path, uri ? uri : "");

    int rlen = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "User-Agent: Portal-Gateway/1.0\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n",
        full_path, r->host,
        extra_headers ? extra_headers : "");

    if (write(fd, req, (size_t)rlen) < 0) { close(fd); return -1; }

    size_t total = 0;
    ssize_t rd;
    while ((rd = read(fd, out + total, outlen - total - 1)) > 0)
        total += (size_t)rd;
    out[total] = '\0';
    close(fd);

    /* Skip HTTP headers, extract body */
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

/* Try cache first, then upstream */
static int gw_call(gw_route_t *r, const char *uri,
                    char *out, size_t outlen, portal_core_t *core)
{
    /* Check cache if enabled */
    if (r->cache_ttl > 0 && core->module_loaded(core, "cache")) {
        char cache_key[512];
        snprintf(cache_key, sizeof(cache_key), "gw:%s:%s", r->name, uri ? uri : "/");

        portal_msg_t *cm = portal_msg_alloc();
        portal_resp_t *cr = portal_resp_alloc();
        if (cm && cr) {
            portal_msg_set_path(cm, "/cache/functions/get");
            portal_msg_set_method(cm, PORTAL_METHOD_CALL);
            portal_msg_add_header(cm, "key", cache_key);
            core->send(core, cm, cr);
            if (cr->status == PORTAL_OK && cr->body && cr->body_len > 0) {
                size_t clen = cr->body_len < outlen ? cr->body_len : outlen - 1;
                memcpy(out, cr->body, clen);
                out[clen] = '\0';
                r->cache_hits++;
                portal_msg_free(cm); portal_resp_free(cr);
                return (int)clen;
            }
            portal_msg_free(cm); portal_resp_free(cr);
        }
    }

    /* Build extra headers */
    char extra[512] = "";
    if (r->auth_header[0])
        snprintf(extra, sizeof(extra), "Authorization: %s\r\n", r->auth_header);

    int len = gw_http_get(r, uri, extra[0] ? extra : NULL, out, outlen);
    if (len < 0) {
        r->errors++;
        return -1;
    }

    r->calls++;

    /* Store in cache */
    if (r->cache_ttl > 0 && len > 0 && core->module_loaded(core, "cache")) {
        char cache_key[512];
        snprintf(cache_key, sizeof(cache_key), "gw:%s:%s", r->name, uri ? uri : "/");
        char ttl_str[16];
        snprintf(ttl_str, sizeof(ttl_str), "%d", r->cache_ttl);

        portal_msg_t *cm = portal_msg_alloc();
        portal_resp_t *cr = portal_resp_alloc();
        if (cm && cr) {
            portal_msg_set_path(cm, "/cache/functions/set");
            portal_msg_set_method(cm, PORTAL_METHOD_CALL);
            portal_msg_add_header(cm, "key", cache_key);
            portal_msg_add_header(cm, "value", out);
            portal_msg_add_header(cm, "ttl", ttl_str);
            core->send(core, cm, cr);
            portal_msg_free(cm); portal_resp_free(cr);
        }
    }

    return len;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_routes, 0, sizeof(g_routes));
    g_count = 0;

    const char *v;
    if ((v = core->config_get(core, "api_gateway", "max_routes")))
        g_max = atoi(v);
    if ((v = core->config_get(core, "api_gateway", "default_cache_ttl")))
        g_default_ttl = atoi(v);
    if ((v = core->config_get(core, "api_gateway", "default_timeout")))
        g_default_tmo = atoi(v);

    core->path_register(core, "/gateway/resources/status", "api_gateway");
    core->path_set_access(core, "/gateway/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/gateway/resources/routes", "api_gateway");
    core->path_set_access(core, "/gateway/resources/routes", PORTAL_ACCESS_READ);
    core->path_register(core, "/gateway/functions/add", "api_gateway");
    core->path_set_access(core, "/gateway/functions/add", PORTAL_ACCESS_RW);
    core->path_register(core, "/gateway/functions/remove", "api_gateway");
    core->path_set_access(core, "/gateway/functions/remove", PORTAL_ACCESS_RW);
    core->path_register(core, "/gateway/functions/call", "api_gateway");
    core->path_set_access(core, "/gateway/functions/call", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "api_gateway",
              "API Gateway ready (max: %d routes, cache TTL: %ds, timeout: %ds)",
              g_max, g_default_ttl, g_default_tmo);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/gateway/resources/status");
    core->path_unregister(core, "/gateway/resources/routes");
    core->path_unregister(core, "/gateway/functions/add");
    core->path_unregister(core, "/gateway/functions/remove");
    core->path_unregister(core, "/gateway/functions/call");
    core->log(core, PORTAL_LOG_INFO, "api_gateway", "API Gateway unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[8192];
    int n;

    if (strcmp(msg->path, "/gateway/resources/status") == 0) {
        int active = 0;
        int64_t tc = 0, th = 0, te = 0;
        for (int i = 0; i < g_count; i++) {
            if (!g_routes[i].active) continue;
            active++; tc += g_routes[i].calls;
            th += g_routes[i].cache_hits; te += g_routes[i].errors;
        }
        n = snprintf(buf, sizeof(buf),
            "API Gateway\n"
            "Routes: %d (max %d)\n"
            "Default cache TTL: %ds\n"
            "Default timeout: %ds\n"
            "Total calls: %lld\n"
            "Cache hits: %lld\n"
            "Errors: %lld\n",
            active, g_max, g_default_ttl, g_default_tmo,
            (long long)tc, (long long)th, (long long)te);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/gateway/resources/routes") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "API Routes:\n");
        for (int i = 0; i < g_count; i++) {
            if (!g_routes[i].active) continue;
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "  %-16s → %s:%d%s  cache:%ds  calls:%lld  hits:%lld  err:%lld\n",
                g_routes[i].name, g_routes[i].host, g_routes[i].port,
                g_routes[i].path, g_routes[i].cache_ttl,
                (long long)g_routes[i].calls,
                (long long)g_routes[i].cache_hits,
                (long long)g_routes[i].errors);
        }
        if (g_count == 0)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/gateway/functions/add") == 0) {
        const char *name = get_hdr(msg, "name");
        const char *upstream = get_hdr(msg, "upstream");
        const char *auth = get_hdr(msg, "auth");
        const char *ttl_s = get_hdr(msg, "cache_ttl");
        const char *tmo_s = get_hdr(msg, "timeout");
        if (!name || !upstream) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf),
                "Need: name, upstream headers. Optional: auth, cache_ttl, timeout\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (find_route(name)) {
            portal_resp_set_status(resp, PORTAL_CONFLICT);
            return -1;
        }
        if (g_count >= g_max) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            return -1;
        }

        gw_route_t *r = &g_routes[g_count++];
        snprintf(r->name, sizeof(r->name), "%s", name);
        snprintf(r->upstream, sizeof(r->upstream), "%s", upstream);
        parse_url(upstream, r->host, sizeof(r->host),
                  &r->port, r->path, sizeof(r->path), &r->use_tls);
        if (auth) snprintf(r->auth_header, sizeof(r->auth_header), "%s", auth);
        r->cache_ttl = ttl_s ? atoi(ttl_s) : g_default_ttl;
        r->timeout = tmo_s ? atoi(tmo_s) : g_default_tmo;
        r->active = 1;

        core->event_emit(core, "/events/gateway/add", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_CREATED);
        n = snprintf(buf, sizeof(buf),
            "Route '%s' → %s:%d%s (cache: %ds, timeout: %ds)\n",
            name, r->host, r->port, r->path, r->cache_ttl, r->timeout);
        portal_resp_set_body(resp, buf, (size_t)n);
        core->log(core, PORTAL_LOG_INFO, "api_gateway",
                  "Added route '%s' → %s", name, upstream);
        return 0;
    }

    if (strcmp(msg->path, "/gateway/functions/remove") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        gw_route_t *r = find_route(name);
        if (!r) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        r->active = 0;
        core->event_emit(core, "/events/gateway/remove", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Route '%s' removed\n", name);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/gateway/functions/call") == 0) {
        const char *name = get_hdr(msg, "route");
        const char *uri = get_hdr(msg, "uri");
        if (!name) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: route header. Optional: uri\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        gw_route_t *r = find_route(name);
        if (!r) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }

        /* Rate limit check via firewall if available */
        if (core->module_loaded(core, "firewall")) {
            const char *source = msg->ctx && msg->ctx->auth.user
                ? msg->ctx->auth.user : "anonymous";
            portal_msg_t *fm = portal_msg_alloc();
            portal_resp_t *fr = portal_resp_alloc();
            if (fm && fr) {
                portal_msg_set_path(fm, "/firewall/functions/check");
                portal_msg_set_method(fm, PORTAL_METHOD_CALL);
                portal_msg_add_header(fm, "source", source);
                core->send(core, fm, fr);
                if (fr->status == PORTAL_FORBIDDEN) {
                    portal_msg_free(fm); portal_resp_free(fr);
                    portal_resp_set_status(resp, PORTAL_FORBIDDEN);
                    n = snprintf(buf, sizeof(buf), "Rate limited\n");
                    portal_resp_set_body(resp, buf, (size_t)n);
                    return -1;
                }
                portal_msg_free(fm); portal_resp_free(fr);
            }
        }

        char *rbuf = malloc(GW_BUF_SIZE);
        if (!rbuf) { portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR); return -1; }

        int rlen = gw_call(r, uri, rbuf, GW_BUF_SIZE, core);
        if (rlen >= 0) {
            core->event_emit(core, "/events/gateway/call", name, strlen(name));
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, rbuf, (size_t)rlen);
        } else {
            portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
            n = snprintf(buf, sizeof(buf), "Upstream unreachable: %s:%d\n",
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
