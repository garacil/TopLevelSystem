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
 * mod_http_client — HTTP/HTTPS outbound client
 *
 * Allows modules to make HTTP requests to external APIs
 * through the Portal path system.
 *
 * Config:
 *   [mod_http_client]
 *   timeout = 30
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "portal/portal.h"

#define HTTPC_BUF_SIZE   65536
#define HTTPC_TIMEOUT    30

static portal_core_t *g_core = NULL;
static int g_timeout = HTTPC_TIMEOUT;
static int64_t g_requests = 0;
static SSL_CTX *g_ssl_ctx = NULL;

static portal_module_info_t info = {
    .name = "http_client", .version = "1.0.0",
    .description = "HTTP/HTTPS outbound client",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0)
            return msg->headers[i].value;
    return NULL;
}

/* --- URL parser --- */

typedef struct {
    int   use_ssl;
    char  host[256];
    int   port;
    char  path[2048];
} parsed_url_t;

static int parse_url(const char *url, parsed_url_t *u)
{
    memset(u, 0, sizeof(*u));
    u->port = 80;
    snprintf(u->path, sizeof(u->path), "/");

    if (strncmp(url, "https://", 8) == 0) {
        u->use_ssl = 1; u->port = 443;
        url += 8;
    } else if (strncmp(url, "http://", 7) == 0) {
        url += 7;
    }

    /* host[:port]/path */
    const char *slash = strchr(url, '/');
    const char *colon = strchr(url, ':');

    if (colon && (!slash || colon < slash)) {
        size_t hlen = (size_t)(colon - url);
        if (hlen >= sizeof(u->host)) return -1;
        memcpy(u->host, url, hlen);
        u->host[hlen] = '\0';
        u->port = atoi(colon + 1);
    } else if (slash) {
        size_t hlen = (size_t)(slash - url);
        if (hlen >= sizeof(u->host)) return -1;
        memcpy(u->host, url, hlen);
        u->host[hlen] = '\0';
    } else {
        snprintf(u->host, sizeof(u->host), "%s", url);
    }

    if (slash)
        snprintf(u->path, sizeof(u->path), "%s", slash);

    return 0;
}

/* --- HTTP request --- */

static int http_request(const char *method, const char *url,
                         const char *content_type, const char *body,
                         size_t body_len, char *response, size_t resp_size)
{
    parsed_url_t u;
    if (parse_url(url, &u) < 0) return -1;

    /* Resolve host */
    struct hostent *he = gethostbyname(u.host);
    if (!he) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* Set timeout */
    struct timeval tv = { .tv_sec = g_timeout, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)u.port);
    memcpy(&addr.sin_addr, he->h_addr, (size_t)he->h_length);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    /* Build request */
    char req[4096];
    int rlen;
    if (body && body_len > 0) {
        rlen = snprintf(req, sizeof(req),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n",
            method, u.path, u.host,
            content_type ? content_type : "text/plain",
            body_len);
    } else {
        rlen = snprintf(req, sizeof(req),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Connection: close\r\n"
            "\r\n",
            method, u.path, u.host);
    }

    SSL *ssl = NULL;
    if (u.use_ssl && g_ssl_ctx) {
        ssl = SSL_new(g_ssl_ctx);
        SSL_set_fd(ssl, fd);
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            close(fd);
            return -1;
        }
        SSL_write(ssl, req, rlen);
        if (body && body_len > 0)
            SSL_write(ssl, body, (int)body_len);
    } else {
        write(fd, req, (size_t)rlen);
        if (body && body_len > 0)
            write(fd, body, body_len);
    }

    /* Read response */
    size_t total = 0;
    while (total < resp_size - 1) {
        ssize_t n;
        if (ssl)
            n = SSL_read(ssl, response + total, (int)(resp_size - total - 1));
        else
            n = read(fd, response + total, resp_size - total - 1);
        if (n <= 0) break;
        total += (size_t)n;
    }
    response[total] = '\0';

    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    close(fd);
    g_requests++;

    /* Extract body (after \r\n\r\n) */
    char *body_start = strstr(response, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        memmove(response, body_start, strlen(body_start) + 1);
    }

    return 0;
}

/* --- Module lifecycle --- */

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_requests = 0;

    const char *v = core->config_get(core, "http_client", "timeout");
    if (v) g_timeout = atoi(v);

    SSL_library_init();
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());

    core->path_register(core, "/httpc/resources/status", "http_client");
    core->path_set_access(core, "/httpc/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/httpc/functions/get", "http_client");
    core->path_set_access(core, "/httpc/functions/get", PORTAL_ACCESS_RW);
    core->path_register(core, "/httpc/functions/post", "http_client");
    core->path_set_access(core, "/httpc/functions/post", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "httpc",
              "HTTP client ready (timeout: %ds)", g_timeout);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    if (g_ssl_ctx) { SSL_CTX_free(g_ssl_ctx); g_ssl_ctx = NULL; }
    core->path_unregister(core, "/httpc/resources/status");
    core->path_unregister(core, "/httpc/functions/get");
    core->path_unregister(core, "/httpc/functions/post");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;
    char buf[HTTPC_BUF_SIZE];

    if (strcmp(msg->path, "/httpc/resources/status") == 0) {
        int n = snprintf(buf, sizeof(buf),
            "HTTP Client\nTimeout: %ds\nRequests: %lld\nTLS: %s\n",
            g_timeout, (long long)g_requests,
            g_ssl_ctx ? "available" : "unavailable");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/httpc/functions/get") == 0) {
        const char *url = get_hdr(msg, "url");
        if (!url) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            const char *e = "Need 'url' header\n";
            portal_resp_set_body(resp, e, strlen(e));
            return -1;
        }
        if (http_request("GET", url, NULL, NULL, 0, buf, sizeof(buf)) == 0) {
            core->event_emit(core, "/events/httpc/get", url, strlen(url));
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, buf, strlen(buf));
        } else {
            portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
            int n = snprintf(buf, sizeof(buf), "Request failed: %s\n", url);
            portal_resp_set_body(resp, buf, (size_t)n);
        }
        return 0;
    }

    if (strcmp(msg->path, "/httpc/functions/post") == 0) {
        const char *url = get_hdr(msg, "url");
        const char *ct = get_hdr(msg, "content_type");
        if (!url) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
        const char *body = msg->body;
        size_t blen = msg->body_len;
        if (http_request("POST", url, ct, body, blen, buf, sizeof(buf)) == 0) {
            core->event_emit(core, "/events/httpc/post", url, strlen(url));
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, buf, strlen(buf));
        } else {
            portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
            int n = snprintf(buf, sizeof(buf), "Request failed: %s\n", url);
            portal_resp_set_body(resp, buf, (size_t)n);
        }
        return 0;
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
