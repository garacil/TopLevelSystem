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
 * mod_web — HTTP REST API Module for Portal
 *
 * Exposes all Portal paths as HTTP endpoints.
 * GET /api/core/status → sends GET to /core/status
 * POST /api/users/bob → sends SET to /users/bob
 *
 * Maps HTTP methods to Portal methods:
 *   HTTP GET    → PORTAL_METHOD_GET
 *   HTTP POST   → PORTAL_METHOD_SET
 *   HTTP PUT    → PORTAL_METHOD_CALL
 *   HTTP DELETE → PORTAL_METHOD_CALL (action=delete)
 *
 * Auth: Bearer token in Authorization header, or api_key query param.
 *
 * Config:
 *   [mod_web]
 *   port = 8080
 *   api_prefix = /api
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "portal/portal.h"
#include "ev_config.h"
#include "ev.h"

#define WEB_DEFAULT_PORT    8080
#define WEB_DEFAULT_TLS_PORT 8443
#define WEB_MAX_REQUEST     65536
#define WEB_MAX_HEADERS     64
#define WEB_API_PREFIX      "/api"

static portal_core_t *g_core = NULL;
static int             g_listen_fd = -1;
static int             g_tls_fd = -1;
static int             g_port = WEB_DEFAULT_PORT;
static int             g_tls_port = 0;  /* 0 = disabled */
static char            g_api_prefix[64] = WEB_API_PREFIX;
static char            g_bind_addr[64] = "0.0.0.0";  /* configurable bind address */
static SSL_CTX        *g_ssl_ctx = NULL;
static char            g_cert_file[PORTAL_MAX_PATH_LEN] = "";
static char            g_key_file[PORTAL_MAX_PATH_LEN] = "";

/* --- Module info --- */

static portal_module_info_t mod_info = {
    .name        = "web",
    .version     = "0.8.0",
    .description = "HTTP REST API gateway",
    .soft_deps   = NULL
};

portal_module_info_t *portal_module_info(void) { return &mod_info; }

/* --- Simple HTTP parser --- */

/* Base64 decoder for HTTP Basic Auth */
static int base64_decode(const char *in, char *out, size_t out_len)
{
    static const unsigned char d[] = {
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
        ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
        ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
        ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
        ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
        ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
        ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
        ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63
    };
    size_t len = strlen(in), o = 0;
    for (size_t i = 0; i < len && o < out_len - 1; i += 4) {
        uint32_t v = (d[(unsigned char)in[i]] << 18) |
                     (d[(unsigned char)in[i+1]] << 12) |
                     (i+2 < len ? d[(unsigned char)in[i+2]] << 6 : 0) |
                     (i+3 < len ? d[(unsigned char)in[i+3]] : 0);
        out[o++] = (char)(v >> 16);
        if (in[i+2] != '=' && o < out_len - 1) out[o++] = (char)(v >> 8);
        if (in[i+3] != '=' && o < out_len - 1) out[o++] = (char)v;
    }
    out[o] = '\0';
    return (int)o;
}

typedef struct {
    char method[16];         /* GET, POST, PUT, DELETE */
    char path[PORTAL_MAX_PATH_LEN];
    char query[1024];        /* query string */
    char auth_token[128];    /* from Bearer token or api_key */
    char basic_user[64];     /* from HTTP Basic Auth */
    char basic_pass[128];    /* from HTTP Basic Auth */
    char content_type[64];
    char body[WEB_MAX_REQUEST];
    int  body_len;
    int  keep_alive;
} http_request_t;

static int parse_http_request(const char *raw, size_t raw_len, http_request_t *req)
{
    memset(req, 0, sizeof(*req));

    /* Parse request line: METHOD /path?query HTTP/1.x */
    const char *line_end = strstr(raw, "\r\n");
    if (!line_end) return -1;

    char request_line[2048];
    size_t ll = (size_t)(line_end - raw);
    if (ll >= sizeof(request_line)) return -1;
    memcpy(request_line, raw, ll);
    request_line[ll] = '\0';

    char full_path[PORTAL_MAX_PATH_LEN];
    if (sscanf(request_line, "%15s %1023s", req->method, full_path) < 2)
        return -1;

    /* Split path and query */
    char *q = strchr(full_path, '?');
    if (q) {
        *q = '\0';
        snprintf(req->query, sizeof(req->query), "%s", q + 1);
    }
    snprintf(req->path, sizeof(req->path), "%s", full_path);

    /* Parse headers */
    const char *p = line_end + 2;
    while (p < raw + raw_len) {
        const char *next = strstr(p, "\r\n");
        if (!next || next == p) break;  /* empty line = end of headers */

        if (strncasecmp(p, "Authorization: Bearer ", 22) == 0)
            snprintf(req->auth_token, sizeof(req->auth_token), "%.*s",
                     (int)(next - p - 22), p + 22);
        else if (strncasecmp(p, "Authorization: Basic ", 21) == 0) {
            char b64[256], decoded[256];
            snprintf(b64, sizeof(b64), "%.*s", (int)(next - p - 21), p + 21);
            base64_decode(b64, decoded, sizeof(decoded));
            char *colon = strchr(decoded, ':');
            if (colon) {
                *colon = '\0';
                snprintf(req->basic_user, sizeof(req->basic_user), "%.63s", decoded);
                snprintf(req->basic_pass, sizeof(req->basic_pass), "%.127s", colon + 1);
            }
        } else if (strncasecmp(p, "Content-Type: ", 14) == 0)
            snprintf(req->content_type, sizeof(req->content_type), "%.*s",
                     (int)(next - p - 14), p + 14);

        p = next + 2;
    }

    /* Check for api_key in query string */
    if (req->auth_token[0] == '\0' && req->query[0]) {
        const char *key = strstr(req->query, "api_key=");
        if (key) {
            key += 8;
            const char *end = strchr(key, '&');
            int len = end ? (int)(end - key) : (int)strlen(key);
            snprintf(req->auth_token, sizeof(req->auth_token), "%.*s", len, key);
        }
    }

    /* Body (after blank line) — use memmem for binary-safe search */
    const char *body_start = memmem(raw, raw_len, "\r\n\r\n", 4);
    if (body_start) {
        body_start += 4;
        req->body_len = (int)(raw_len - (size_t)(body_start - raw));
        if (req->body_len > 0 && req->body_len < WEB_MAX_REQUEST)
            memcpy(req->body, body_start, (size_t)req->body_len);
    }

    return 0;
}

/* --- HTTP response builder --- */

/* Forward declaration */
static void send_http_response_conn(int fd, int status, const char *status_text,
                                     const char *content_type,
                                     const char *body, size_t body_len);

/* --- Map HTTP to Portal --- */

static uint8_t http_to_portal_method(const char *http_method)
{
    if (strcmp(http_method, "GET") == 0)    return PORTAL_METHOD_GET;
    if (strcmp(http_method, "POST") == 0)   return PORTAL_METHOD_SET;
    if (strcmp(http_method, "PUT") == 0)    return PORTAL_METHOD_CALL;
    if (strcmp(http_method, "DELETE") == 0) return PORTAL_METHOD_CALL;
    return PORTAL_METHOD_GET;
}

static void portal_status_to_http(uint16_t status, int *http_status,
                                   const char **http_text)
{
    switch (status) {
    case PORTAL_OK:            *http_status = 200; *http_text = "OK"; break;
    case PORTAL_CREATED:       *http_status = 201; *http_text = "Created"; break;
    case PORTAL_BAD_REQUEST:   *http_status = 400; *http_text = "Bad Request"; break;
    case PORTAL_UNAUTHORIZED:  *http_status = 401; *http_text = "Unauthorized"; break;
    case PORTAL_FORBIDDEN:     *http_status = 403; *http_text = "Forbidden"; break;
    case PORTAL_NOT_FOUND:     *http_status = 404; *http_text = "Not Found"; break;
    case PORTAL_INTERNAL_ERROR:*http_status = 500; *http_text = "Internal Server Error"; break;
    case PORTAL_UNAVAILABLE:   *http_status = 503; *http_text = "Service Unavailable"; break;
    default:                   *http_status = 500; *http_text = "Unknown"; break;
    }
}

/* --- Handle HTTP request ��� Portal message → HTTP response --- */

static void handle_http_request(int fd, http_request_t *req)
{
    /* Handle CORS preflight */
    if (strcmp(req->method, "OPTIONS") == 0) {
        const char *cors =
            "HTTP/1.1 204 No Content\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Authorization, Content-Type\r\n"
            "Access-Control-Max-Age: 86400\r\n"
            "\r\n";
        write(fd, cors, strlen(cors));
        return;
    }

    /* Strip API prefix to get portal path */
    const char *portal_path = req->path;
    size_t prefix_len = strlen(g_api_prefix);
    if (strncmp(portal_path, g_api_prefix, prefix_len) == 0)
        portal_path += prefix_len;

    if (portal_path[0] != '/' && portal_path[0] != '\0')
        portal_path = req->path;

    /* Strip trailing slash (except root) */
    static char clean_path[PORTAL_MAX_PATH_LEN];
    snprintf(clean_path, sizeof(clean_path), "%s", portal_path);
    size_t clen = strlen(clean_path);
    if (clen > 1 && clean_path[clen - 1] == '/')
        clean_path[clen - 1] = '\0';
    portal_path = clean_path;

    /* Root /api or /api/ — auto-generated index from live paths */
    if (portal_path[0] == '\0' || strcmp(portal_path, "/") == 0) {
        /* Query core for path list */
        portal_msg_t *idx_msg = portal_msg_alloc();
        portal_resp_t *idx_resp = portal_resp_alloc();
        if (idx_msg && idx_resp) {
            portal_msg_set_path(idx_msg, "/core/paths");
            portal_msg_set_method(idx_msg, PORTAL_METHOD_GET);
            g_core->send(g_core, idx_msg, idx_resp);

            char buf[16384];
            size_t off = 0;
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "Portal v" PORTAL_VERSION_STR " REST API\n"
                "============================================\n\n"
                "Auth: ?api_key=KEY | Authorization: Bearer TOKEN | Basic user:pass\n\n"
                "Endpoints (GET %s<path>):\n\n", g_api_prefix);

            /* Parse the path list response and format as API endpoints */
            if (idx_resp->body) {
                char *body = strdup(idx_resp->body);
                char *line = body;
                char last_prefix[64] = "";
                while (line && *line && off < sizeof(buf) - 256) {
                    char *nl = strchr(line, '\n');
                    if (nl) *nl = '\0';
                    /* Parse: "  /path/here   → module" */
                    char *arrow = strstr(line, "→");
                    if (arrow) {
                        char *path_start = line;
                        while (*path_start == ' ') path_start++;
                        char path_buf[PORTAL_MAX_PATH_LEN];
                        char mod_buf[PORTAL_MAX_MODULE_NAME];
                        if (sscanf(path_start, "%1023s", path_buf) == 1) {
                            char *m = arrow + 3;  /* skip "→ " (UTF-8 arrow is 3 bytes + space) */
                            while (*m == ' ') m++;
                            sscanf(m, "%63s", mod_buf);
                            /* Group by first segment */
                            char prefix[64];
                            const char *s = strchr(path_buf + 1, '/');
                            if (s) {
                                size_t plen = (size_t)(s - path_buf);
                                if (plen >= sizeof(prefix)) plen = sizeof(prefix) - 1;
                                memcpy(prefix, path_buf, plen);
                                prefix[plen] = '\0';
                            } else {
                                snprintf(prefix, sizeof(prefix), "%.63s", path_buf);
                            }
                            if (strcmp(prefix, last_prefix) != 0) {
                                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                                    "  [%s]\n", prefix + 1);
                                snprintf(last_prefix, sizeof(last_prefix), "%s", prefix);
                            }
                            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                                "    GET %s%-40s  [%s]\n", g_api_prefix, path_buf, mod_buf);
                        }
                    }
                    if (!nl) break;
                    line = nl + 1;
                }
                free(body);
            }
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "\nAll paths accept GET. Use POST to create, PUT to call actions.\n");

            send_http_response_conn(fd, 200, "OK", "text/plain; charset=utf-8",
                                     buf, off);
            portal_msg_free(idx_msg);
            portal_resp_free(idx_resp);
        }
        return;
    }

    /* Build portal message */
    portal_msg_t *msg = portal_msg_alloc();
    portal_resp_t *resp = portal_resp_alloc();
    if (!msg || !resp) {
        send_http_response_conn(fd, 500, "Internal Server Error",
                            "text/plain", "Out of memory\n", 14);
        return;
    }

    portal_msg_set_path(msg, portal_path);
    uint8_t method = http_to_portal_method(req->method);

    /* If "action" is in query params, override to CALL method */
    if (req->query[0] && strstr(req->query, "action="))
        method = PORTAL_METHOD_CALL;

    portal_msg_set_method(msg, method);

    if (req->body_len > 0)
        portal_msg_set_body(msg, req->body, (size_t)req->body_len);

    /* Parse query string as headers: key=value&key2=value2 */
    if (req->query[0]) {
        char qbuf[1024];
        snprintf(qbuf, sizeof(qbuf), "%s", req->query);
        char *saveptr = NULL;
        char *pair = strtok_r(qbuf, "&", &saveptr);
        while (pair) {
            char *eq = strchr(pair, '=');
            if (eq) {
                *eq = '\0';
                portal_msg_add_header(msg, pair, eq + 1);
            }
            pair = strtok_r(NULL, "&", &saveptr);
        }
    }

    /* Auth: 3 methods — Bearer token, API key, HTTP Basic Auth */
    if (req->auth_token[0]) {
        /* Bearer token or API key — attach directly */
        msg->ctx = calloc(1, sizeof(portal_ctx_t));
        if (msg->ctx)
            msg->ctx->auth.token = strdup(req->auth_token);
    } else if (req->basic_user[0]) {
        /* HTTP Basic Auth — login to get a token */
        portal_msg_t *login_msg = portal_msg_alloc();
        portal_resp_t *login_resp = portal_resp_alloc();
        if (login_msg && login_resp) {
            portal_msg_set_path(login_msg, "/auth/login");
            portal_msg_set_method(login_msg, PORTAL_METHOD_CALL);
            portal_msg_add_header(login_msg, "username", req->basic_user);
            portal_msg_add_header(login_msg, "password", req->basic_pass);
            g_core->send(g_core, login_msg, login_resp);
            if (login_resp->status == PORTAL_OK && login_resp->body) {
                /* Token is in response body (strip newline) */
                char token[128];
                snprintf(token, sizeof(token), "%s", (char *)login_resp->body);
                size_t tlen = strlen(token);
                while (tlen > 0 && (token[tlen-1] == '\n' || token[tlen-1] == '\0'))
                    token[--tlen] = '\0';
                msg->ctx = calloc(1, sizeof(portal_ctx_t));
                if (msg->ctx) {
                    msg->ctx->auth.user = strdup(req->basic_user);
                    msg->ctx->auth.token = strdup(token);
                }
            } else {
                /* Auth failed */
                send_http_response_conn(fd, 401, "Unauthorized",
                    "text/plain; charset=utf-8",
                    "Authentication failed\n", 22);
                portal_msg_free(login_msg);
                portal_resp_free(login_resp);
                portal_msg_free(msg);
                portal_resp_free(resp);
                return;
            }
            portal_msg_free(login_msg);
            portal_resp_free(login_resp);
        }
    }

    /* Route through core (ACL enforced automatically) */
    g_core->send(g_core, msg, resp);

    /* Build HTTP response */
    int http_status;
    const char *http_text;
    portal_status_to_http(resp->status, &http_status, &http_text);

    /* Strip null terminator from body_len (Portal includes it, HTTP doesn't) */
    size_t http_body_len = resp->body_len;
    if (http_body_len > 0 && resp->body &&
        ((char *)resp->body)[http_body_len - 1] == '\0')
        http_body_len--;

    /* Detect content type from path and response body */
    const char *content_type = "text/plain; charset=utf-8";
    if (http_body_len > 0 && resp->body) {
        if (strstr(portal_path, "/compress") || strstr(portal_path, "/decompress")) {
            content_type = "application/octet-stream";
            http_body_len = resp->body_len;  /* preserve binary */
        } else if (strstr(portal_path, "/admin/") ||
                   (http_body_len > 14 && strncmp(resp->body, "<!DOCTYPE", 9) == 0)) {
            content_type = "text/html; charset=utf-8";
        } else if (strstr(portal_path, "/json") ||
                   (http_body_len > 0 && ((char *)resp->body)[0] == '{')) {
            content_type = "application/json; charset=utf-8";
        }
    }

    send_http_response_conn(fd, http_status, http_text,
                        content_type,
                        resp->body, http_body_len);

    portal_msg_free(msg);
    portal_resp_free(resp);
}

/* --- Event handlers --- */

/* Per-connection context */
typedef struct {
    SSL *ssl;   /* NULL for plain HTTP */
} web_conn_t;

#define WEB_MAX_CONNS 256
static web_conn_t g_conns[WEB_MAX_CONNS];

static web_conn_t *get_conn(int fd)
{
    if (fd >= 0 && fd < WEB_MAX_CONNS) return &g_conns[fd];
    return NULL;
}

static ssize_t conn_read(int fd, void *buf, size_t len)
{
    web_conn_t *c = get_conn(fd);
    if (c && c->ssl) return SSL_read(c->ssl, buf, (int)len);
    return read(fd, buf, len);
}

static ssize_t conn_write(int fd, const void *buf, size_t len)
{
    web_conn_t *c = get_conn(fd);
    if (c && c->ssl) return SSL_write(c->ssl, buf, (int)len);
    return write(fd, buf, len);
}

static void conn_close(int fd)
{
    web_conn_t *c = get_conn(fd);
    if (c && c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
    g_core->fd_del(g_core, fd);
    close(fd);
}

/* Override send_http_response to use conn_write */
static void send_http_response_conn(int fd, int status, const char *status_text,
                                     const char *content_type,
                                     const char *body, size_t body_len)
{
    char header[1024];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, status_text,
        content_type ? content_type : "text/plain",
        body_len);
    conn_write(fd, header, (size_t)hlen);
    if (body && body_len > 0)
        conn_write(fd, body, body_len);
}

static void on_http_client(int fd, uint32_t events, void *userdata)
{
    (void)userdata;
    if (events & EV_ERROR) { conn_close(fd); return; }

    char buf[WEB_MAX_REQUEST];
    ssize_t n = conn_read(fd, buf, sizeof(buf));
    if (n <= 0) { conn_close(fd); return; }

    http_request_t req;
    if (parse_http_request(buf, (size_t)n, &req) == 0)
        handle_http_request(fd, &req);
    else
        send_http_response_conn(fd, 400, "Bad Request",
                                 "text/plain", "Invalid HTTP request\n", 20);

    conn_close(fd);
}

static void on_http_accept(int fd, uint32_t events, void *userdata)
{
    (void)events; (void)userdata;
    int client = accept(fd, NULL, NULL);
    if (client < 0) return;
    if (client < WEB_MAX_CONNS)
        g_conns[client].ssl = NULL;  /* plain HTTP */
    g_core->fd_add(g_core, client, EV_READ, on_http_client, NULL);
}

static void on_https_accept(int fd, uint32_t events, void *userdata)
{
    (void)events; (void)userdata;
    int client = accept(fd, NULL, NULL);
    if (client < 0 || client >= WEB_MAX_CONNS) {
        if (client >= 0) close(client);
        return;
    }

    SSL *ssl = SSL_new(g_ssl_ctx);
    SSL_set_fd(ssl, client);
    if (SSL_accept(ssl) <= 0) {
        g_core->log(g_core, PORTAL_LOG_WARN, "web", "TLS handshake failed");
        SSL_free(ssl);
        close(client);
        return;
    }

    g_conns[client].ssl = ssl;
    g_core->fd_add(g_core, client, EV_READ, on_http_client, NULL);
}

/* --- Module lifecycle --- */

int portal_module_load(portal_core_t *core)
{
    g_core = core;

    memset(g_conns, 0, sizeof(g_conns));

    const char *v;
    if ((v = core->config_get(core, "web", "port")))
        g_port = atoi(v);
    if ((v = core->config_get(core, "web", "tls_port")))
        g_tls_port = atoi(v);
    if ((v = core->config_get(core, "web", "api_prefix")))
        snprintf(g_api_prefix, sizeof(g_api_prefix), "%s", v);
    if ((v = core->config_get(core, "web", "cert_file")))
        snprintf(g_cert_file, sizeof(g_cert_file), "%s", v);
    if ((v = core->config_get(core, "web", "key_file")))
        snprintf(g_key_file, sizeof(g_key_file), "%s", v);
    if ((v = core->config_get(core, "web", "bind")))
        snprintf(g_bind_addr, sizeof(g_bind_addr), "%s", v);

    /* Create TCP listener */
    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) {
        core->log(core, PORTAL_LOG_ERROR, "web", "socket() failed");
        return PORTAL_MODULE_FAIL;
    }

    int opt = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, g_bind_addr, &addr.sin_addr);
    addr.sin_port = htons((uint16_t)g_port);

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        core->log(core, PORTAL_LOG_ERROR, "web", "bind(%d) failed: %s",
                  g_port, strerror(errno));
        close(g_listen_fd); g_listen_fd = -1;
        return PORTAL_MODULE_FAIL;
    }

    listen(g_listen_fd, 64);
    core->fd_add(core, g_listen_fd, EV_READ, on_http_accept, NULL);

    /* HTTPS listener (optional) */
    if (g_tls_port > 0 && g_cert_file[0] && g_key_file[0]) {
        SSL_library_init();
        SSL_load_error_strings();
        g_ssl_ctx = SSL_CTX_new(TLS_server_method());
        if (g_ssl_ctx) {
            if (SSL_CTX_use_certificate_file(g_ssl_ctx, g_cert_file,
                                              SSL_FILETYPE_PEM) <= 0 ||
                SSL_CTX_use_PrivateKey_file(g_ssl_ctx, g_key_file,
                                             SSL_FILETYPE_PEM) <= 0) {
                core->log(core, PORTAL_LOG_ERROR, "web",
                          "TLS cert/key load failed");
                SSL_CTX_free(g_ssl_ctx);
                g_ssl_ctx = NULL;
            }
        }

        if (g_ssl_ctx) {
            g_tls_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (g_tls_fd >= 0) {
                int topt = 1;
                setsockopt(g_tls_fd, SOL_SOCKET, SO_REUSEADDR, &topt, sizeof(topt));
                struct sockaddr_in taddr = {0};
                taddr.sin_family = AF_INET;
                inet_pton(AF_INET, g_bind_addr, &taddr.sin_addr);
                taddr.sin_port = htons((uint16_t)g_tls_port);
                if (bind(g_tls_fd, (struct sockaddr *)&taddr, sizeof(taddr)) == 0) {
                    listen(g_tls_fd, 64);
                    core->fd_add(core, g_tls_fd, EV_READ, on_https_accept, NULL);
                    core->log(core, PORTAL_LOG_INFO, "web",
                              "HTTPS listening on port %d", g_tls_port);
                } else {
                    core->log(core, PORTAL_LOG_ERROR, "web",
                              "HTTPS bind(%d) failed", g_tls_port);
                    close(g_tls_fd); g_tls_fd = -1;
                }
            }
        }
    }

    /* Register paths */
    core->path_register(core, "/web/resources/status", "web");
    core->path_set_access(core, "/web/resources/status", PORTAL_ACCESS_READ);

    core->log(core, PORTAL_LOG_INFO, "web",
              "HTTP API listening on port %d (prefix: %s)",
              g_port, g_api_prefix);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    if (g_listen_fd >= 0) {
        core->fd_del(core, g_listen_fd);
        close(g_listen_fd);
        g_listen_fd = -1;
    }
    if (g_tls_fd >= 0) {
        core->fd_del(core, g_tls_fd);
        close(g_tls_fd);
        g_tls_fd = -1;
    }
    if (g_ssl_ctx) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }
    core->path_unregister(core, "/web/resources/status");
    core->log(core, PORTAL_LOG_INFO, "web", "HTTP/HTTPS API stopped");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    if (strcmp(msg->path, "/web/resources/status") == 0) {
        char buf[256];
        int n = snprintf(buf, sizeof(buf),
            "HTTP REST API Gateway\n"
            "Port: %d\n"
            "Prefix: %s\n"
            "Status: listening\n",
            g_port, g_api_prefix);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n + 1);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
