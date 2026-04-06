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
 * mod_tunnel — Port forwarding through federation
 *
 * Export local services to federation, map remote services to local ports.
 * Both sides control access: remote exports, local maps.
 *
 * Export (remote node):
 *   /tunnel/functions/export?name=web&port=80&proto=tcp
 *   /tunnel/functions/unexport?name=web
 *   /tunnel/resources/exports
 *
 * Map (local node):
 *   /tunnel/functions/map?node=asus&service=web&listen=8080
 *   /tunnel/functions/unmap?listen=8080
 *   /tunnel/resources/maps
 *
 * Data flow:
 *   client → localhost:8080 → mod_tunnel → federation → asus:mod_tunnel → localhost:80
 *
 * Config persisted to /etc/portal/<instance>/tunnel/ (Law 11)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#include "portal/portal.h"

#define TUNNEL_MAX_EXPORTS  64
#define TUNNEL_MAX_MAPS     64
#define TUNNEL_BUF_SIZE     65536

/* ================================================================
 * Types
 * ================================================================ */

typedef struct {
    char     name[64];       /* service name: web, ssh, pgsql */
    int      port;           /* local port to forward */
    char     proto[8];       /* tcp or udp */
    int      active;
} tunnel_export_t;

typedef struct {
    char     node[64];       /* remote node name */
    char     service[64];    /* remote service name */
    int      remote_port;    /* remote port (filled from export list) */
    int      listen_port;    /* local listening port */
    char     proto[8];       /* tcp or udp */
    int      listen_fd;      /* listening socket */
    int      active;
    pthread_t thread;        /* acceptor thread */
    int      running;
} tunnel_map_t;

/* ================================================================
 * Globals
 * ================================================================ */

static portal_core_t  *g_core = NULL;
static tunnel_export_t g_exports[TUNNEL_MAX_EXPORTS];
static int             g_export_count = 0;
static tunnel_map_t    g_maps[TUNNEL_MAX_MAPS];
static int             g_map_count = 0;
static char            g_tunnel_dir[512] = "";

static portal_module_info_t info = {
    .name = "tunnel", .version = "1.0.0",
    .description = "Port forwarding through federation",
    .soft_deps = (const char *[]){"node", NULL}
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

/* ================================================================
 * Export management
 * ================================================================ */

static tunnel_export_t *find_export(const char *name)
{
    for (int i = 0; i < g_export_count; i++)
        if (g_exports[i].active && strcmp(g_exports[i].name, name) == 0)
            return &g_exports[i];
    return NULL;
}

static void save_export(tunnel_export_t *e)
{
    if (g_tunnel_dir[0] == '\0') return;
    char path[768];
    snprintf(path, sizeof(path), "%s/export_%s.conf", g_tunnel_dir, e->name);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f,
        "# ═══════════════════════════════════════════════════════\n"
        "# Tunnel Export: %s\n"
        "# ═══════════════════════════════════════════════════════\n"
        "#\n"
        "# name    : Service name visible to remote nodes\n"
        "# port    : Local port to expose through federation\n"
        "# proto   : Protocol (tcp or udp)\n"
        "# enabled : true = active, false = disabled\n"
        "#\n"
        "# Last updated: %ld\n"
        "# ═══════════════════════════════════════════════════════\n"
        "\n"
        "type    = export\n"
        "name    = %s\n"
        "port    = %d\n"
        "proto   = %s\n"
        "enabled = true\n",
        e->name, (long)time(NULL), e->name, e->port, e->proto);
    fclose(f);
}

static void delete_export_file(const char *name)
{
    if (g_tunnel_dir[0] == '\0') return;
    char path[768];
    snprintf(path, sizeof(path), "%s/export_%s.conf", g_tunnel_dir, name);
    unlink(path);
}

/* ================================================================
 * Map management — listener + relay threads
 * ================================================================ */

static tunnel_map_t *find_map_by_port(int port)
{
    for (int i = 0; i < g_map_count; i++)
        if (g_maps[i].active && g_maps[i].listen_port == port)
            return &g_maps[i];
    return NULL;
}

static tunnel_map_t __attribute__((unused)) *find_map_by_service(const char *node, const char *service)
{
    for (int i = 0; i < g_map_count; i++)
        if (g_maps[i].active &&
            strcmp(g_maps[i].node, node) == 0 &&
            strcmp(g_maps[i].service, service) == 0)
            return &g_maps[i];
    return NULL;
}

/* ================================================================
 * Stream sessions (remote side — used by legacy stream/data/close)
 * ================================================================ */

#define STREAM_MAX_SESSIONS  32
#define STREAM_CHUNK_SIZE    32768

typedef struct {
    int  id;
    int  fd;
    int  active;
} stream_session_t;

static stream_session_t g_sessions[STREAM_MAX_SESSIONS];
static int g_session_count = 0;
static int g_next_session_id = 1;

static stream_session_t *find_session(int id)
{
    for (int i = 0; i < g_session_count; i++)
        if (g_sessions[i].active && g_sessions[i].id == id)
            return &g_sessions[i];
    return NULL;
}

/* ================================================================
 * Raw TCP pipe — zero overhead, native speed
 *
 * Uses /node/functions/pipe to reserve a worker fd, switch it to
 * raw mode, then select() pipes bytes between client ↔ worker.
 * No encoding, no polling, no messages after initial handshake.
 * ================================================================ */

static void relay_connection(int client_fd, const char *node,
                              int remote_port)
{
    /* Step 1: Request raw pipe from mod_node */
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (!m || !r) { portal_msg_free(m); portal_resp_free(r); close(client_fd); return; }

    portal_msg_set_path(m, "/node/functions/pipe");
    portal_msg_set_method(m, PORTAL_METHOD_CALL);
    portal_msg_add_header(m, "peer", node);
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", remote_port);
    portal_msg_add_header(m, "port", port_str);

    g_core->send(g_core, m, r);

    if (r->status != PORTAL_OK || !r->body) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "tunnel",
                    "Pipe request failed for %s:%d (status %d)",
                    node, remote_port, r->status);
        portal_msg_free(m); portal_resp_free(r);
        close(client_fd);
        return;
    }

    /* Step 2: Get the raw worker fd from response */
    int worker_fd = atoi(r->body);
    portal_msg_free(m); portal_resp_free(r);

    if (worker_fd <= 0) {
        close(client_fd);
        return;
    }

    g_core->log(g_core, PORTAL_LOG_INFO, "tunnel",
                "Raw pipe: client ↔ fd %d ↔ %s:%d", worker_fd, node, remote_port);

    /* Step 3: Raw select() loop — zero overhead byte relay */
    int maxfd = (client_fd > worker_fd ? client_fd : worker_fd) + 1;
    char buf[65536];

    /* Remove any socket timeouts */
    struct timeval notv = {0, 0};
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &notv, sizeof(notv));
    setsockopt(worker_fd, SOL_SOCKET, SO_RCVTIMEO, &notv, sizeof(notv));

    while (1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(client_fd, &rfds);
        FD_SET(worker_fd, &rfds);

        int rc = select(maxfd, &rfds, NULL, NULL, NULL);
        if (rc <= 0) break;

        /* Remote → client */
        if (FD_ISSET(worker_fd, &rfds)) {
            ssize_t n = read(worker_fd, buf, sizeof(buf));
            if (n <= 0) break;
            ssize_t sent = 0;
            while (sent < n) {
                ssize_t w = write(client_fd, buf + sent, (size_t)(n - sent));
                if (w <= 0) goto done;
                sent += w;
            }
        }

        /* Client → remote */
        if (FD_ISSET(client_fd, &rfds)) {
            ssize_t n = read(client_fd, buf, sizeof(buf));
            if (n <= 0) break;
            ssize_t sent = 0;
            while (sent < n) {
                ssize_t w = write(worker_fd, buf + sent, (size_t)(n - sent));
                if (w <= 0) goto done;
                sent += w;
            }
        }
    }

done:
    close(client_fd);

    /* Worker fd returns to mod_node pool automatically when
     * the remote pipe_relay_thread detects the close */
    g_core->log(g_core, PORTAL_LOG_INFO, "tunnel",
                "Raw pipe closed: fd %d → %s:%d", worker_fd, node, remote_port);
}

/* Thread: accept connections on mapped port and relay */
static void *map_acceptor_thread(void *arg)
{
    tunnel_map_t *map = (tunnel_map_t *)arg;

    while (map->running) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int cfd = accept(map->listen_fd, (struct sockaddr *)&caddr, &clen);
        if (cfd < 0) {
            if (!map->running) break;
            continue;
        }

        g_core->log(g_core, PORTAL_LOG_INFO, "tunnel",
                    "Connection on :%d → %s:%d",
                    map->listen_port, map->node, map->remote_port);

        /* Relay in dedicated thread (allows concurrent connections) */
        /* For now: inline blocking relay (one connection at a time per map) */
        relay_connection(cfd, map->node, map->remote_port);
    }

    return NULL;
}

static int start_listener(tunnel_map_t *map)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)map->listen_port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }

    map->listen_fd = fd;
    map->running = 1;
    pthread_create(&map->thread, NULL, map_acceptor_thread, map);

    return 0;
}

static void stop_listener(tunnel_map_t *map)
{
    map->running = 0;
    if (map->listen_fd >= 0) {
        shutdown(map->listen_fd, SHUT_RDWR);
        close(map->listen_fd);
        map->listen_fd = -1;
    }
    pthread_join(map->thread, NULL);
}

static void save_map(tunnel_map_t *map)
{
    if (g_tunnel_dir[0] == '\0') return;
    char path[768];
    snprintf(path, sizeof(path), "%s/map_%s_%s_%d.conf",
             g_tunnel_dir, map->node, map->service, map->listen_port);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f,
        "# ═══════════════════════════════════════════════════════\n"
        "# Tunnel Map: %s:%s → localhost:%d\n"
        "# ═══════════════════════════════════════════════════════\n"
        "#\n"
        "# node        : Remote federation node name\n"
        "# service     : Service name exported by remote node\n"
        "# remote_port : Remote port (from export list)\n"
        "# listen_port : Local port to listen on\n"
        "# proto       : Protocol (tcp or udp)\n"
        "# enabled     : true = auto-start on load\n"
        "#\n"
        "# Last updated: %ld\n"
        "# ═══════════════════════════════════════════════════════\n"
        "\n"
        "type        = map\n"
        "node        = %s\n"
        "service     = %s\n"
        "remote_port = %d\n"
        "listen_port = %d\n"
        "proto       = %s\n"
        "enabled     = true\n",
        map->node, map->service, map->listen_port,
        (long)time(NULL),
        map->node, map->service, map->remote_port,
        map->listen_port, map->proto);
    fclose(f);
}

static void delete_map_file(tunnel_map_t *map)
{
    if (g_tunnel_dir[0] == '\0') return;
    char path[768];
    snprintf(path, sizeof(path), "%s/map_%s_%s_%d.conf",
             g_tunnel_dir, map->node, map->service, map->listen_port);
    unlink(path);
}

/* ================================================================
 * Load saved tunnels from config directory
 * ================================================================ */

static int tunnels_load_all(portal_core_t *core)
{
    if (g_tunnel_dir[0] == '\0') return 0;
    DIR *d = opendir(g_tunnel_dir);
    if (!d) return 0;

    int loaded = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        size_t nlen = strlen(ent->d_name);
        if (nlen < 6 || strcmp(ent->d_name + nlen - 5, ".conf") != 0) continue;

        char fpath[800];
        snprintf(fpath, sizeof(fpath), "%s/%s", g_tunnel_dir, ent->d_name);

        FILE *f = fopen(fpath, "r");
        if (!f) continue;

        char type[16] = "", name[64] = "", node[64] = "", service[64] = "";
        char proto[8] = "tcp";
        int port = 0, remote_port = 0, listen_port = 0, enabled = 1;
        char line[512];

        while (fgets(line, sizeof(line), f)) {
            char *s = line;
            while (*s == ' ' || *s == '\t') s++;
            if (*s == '#' || *s == '\n' || *s == '\0') continue;
            char *eq = strchr(s, '=');
            if (!eq) continue;
            *eq = '\0';
            char *key = s, *val = eq + 1;
            while (*key && key[strlen(key)-1] == ' ') key[strlen(key)-1] = '\0';
            while (*val == ' ') val++;
            char *nl = strchr(val, '\n'); if (nl) *nl = '\0';
            size_t vl = strlen(val);
            while (vl > 0 && val[vl-1] == ' ') val[--vl] = '\0';

            if (strcmp(key, "type") == 0) snprintf(type, sizeof(type), "%s", val);
            else if (strcmp(key, "name") == 0) snprintf(name, sizeof(name), "%s", val);
            else if (strcmp(key, "node") == 0) snprintf(node, sizeof(node), "%s", val);
            else if (strcmp(key, "service") == 0) snprintf(service, sizeof(service), "%s", val);
            else if (strcmp(key, "port") == 0) port = atoi(val);
            else if (strcmp(key, "remote_port") == 0) remote_port = atoi(val);
            else if (strcmp(key, "listen_port") == 0) listen_port = atoi(val);
            else if (strcmp(key, "proto") == 0) snprintf(proto, sizeof(proto), "%s", val);
            else if (strcmp(key, "enabled") == 0)
                enabled = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
        }
        fclose(f);

        if (!enabled) continue;

        if (strcmp(type, "export") == 0 && name[0] && port > 0) {
            if (g_export_count < TUNNEL_MAX_EXPORTS && !find_export(name)) {
                tunnel_export_t *e = &g_exports[g_export_count++];
                snprintf(e->name, sizeof(e->name), "%s", name);
                e->port = port;
                snprintf(e->proto, sizeof(e->proto), "%s", proto);
                e->active = 1;
                loaded++;
            }
        } else if (strcmp(type, "map") == 0 && node[0] && service[0] && listen_port > 0) {
            if (g_map_count < TUNNEL_MAX_MAPS && !find_map_by_port(listen_port)) {
                tunnel_map_t *m = &g_maps[g_map_count++];
                memset(m, 0, sizeof(*m));
                snprintf(m->node, sizeof(m->node), "%s", node);
                snprintf(m->service, sizeof(m->service), "%s", service);
                m->remote_port = remote_port;
                m->listen_port = listen_port;
                snprintf(m->proto, sizeof(m->proto), "%s", proto);
                m->listen_fd = -1;
                m->active = 1;
                /* Start listener */
                if (start_listener(m) == 0) {
                    core->log(core, PORTAL_LOG_INFO, "tunnel",
                              "Mapped %s:%s (:%d) → localhost:%d",
                              m->node, m->service, m->remote_port, m->listen_port);
                }
                loaded++;
            }
        }
    }
    closedir(d);
    return loaded;
}

/* ================================================================
 * Remote-side stream handlers
 *
 * /tunnel/functions/stream?port=22  → open TCP, return session ID
 * /tunnel/functions/data?session=X&action=write  body=bytes → write+read
 * /tunnel/functions/data?session=X&action=read   → read only
 * /tunnel/functions/close?session=X → close session
 * /tunnel/functions/connect?port=X  → legacy single-shot relay
 * ================================================================ */

static int check_exported(int port)
{
    for (int i = 0; i < g_export_count; i++)
        if (g_exports[i].active && g_exports[i].port == port)
            return 1;
    return 0;
}

static int handle_stream_open(portal_core_t *core, const portal_msg_t *msg,
                               portal_resp_t *resp)
{
    const char *port_str = get_hdr(msg, "port");
    if (!port_str) { resp->status = PORTAL_BAD_REQUEST; return -1; }
    int port = atoi(port_str);

    if (!check_exported(port)) {
        core->log(core, PORTAL_LOG_WARN, "tunnel",
                  "Stream rejected: port %d not exported", port);
        resp->status = PORTAL_FORBIDDEN;
        return -1;
    }

    /* Connect to local service */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { resp->status = PORTAL_UNAVAILABLE; return -1; }

    struct timeval tv = {1, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        core->log(core, PORTAL_LOG_ERROR, "tunnel",
                  "Cannot connect to localhost:%d", port);
        resp->status = PORTAL_UNAVAILABLE;
        return -1;
    }

    /* Create session */
    if (g_session_count >= STREAM_MAX_SESSIONS) {
        close(fd);
        resp->status = PORTAL_UNAVAILABLE;
        return -1;
    }

    stream_session_t *s = &g_sessions[g_session_count++];
    s->id = g_next_session_id++;
    s->fd = fd;
    s->active = 1;

    core->log(core, PORTAL_LOG_INFO, "tunnel",
              "Stream session %d opened → localhost:%d", s->id, port);

    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%d", s->id);
    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, buf, (size_t)n);
    return 0;
}

static int handle_stream_data(portal_core_t *core, const portal_msg_t *msg,
                               portal_resp_t *resp)
{
    (void)core;
    const char *sid_str = get_hdr(msg, "session");
    const char *action = get_hdr(msg, "action");
    if (!sid_str) { resp->status = PORTAL_BAD_REQUEST; return -1; }

    stream_session_t *s = find_session(atoi(sid_str));
    if (!s) { resp->status = PORTAL_NOT_FOUND; return -1; }

    /* Write data to local service if present */
    if (action && strcmp(action, "write") == 0 && msg->body && msg->body_len > 0) {
        write(s->fd, msg->body, msg->body_len);
    }

    /* Read available data from local service */
    char buf[STREAM_CHUNK_SIZE];
    ssize_t rd = read(s->fd, buf, sizeof(buf));

    if (rd > 0) {
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)rd);
    } else if (rd == 0) {
        /* Connection closed by local service */
        portal_resp_set_status(resp, PORTAL_GONE);
    } else {
        /* No data yet (timeout/EAGAIN) */
        portal_resp_set_status(resp, PORTAL_OK);
    }

    return 0;
}

static int handle_stream_close(portal_core_t *core, const portal_msg_t *msg,
                                portal_resp_t *resp)
{
    const char *sid_str = get_hdr(msg, "session");
    if (!sid_str) { resp->status = PORTAL_BAD_REQUEST; return -1; }

    stream_session_t *s = find_session(atoi(sid_str));
    if (!s) { resp->status = PORTAL_NOT_FOUND; return -1; }

    close(s->fd);
    s->active = 0;
    core->log(core, PORTAL_LOG_INFO, "tunnel",
              "Stream session %d closed", s->id);

    portal_resp_set_status(resp, PORTAL_OK);
    return 0;
}

static int handle_connect(portal_core_t *core, const portal_msg_t *msg,
                           portal_resp_t *resp)
{
    const char *port_str = get_hdr(msg, "port");
    if (!port_str) { resp->status = PORTAL_BAD_REQUEST; return -1; }
    int port = atoi(port_str);

    if (!check_exported(port)) {
        core->log(core, PORTAL_LOG_WARN, "tunnel",
                  "Connect rejected: port %d not exported", port);
        resp->status = PORTAL_FORBIDDEN;
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { resp->status = PORTAL_UNAVAILABLE; return -1; }

    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        resp->status = PORTAL_UNAVAILABLE;
        return -1;
    }

    if (msg->body && msg->body_len > 0)
        write(fd, msg->body, msg->body_len);

    char buf[TUNNEL_BUF_SIZE];
    ssize_t rd = read(fd, buf, sizeof(buf));
    close(fd);

    portal_resp_set_status(resp, PORTAL_OK);
    if (rd > 0)
        portal_resp_set_body(resp, buf, (size_t)rd);
    return 0;
}

/* ================================================================
 * Module lifecycle
 * ================================================================ */

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_exports, 0, sizeof(g_exports));
    memset(g_maps, 0, sizeof(g_maps));
    g_export_count = 0;
    g_map_count = 0;

    /* Resources (READ) */
    core->path_register(core, "/tunnel/resources/status", "tunnel");
    core->path_set_access(core, "/tunnel/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/tunnel/resources/exports", "tunnel");
    core->path_set_access(core, "/tunnel/resources/exports", PORTAL_ACCESS_READ);
    core->path_register(core, "/tunnel/resources/maps", "tunnel");
    core->path_set_access(core, "/tunnel/resources/maps", PORTAL_ACCESS_READ);

    /* Functions (RW) */
    core->path_register(core, "/tunnel/functions/export", "tunnel");
    core->path_set_access(core, "/tunnel/functions/export", PORTAL_ACCESS_RW);
    core->path_register(core, "/tunnel/functions/unexport", "tunnel");
    core->path_set_access(core, "/tunnel/functions/unexport", PORTAL_ACCESS_RW);
    core->path_register(core, "/tunnel/functions/map", "tunnel");
    core->path_set_access(core, "/tunnel/functions/map", PORTAL_ACCESS_RW);
    core->path_register(core, "/tunnel/functions/unmap", "tunnel");
    core->path_set_access(core, "/tunnel/functions/unmap", PORTAL_ACCESS_RW);
    core->path_register(core, "/tunnel/functions/connect", "tunnel");
    core->path_set_access(core, "/tunnel/functions/connect", PORTAL_ACCESS_RW);
    core->path_register(core, "/tunnel/functions/stream", "tunnel");
    core->path_set_access(core, "/tunnel/functions/stream", PORTAL_ACCESS_RW);
    core->path_register(core, "/tunnel/functions/data", "tunnel");
    core->path_set_access(core, "/tunnel/functions/data", PORTAL_ACCESS_RW);
    core->path_register(core, "/tunnel/functions/close", "tunnel");
    core->path_set_access(core, "/tunnel/functions/close", PORTAL_ACCESS_RW);

    /* Persistence directory */
    const char *data_dir = core->config_get(core, "core", "data_dir");
    if (data_dir) {
        snprintf(g_tunnel_dir, sizeof(g_tunnel_dir), "%s/tunnel", data_dir);
        mkdir(g_tunnel_dir, 0755);
    }

    int loaded = tunnels_load_all(core);

    core->log(core, PORTAL_LOG_INFO, "tunnel",
              "Tunnel ready (exports: %d, maps: %d, loaded: %d)",
              g_export_count, g_map_count, loaded);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    /* Stop all map listeners */
    for (int i = 0; i < g_map_count; i++)
        if (g_maps[i].active && g_maps[i].running)
            stop_listener(&g_maps[i]);

    core->path_unregister(core, "/tunnel/resources/status");
    core->path_unregister(core, "/tunnel/resources/exports");
    core->path_unregister(core, "/tunnel/resources/maps");
    core->path_unregister(core, "/tunnel/functions/export");
    core->path_unregister(core, "/tunnel/functions/unexport");
    core->path_unregister(core, "/tunnel/functions/map");
    core->path_unregister(core, "/tunnel/functions/unmap");
    core->path_unregister(core, "/tunnel/functions/connect");
    core->path_unregister(core, "/tunnel/functions/stream");
    core->path_unregister(core, "/tunnel/functions/data");
    core->path_unregister(core, "/tunnel/functions/close");

    /* Close active stream sessions */
    for (int i = 0; i < g_session_count; i++)
        if (g_sessions[i].active) { close(g_sessions[i].fd); g_sessions[i].active = 0; }
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

/* ================================================================
 * Request handler
 * ================================================================ */

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[8192];
    int n;

    /* --- /tunnel/resources/status --- */
    if (strcmp(msg->path, "/tunnel/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "Tunnel Port Forwarding\n"
            "Exports: %d (max %d)\n"
            "Maps: %d (max %d)\n"
            "Config: %s\n",
            g_export_count, TUNNEL_MAX_EXPORTS,
            g_map_count, TUNNEL_MAX_MAPS,
            g_tunnel_dir[0] ? g_tunnel_dir : "(none)");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* --- /tunnel/resources/exports --- */
    if (strcmp(msg->path, "/tunnel/resources/exports") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
            "%-16s %-8s %s\n", "NAME", "PORT", "PROTO");
        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
            "%-16s %-8s %s\n", "----", "----", "-----");
        for (int i = 0; i < g_export_count; i++) {
            if (!g_exports[i].active) continue;
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "%-16s %-8d %s\n",
                g_exports[i].name, g_exports[i].port, g_exports[i].proto);
        }
        if (g_export_count == 0)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "(none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    /* --- /tunnel/resources/maps --- */
    if (strcmp(msg->path, "/tunnel/resources/maps") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
            "%-12s %-12s %-8s %-8s %s\n",
            "NODE", "SERVICE", "REMOTE", "LOCAL", "STATUS");
        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
            "%-12s %-12s %-8s %-8s %s\n",
            "----", "-------", "------", "-----", "------");
        for (int i = 0; i < g_map_count; i++) {
            if (!g_maps[i].active) continue;
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "%-12s %-12s %-8d %-8d %s\n",
                g_maps[i].node, g_maps[i].service,
                g_maps[i].remote_port, g_maps[i].listen_port,
                g_maps[i].running ? "ACTIVE" : "STOPPED");
        }
        if (g_map_count == 0)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "(none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    /* --- /tunnel/functions/export --- */
    if (strcmp(msg->path, "/tunnel/functions/export") == 0) {
        const char *name = get_hdr(msg, "name");
        const char *port_str = get_hdr(msg, "port");
        const char *proto = get_hdr(msg, "proto");
        if (!name || !port_str) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: name, port. Optional: proto (default tcp)\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (find_export(name)) {
            portal_resp_set_status(resp, PORTAL_CONFLICT);
            n = snprintf(buf, sizeof(buf), "Export '%s' already exists\n", name);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (g_export_count >= TUNNEL_MAX_EXPORTS) {
            portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
            return -1;
        }

        tunnel_export_t *e = &g_exports[g_export_count++];
        snprintf(e->name, sizeof(e->name), "%s", name);
        e->port = atoi(port_str);
        snprintf(e->proto, sizeof(e->proto), "%s", proto ? proto : "tcp");
        e->active = 1;
        save_export(e);

        core->event_emit(core, "/events/tunnel/exported", name, strlen(name));
        core->log(core, PORTAL_LOG_INFO, "tunnel",
                  "Exported '%s' (%s:%d)", name, e->proto, e->port);

        portal_resp_set_status(resp, PORTAL_CREATED);
        n = snprintf(buf, sizeof(buf), "Exported '%s' (%s:%d)\n",
                     name, e->proto, e->port);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* --- /tunnel/functions/unexport --- */
    if (strcmp(msg->path, "/tunnel/functions/unexport") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        tunnel_export_t *e = find_export(name);
        if (!e) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        e->active = 0;
        delete_export_file(name);
        core->event_emit(core, "/events/tunnel/unexported", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Unexported '%s'\n", name);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* --- /tunnel/functions/map --- */
    if (strcmp(msg->path, "/tunnel/functions/map") == 0) {
        const char *node = get_hdr(msg, "node");
        const char *service = get_hdr(msg, "service");
        const char *listen_str = get_hdr(msg, "listen");
        if (!node || !service || !listen_str) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: node, service, listen\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        int listen_port = atoi(listen_str);
        if (find_map_by_port(listen_port)) {
            portal_resp_set_status(resp, PORTAL_CONFLICT);
            n = snprintf(buf, sizeof(buf), "Port %d already mapped\n", listen_port);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        /* Query remote node for export info */
        int remote_port = 0;
        char rpath[256];
        snprintf(rpath, sizeof(rpath), "/%s/tunnel/resources/exports", node);
        portal_msg_t *qm = portal_msg_alloc();
        portal_resp_t *qr = portal_resp_alloc();
        if (qm && qr) {
            portal_msg_set_path(qm, rpath);
            portal_msg_set_method(qm, PORTAL_METHOD_GET);
            core->send(core, qm, qr);
            if (qr->body) {
                /* Parse exports to find the service port */
                char *line = qr->body;
                while (line && *line) {
                    char *nl = strchr(line, '\n');
                    if (nl) *nl = '\0';
                    char sname[64];
                    int sport;
                    if (sscanf(line, "%63s %d", sname, &sport) == 2) {
                        if (strcmp(sname, service) == 0) {
                            remote_port = sport;
                            break;
                        }
                    }
                    if (nl) line = nl + 1; else break;
                }
            }
            portal_msg_free(qm);
            portal_resp_free(qr);
        }

        if (remote_port == 0) {
            /* Try using service as port number directly */
            remote_port = atoi(service);
            if (remote_port <= 0) {
                portal_resp_set_status(resp, PORTAL_NOT_FOUND);
                n = snprintf(buf, sizeof(buf),
                    "Service '%s' not found on node '%s'\n", service, node);
                portal_resp_set_body(resp, buf, (size_t)n);
                return -1;
            }
        }

        if (g_map_count >= TUNNEL_MAX_MAPS) {
            portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
            return -1;
        }

        tunnel_map_t *m = &g_maps[g_map_count++];
        memset(m, 0, sizeof(*m));
        snprintf(m->node, sizeof(m->node), "%s", node);
        snprintf(m->service, sizeof(m->service), "%s", service);
        m->remote_port = remote_port;
        m->listen_port = listen_port;
        snprintf(m->proto, sizeof(m->proto), "tcp");
        m->listen_fd = -1;
        m->active = 1;

        if (start_listener(m) < 0) {
            m->active = 0;
            g_map_count--;
            portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
            n = snprintf(buf, sizeof(buf), "Failed to listen on port %d\n", listen_port);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        save_map(m);
        core->event_emit(core, "/events/tunnel/mapped", node, strlen(node));
        core->log(core, PORTAL_LOG_INFO, "tunnel",
                  "Mapped %s:%s (:%d) → localhost:%d",
                  node, service, remote_port, listen_port);

        portal_resp_set_status(resp, PORTAL_CREATED);
        n = snprintf(buf, sizeof(buf),
            "Mapped %s:%s (:%d) → localhost:%d\n",
            node, service, remote_port, listen_port);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* --- /tunnel/functions/unmap --- */
    if (strcmp(msg->path, "/tunnel/functions/unmap") == 0) {
        const char *listen_str = get_hdr(msg, "listen");
        if (!listen_str) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        int listen_port = atoi(listen_str);
        tunnel_map_t *m = find_map_by_port(listen_port);
        if (!m) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        stop_listener(m);
        delete_map_file(m);
        m->active = 0;
        core->event_emit(core, "/events/tunnel/unmapped",
                         listen_str, strlen(listen_str));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Unmapped localhost:%d\n", listen_port);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* --- /tunnel/functions/stream --- (open stream session) */
    if (strcmp(msg->path, "/tunnel/functions/stream") == 0)
        return handle_stream_open(core, msg, resp);

    /* --- /tunnel/functions/data --- (read/write stream data) */
    if (strcmp(msg->path, "/tunnel/functions/data") == 0)
        return handle_stream_data(core, msg, resp);

    /* --- /tunnel/functions/close --- (close stream session) */
    if (strcmp(msg->path, "/tunnel/functions/close") == 0)
        return handle_stream_close(core, msg, resp);

    /* --- /tunnel/functions/connect --- (legacy single-shot) */
    if (strcmp(msg->path, "/tunnel/functions/connect") == 0)
        return handle_connect(core, msg, resp);

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
