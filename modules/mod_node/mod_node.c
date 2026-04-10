/*
 * mod_node — Node Federation Module
 *
 * Connects Portal instances into a distributed network.
 * Remote paths transparently accessible as /node_name/path.
 * Wire protocol (PORTAL02) over TCP/TLS with thread pool per peer.
 *
 * Features:
 *   - TLS encryption (OpenSSL, optional, self-signed or CA certs)
 *   - Federation key (SHA-256 shared secret in handshake)
 *   - Hub routing (NAT nodes reach each other through public hub)
 *   - Peer advertisement (handshake shares connected peer list)
 *   - Auto-reconnect (core timer, detects stuck/dead peers, retries)
 *   - TCP keepalive (idle=60s, interval=30s, count=3 — NAT safe)
 *   - Indirect peer cascade (hub dies -> indirects removed, recreated on reconnect)
 *   - Traffic counters (msgs/bytes sent/recv per peer)
 *   - Diagnostics: ping, tracert, node status with latency
 *   - Location/GPS (manual or auto-geolocate from IP)
 *   - Raw TCP pipe for port forwarding (tunnel support)
 *
 * Config:
 *   [mod_node]
 *   listen_port      = 9700
 *   node_name        = local
 *   threads_per_peer = 4
 *   tls              = false
 *   cert_file        = /etc/portal/<instance>/certs/server.crt
 *   key_file         = /etc/portal/<instance>/certs/server.key
 *   tls_verify       = false
 *   federation_key   = shared-secret
 *   location         = City, Country
 *   gps              = lat,lon
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

#ifdef HAS_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include "portal/portal.h"
#include "ev_config.h"
#include "ev.h"

extern int     portal_wire_encode_msg(const portal_msg_t *msg, uint8_t **buf, size_t *len);
extern int     portal_wire_decode_msg(const uint8_t *buf, size_t len, portal_msg_t *msg);
extern int     portal_wire_encode_resp(const portal_resp_t *resp, uint8_t **buf, size_t *len);
extern int     portal_wire_decode_resp(const uint8_t *buf, size_t len, portal_resp_t *resp);
extern int32_t portal_wire_read_length(const uint8_t *buf);

#define NODE_MAX_PEERS        2048
#define NODE_MAX_THREADS      16
#define NODE_BUF_SIZE         65536
#define NODE_DEFAULT_PORT     9700
#define NODE_DEFAULT_THREADS  4
#define NODE_HANDSHAKE_MAGIC  "PORTAL02"
#define NODE_RECONNECT_SEC    10
#define NODE_MAX_FDS          8192
#define NODE_PEER_MAX_PATHS   32      /* paths registered per remote peer (was 256) */
#define NODE_PEER_PATH_LEN    256     /* max path length per peer (was 1024) */
#define NODE_KEY_HASH_LEN     32   /* SHA-256 hash of federation key */

/* --- Federation key (authentication) --- */
static char     g_federation_key[256] = "";
static uint8_t  g_key_hash[NODE_KEY_HASH_LEN]; /* SHA-256 of federation_key */
static int      g_has_key = 0;

/* SHA-256 for federation key (from lib/sha256) */
#include "sha256.h"

static void compute_sha256(const uint8_t *data, size_t len, uint8_t *out)
{
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

/* --- TLS state --- */

#ifdef HAS_SSL
static SSL_CTX *g_ssl_server_ctx = NULL;
static SSL_CTX *g_ssl_client_ctx = NULL;
static int      g_tls_enabled = 0;
static char     g_cert_file[PORTAL_MAX_PATH_LEN] = "";
static char     g_key_file[PORTAL_MAX_PATH_LEN] = "";
static int      g_tls_verify = 0;
static SSL     *g_fd_ssl[NODE_MAX_FDS]; /* fd → SSL* lookup */
#endif

/* --- Thread pool for outbound requests --- */

typedef struct {
    int            fd;          /* persistent TCP connection */
    int            busy;        /* 1 = processing a request, 2 = pipe mode */
    pthread_t      thread;
    int            running;
#ifdef HAS_SSL
    SSL           *ssl;
#endif
} worker_t;

typedef struct {
    char           name[PORTAL_MAX_MODULE_NAME];
    char           host[256];
    int            port;
    int            ctrl_fd;     /* control connection (handshake, inbound) */
#ifdef HAS_SSL
    SSL           *ctrl_ssl;
#endif
    int            is_inbound;
    int            is_indirect; /* 1 = reachable through hub peer, not direct */
    int            hub_idx;     /* index into g_peers[] of the hub peer */
    int            ready;
    int            dead;        /* 1 = connection lost, needs reconnect */
    char           cfg_host[256]; /* original config host (for reconnect) */
    int            cfg_port;      /* original config port (for reconnect) */
    worker_t       workers[NODE_MAX_THREADS];
    int            worker_count;
    int            next_worker;  /* round-robin index */
    pthread_mutex_t lock;
    char           paths[NODE_PEER_MAX_PATHS][NODE_PEER_PATH_LEN];
    int            path_count;
    /* Traffic counters */
    uint64_t       msgs_sent;
    uint64_t       msgs_recv;
    uint64_t       bytes_sent;
    uint64_t       bytes_recv;
    uint64_t       errors;
    time_t         connected_at;
} node_peer_t;

typedef struct {
    int worker_fd;    /* federation TCP connection */
    int service_fd;   /* local TCP to service (e.g. localhost:22) */
#ifdef HAS_SSL
    SSL *worker_ssl;  /* TLS on federation side; service stays plain */
#endif
} pipe_ctx_t;

/* Module state */
static portal_core_t *g_core = NULL;
static int             g_listen_fd = -1;
static int             g_listen_port = NODE_DEFAULT_PORT;
static int             g_threads_per_peer = NODE_DEFAULT_THREADS;
static char            g_node_name[PORTAL_MAX_MODULE_NAME] = "local";
static char            g_location[256] = "";
static char            g_gps[64] = "";       /* "lat,lon" */
static node_peer_t     g_peers[NODE_MAX_PEERS];
static int             g_peer_count = 0;

static portal_module_info_t mod_info = {
    .name        = "node",
    .version     = "0.4.0",
    .description = "Node federation over TCP/TLS (threaded, hub routing)",
    .soft_deps   = NULL
};

portal_module_info_t *portal_module_info(void) { return &mod_info; }

/* ================================================================
 * I/O helpers — plain TCP and TLS-aware wrappers
 * ================================================================ */

static int send_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) return -1;
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) return -1;
        p += n; len -= (size_t)n;
    }
    return 0;
}

#ifdef HAS_SSL
static int ssl_send_all(SSL *ssl, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len > 0) {
        int n = SSL_write(ssl, p, (int)len);
        if (n <= 0) return -1;
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int ssl_recv_all(SSL *ssl, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len > 0) {
        int n = SSL_read(ssl, p, (int)len);
        if (n <= 0) return -1;
        p += n; len -= (size_t)n;
    }
    return 0;
}

static ssize_t ssl_read_partial(SSL *ssl, void *buf, size_t len)
{
    int n = SSL_read(ssl, buf, (int)len);
    return (ssize_t)n;
}
#endif

/* Unified I/O: SSL if available, else plain fd */
static int node_send(int fd, void *ssl_ptr, const void *buf, size_t len)
{
#ifdef HAS_SSL
    SSL *ssl = (SSL *)ssl_ptr;
    if (ssl) return ssl_send_all(ssl, buf, len);
#else
    (void)ssl_ptr;
#endif
    return send_all(fd, buf, len);
}

static int node_recv(int fd, void *ssl_ptr, void *buf, size_t len)
{
#ifdef HAS_SSL
    SSL *ssl = (SSL *)ssl_ptr;
    if (ssl) return ssl_recv_all(ssl, buf, len);
#else
    (void)ssl_ptr;
#endif
    return recv_all(fd, buf, len);
}

static ssize_t node_read_partial(int fd, void *ssl_ptr, void *buf, size_t len)
{
#ifdef HAS_SSL
    SSL *ssl = (SSL *)ssl_ptr;
    if (ssl) return ssl_read_partial(ssl, buf, len);
#else
    (void)ssl_ptr;
#endif
    return read(fd, buf, len);
}

/* ================================================================
 * TLS handshake helpers
 * ================================================================ */

#ifdef HAS_SSL
static void fd_ssl_set(int fd, SSL *ssl)
{
    if (fd >= 0 && fd < NODE_MAX_FDS)
        g_fd_ssl[fd] = ssl;
}

static SSL *fd_ssl_get(int fd)
{
    if (fd >= 0 && fd < NODE_MAX_FDS)
        return g_fd_ssl[fd];
    return NULL;
}

static void fd_ssl_clear(int fd)
{
    if (fd >= 0 && fd < NODE_MAX_FDS)
        g_fd_ssl[fd] = NULL;
}

static SSL *node_tls_connect(int fd)
{
    if (!g_tls_enabled || !g_ssl_client_ctx) return NULL;
    SSL *ssl = SSL_new(g_ssl_client_ctx);
    if (!ssl) return NULL;
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) <= 0) {
        if (g_core)
            g_core->log(g_core, PORTAL_LOG_WARN, "node",
                        "TLS connect failed on fd %d", fd);
        SSL_free(ssl);
        return NULL;
    }
    fd_ssl_set(fd, ssl);
    return ssl;
}

static SSL *node_tls_accept(int fd)
{
    if (!g_tls_enabled || !g_ssl_server_ctx) return NULL;
    SSL *ssl = SSL_new(g_ssl_server_ctx);
    if (!ssl) return NULL;
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) <= 0) {
        if (g_core)
            g_core->log(g_core, PORTAL_LOG_WARN, "node",
                        "TLS accept failed on fd %d", fd);
        SSL_free(ssl);
        return NULL;
    }
    fd_ssl_set(fd, ssl);
    return ssl;
}

static void node_ssl_close(int fd, SSL *ssl)
{
    if (ssl) {
        /* Skip SSL_shutdown — just free. Shutdown on dead connections
         * can segfault on some OpenSSL versions (1.1.1 on Ubuntu 18.04) */
        SSL_free(ssl);
    }
    fd_ssl_clear(fd);
}

static int init_tls_contexts(void)
{
    SSL_library_init();
    SSL_load_error_strings();

    /* Server context (for accepting inbound peers) */
    g_ssl_server_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ssl_server_ctx) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "node",
                    "Failed to create TLS server context");
        return -1;
    }
    if (SSL_CTX_use_certificate_file(g_ssl_server_ctx, g_cert_file,
                                      SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(g_ssl_server_ctx, g_key_file,
                                     SSL_FILETYPE_PEM) <= 0) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "node",
                    "TLS cert/key load failed: %s / %s", g_cert_file, g_key_file);
        SSL_CTX_free(g_ssl_server_ctx);
        g_ssl_server_ctx = NULL;
        return -1;
    }

    /* Client context (for outbound connections) */
    g_ssl_client_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_client_ctx) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "node",
                    "Failed to create TLS client context");
        SSL_CTX_free(g_ssl_server_ctx);
        g_ssl_server_ctx = NULL;
        return -1;
    }
    if (!g_tls_verify)
        SSL_CTX_set_verify(g_ssl_client_ctx, SSL_VERIFY_NONE, NULL);

    return 0;
}

static void free_tls_contexts(void)
{
    if (g_ssl_server_ctx) { SSL_CTX_free(g_ssl_server_ctx); g_ssl_server_ctx = NULL; }
    if (g_ssl_client_ctx) { SSL_CTX_free(g_ssl_client_ctx); g_ssl_client_ctx = NULL; }
}

static int reload_tls_contexts(void)
{
    /* Create new contexts, swap, free old */
    SSL_CTX *old_server = g_ssl_server_ctx;
    SSL_CTX *old_client = g_ssl_client_ctx;
    g_ssl_server_ctx = NULL;
    g_ssl_client_ctx = NULL;

    if (init_tls_contexts() < 0) {
        /* Restore old on failure */
        g_ssl_server_ctx = old_server;
        g_ssl_client_ctx = old_client;
        return -1;
    }

    /* Free old (existing SSL* objects hold their own ref) */
    if (old_server) SSL_CTX_free(old_server);
    if (old_client) SSL_CTX_free(old_client);

    g_core->log(g_core, PORTAL_LOG_INFO, "node",
                "TLS contexts reloaded from %s", g_cert_file);
    return 0;
}
#endif /* HAS_SSL */

/* ================================================================
 * Wire protocol handshake (runs AFTER TLS handshake if enabled)
 * ================================================================ */

/*
 * Handshake format (PORTAL02):
 *   8 bytes: magic "PORTAL02"
 *  32 bytes: SHA-256 of federation_key (or zeros if no key)
 *   2 bytes: node name length (big-endian)
 *   N bytes: node name
 *   2 bytes: peer count (number of connected peer names)
 *   For each peer:
 *     2 bytes: name length
 *     N bytes: name
 */
static int send_handshake(int fd, void *ssl)
{
    uint8_t buf[4096];
    uint8_t *p = buf;
    memcpy(p, NODE_HANDSHAKE_MAGIC, 8); p += 8;

    /* Federation key hash (32 bytes) */
    if (g_has_key)
        memcpy(p, g_key_hash, NODE_KEY_HASH_LEN);
    else
        memset(p, 0, NODE_KEY_HASH_LEN);
    p += NODE_KEY_HASH_LEN;

    /* Node name */
    uint16_t nlen = (uint16_t)strlen(g_node_name);
    p[0] = nlen >> 8; p[1] = nlen & 0xff; p += 2;
    memcpy(p, g_node_name, nlen); p += nlen;

    /* Advertise connected peer names (for hub discovery) */
    int peer_adv_count = 0;
    uint8_t *count_pos = p;
    p += 2;  /* reserve 2 bytes for count */
    for (int i = 0; i < g_peer_count; i++) {
        if (!g_peers[i].ready || g_peers[i].is_indirect) continue;
        uint16_t pnlen = (uint16_t)strlen(g_peers[i].name);
        if (p + 2 + pnlen > buf + sizeof(buf) - 2) break;
        p[0] = pnlen >> 8; p[1] = pnlen & 0xff; p += 2;
        memcpy(p, g_peers[i].name, pnlen); p += pnlen;
        peer_adv_count++;
    }
    count_pos[0] = (uint8_t)(peer_adv_count >> 8);
    count_pos[1] = (uint8_t)(peer_adv_count & 0xff);

    return node_send(fd, ssl, buf, (size_t)(p - buf));
}

static int recv_handshake(int fd, void *ssl, char *peer_name, size_t name_size,
                           char advertised[][PORTAL_MAX_MODULE_NAME], int *adv_count)
{
    uint8_t hdr[8 + NODE_KEY_HASH_LEN + 2];  /* magic + key_hash + name_len */
    if (node_recv(fd, ssl, hdr, sizeof(hdr)) < 0) return -1;
    if (memcmp(hdr, NODE_HANDSHAKE_MAGIC, 8) != 0) return -1;

    /* Verify federation key */
    uint8_t *remote_hash = hdr + 8;
    if (g_has_key) {
        if (memcmp(remote_hash, g_key_hash, NODE_KEY_HASH_LEN) != 0) {
            if (g_core)
                g_core->log(g_core, PORTAL_LOG_WARN, "node",
                            "Federation key mismatch — rejecting peer");
            return -2;  /* auth failure */
        }
    }

    /* Read node name */
    uint16_t nlen = ((uint16_t)hdr[8 + NODE_KEY_HASH_LEN] << 8)
                   | hdr[8 + NODE_KEY_HASH_LEN + 1];
    if (nlen >= name_size) return -1;
    if (node_recv(fd, ssl, peer_name, nlen) < 0) return -1;
    peer_name[nlen] = '\0';

    /* Read advertised peer count + names */
    uint8_t pc[2];
    if (node_recv(fd, ssl, pc, 2) < 0) return -1;
    int count = ((int)pc[0] << 8) | pc[1];
    if (adv_count) *adv_count = 0;

    for (int i = 0; i < count; i++) {
        uint8_t pnl[2];
        if (node_recv(fd, ssl, pnl, 2) < 0) return -1;
        uint16_t pnlen = ((uint16_t)pnl[0] << 8) | pnl[1];
        if (pnlen >= PORTAL_MAX_MODULE_NAME) {
            /* Skip oversized name */
            char skip[256];
            node_recv(fd, ssl, skip, pnlen < 256 ? pnlen : 256);
            continue;
        }
        char pname[PORTAL_MAX_MODULE_NAME];
        if (node_recv(fd, ssl, pname, pnlen) < 0) return -1;
        pname[pnlen] = '\0';

        /* Store if caller wants it */
        if (advertised && adv_count && *adv_count < NODE_MAX_PEERS) {
            snprintf(advertised[*adv_count], PORTAL_MAX_MODULE_NAME, "%s", pname);
            (*adv_count)++;
        }
    }

    return 0;
}

/* Create a TCP connection to a peer */
static int create_connection(const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* TCP keepalive: prevents NAT table expiry on idle connections */
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
#ifdef TCP_KEEPIDLE
    int idle = 60;      /* start keepalive after 60s idle */
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
#endif
#ifdef TCP_KEEPINTVL
    int intvl = 30;     /* send keepalive every 30s */
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
#endif
#ifdef TCP_KEEPCNT
    int cnt = 3;        /* 3 failed keepalives = dead */
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) { close(fd); return -1; }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    return fd;
}

/* Forward declarations */
static void on_inbound_data(int fd, uint32_t events, void *userdata);
static void mark_peer_dead_by_fd(int fd);
static void reconnect_dead_peers(void);

/* --- Worker thread pool --- */

/* Register an indirect (hub-proxied) peer */
static void register_indirect_peer(const char *name, int hub_idx)
{
    /* Don't register ourselves or already-known peers */
    if (strcmp(name, g_node_name) == 0) return;
    for (int i = 0; i < g_peer_count; i++)
        if (strcmp(g_peers[i].name, name) == 0) return;
    if (g_peer_count >= NODE_MAX_PEERS) return;

    node_peer_t *peer = &g_peers[g_peer_count++];
    memset(peer, 0, sizeof(*peer));
    pthread_mutex_init(&peer->lock, NULL);
    snprintf(peer->name, sizeof(peer->name), "%s", name);
    peer->ctrl_fd = -1;
    peer->is_inbound = 0;
    peer->is_indirect = 1;
    peer->hub_idx = hub_idx;
    peer->worker_count = 0;
    peer->ready = 1;
    peer->connected_at = time(NULL);

    /* Register wildcard path */
    char path[PORTAL_MAX_PATH_LEN];
    snprintf(path, sizeof(path), "/%s/*", name);
    if (g_core->path_register(g_core, path, "node") == 0) {
        g_core->path_set_access(g_core, path, PORTAL_ACCESS_RW);
        snprintf(peer->paths[0], NODE_PEER_PATH_LEN, "%.*s",
                (int)(NODE_PEER_PATH_LEN - 1), path);
        peer->path_count = 1;
        g_core->log(g_core, PORTAL_LOG_INFO, "node",
                    "Indirect peer '%s' via hub '%s'",
                    name, g_peers[hub_idx].name);
    }
}

static int create_worker_connections(node_peer_t *peer)
{
    for (int i = 0; i < peer->worker_count; i++) {
        if (peer->is_inbound) {
            peer->workers[i].fd = -1;
#ifdef HAS_SSL
            peer->workers[i].ssl = NULL;
#endif
        } else {
            peer->workers[i].fd = create_connection(peer->host, peer->port);
            if (peer->workers[i].fd >= 0) {
                void *ssl = NULL;
#ifdef HAS_SSL
                if (g_tls_enabled) {
                    ssl = node_tls_connect(peer->workers[i].fd);
                    if (!ssl && g_tls_enabled) {
                        close(peer->workers[i].fd);
                        peer->workers[i].fd = -1;
                        continue;
                    }
                }
                peer->workers[i].ssl = ssl;
#endif
                send_handshake(peer->workers[i].fd, ssl);
                char dummy[64];
                recv_handshake(peer->workers[i].fd, ssl, dummy, sizeof(dummy),
                               NULL, NULL);
                g_core->fd_add(g_core, peer->workers[i].fd,
                               EV_READ, on_inbound_data, NULL);
            }
        }
        peer->workers[i].busy = 0;
    }
    return 0;
}

static node_peer_t *find_peer_by_name(const char *name)
{
    for (int i = 0; i < g_peer_count; i++)
        if (strcmp(g_peers[i].name, name) == 0 && g_peers[i].ready)
            return &g_peers[i];
    return NULL;
}

/* Find peer by fd (for inbound counter tracking) */
static node_peer_t *find_peer_by_fd(int fd)
{
    for (int i = 0; i < g_peer_count; i++) {
        node_peer_t *p = &g_peers[i];
        if (p->ctrl_fd == fd) return p;
        for (int j = 0; j < p->worker_count; j++)
            if (p->workers[j].fd == fd) return p;
    }
    return NULL;
}

/* Find peer by name regardless of state (for status queries) */
static node_peer_t *find_peer_any(const char *name)
{
    for (int i = 0; i < g_peer_count; i++)
        if (strcmp(g_peers[i].name, name) == 0)
            return &g_peers[i];
    return NULL;
}

/* Get current time in microseconds */
static uint64_t now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

static worker_t *get_worker(node_peer_t *peer)
{
    pthread_mutex_lock(&peer->lock);
    for (int attempt = 0; attempt < peer->worker_count; attempt++) {
        int idx = (peer->next_worker + attempt) % peer->worker_count;
        if (!peer->workers[idx].busy && peer->workers[idx].fd >= 0) {
            peer->workers[idx].busy = 1;
            peer->next_worker = (idx + 1) % peer->worker_count;
            pthread_mutex_unlock(&peer->lock);
            g_core->fd_del(g_core, peer->workers[idx].fd);
            return &peer->workers[idx];
        }
    }
    int idx = peer->next_worker;
    peer->next_worker = (idx + 1) % peer->worker_count;
    pthread_mutex_unlock(&peer->lock);
    g_core->fd_del(g_core, peer->workers[idx].fd);
    return &peer->workers[idx];
}

static void release_worker(node_peer_t *peer, worker_t *w)
{
    (void)peer;
    w->busy = 0;
    g_core->fd_add(g_core, w->fd, EV_READ, on_inbound_data, NULL);
}

/* Send a message through a worker and read response */
static int worker_send_recv(worker_t *w, const portal_msg_t *msg,
                             portal_resp_t *resp)
{
    struct timeval tv = {30, 0};
    setsockopt(w->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(w->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    void *ssl = NULL;
#ifdef HAS_SSL
    ssl = w->ssl;
#endif

    uint8_t *wire_buf = NULL;
    size_t wire_len = 0;
    if (portal_wire_encode_msg(msg, &wire_buf, &wire_len) < 0)
        return -1;

    if (node_send(w->fd, ssl, wire_buf, wire_len) < 0) {
        free(wire_buf);
        return -1;
    }
    free(wire_buf);

    uint8_t hdr[4];
    if (node_recv(w->fd, ssl, hdr, 4) < 0) return -1;

    int32_t resp_len = portal_wire_read_length(hdr);
    if (resp_len <= 0 || resp_len > NODE_BUF_SIZE) return -1;

    uint8_t *resp_buf = malloc((size_t)resp_len + 4);
    memcpy(resp_buf, hdr, 4);
    if (node_recv(w->fd, ssl, resp_buf + 4, (size_t)resp_len) < 0) {
        free(resp_buf);
        return -1;
    }

    int rc = portal_wire_decode_resp(resp_buf, (size_t)resp_len + 4, resp);
    free(resp_buf);
    return rc;
}

/* ================================================================
 * Raw TCP pipe — byte relay through worker fd
 * Federation side uses TLS if enabled, local service stays plain.
 * ================================================================ */

static void *pipe_relay_thread(void *arg)
{
    pipe_ctx_t *ctx = (pipe_ctx_t *)arg;
    int wfd = ctx->worker_fd;
    int sfd = ctx->service_fd;
    int maxfd = (wfd > sfd ? wfd : sfd) + 1;
    char buf[65536];
    void *wssl = NULL;

#ifdef HAS_SSL
    wssl = ctx->worker_ssl;
#endif

    /* Remove any socket timeouts for raw pipe mode */
    struct timeval notv = {0, 0};
    setsockopt(wfd, SOL_SOCKET, SO_RCVTIMEO, &notv, sizeof(notv));
    setsockopt(wfd, SOL_SOCKET, SO_SNDTIMEO, &notv, sizeof(notv));

    while (1) {
#ifdef HAS_SSL
        /* With TLS: SSL may have buffered data that select() won't see.
         * Use a short timeout so we re-check SSL_pending frequently.
         * Without TLS: block indefinitely on select(). */
        int has_pending = wssl && SSL_pending((SSL *)wssl) > 0;
#else
        int has_pending = 0;
#endif
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(wfd, &rfds);
        FD_SET(sfd, &rfds);

        struct timeval tv = {0, has_pending ? 0 : 100000}; /* 0 or 100ms */
        int rc = select(maxfd, &rfds, NULL, NULL, has_pending ? &tv : NULL);
        if (rc < 0) break;

        /* Read from federation side (TLS or plain) */
        if (FD_ISSET(wfd, &rfds) || has_pending) {
            do {
                ssize_t n = node_read_partial(wfd, wssl, buf, sizeof(buf));
                if (n <= 0) { if (FD_ISSET(wfd, &rfds)) goto done; else break; }
                if (send_all(sfd, (uint8_t *)buf, (size_t)n) < 0) goto done;
#ifdef HAS_SSL
            } while (wssl && SSL_pending((SSL *)wssl) > 0);
#else
            } while (0);
#endif
        }

        /* Read from local service (always plain TCP) */
        if (FD_ISSET(sfd, &rfds)) {
            ssize_t n = read(sfd, buf, sizeof(buf));
            if (n <= 0) break;
            if (node_send(wfd, wssl, (uint8_t *)buf, (size_t)n) < 0) break;
        }
    }
done:

    close(sfd);
#ifdef HAS_SSL
    if (wssl) {
        /* TLS pipe: shutdown SSL, close fd — don't re-add to event loop.
         * The fd is unusable after SSL_free and would crash libev. */
        node_ssl_close(wfd, (SSL *)wssl);
        close(wfd);
        g_core->log(g_core, PORTAL_LOG_INFO, "node",
                    "TLS pipe closed on fd %d", wfd);
        free(ctx);
        return NULL;
    }
#endif
    /* Plain TCP pipe: re-add fd to event loop for reuse */
    g_core->fd_add(g_core, wfd, EV_READ, on_inbound_data, NULL);
    g_core->log(g_core, PORTAL_LOG_INFO, "node", "Pipe closed on fd %d", wfd);
    free(ctx);
    return NULL;
}

static int start_pipe(int worker_fd, int port)
{
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) return -1;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sfd);
        return -1;
    }

    g_core->fd_del(g_core, worker_fd);

    pipe_ctx_t *ctx = malloc(sizeof(*ctx));
    ctx->worker_fd = worker_fd;
    ctx->service_fd = sfd;
#ifdef HAS_SSL
    ctx->worker_ssl = fd_ssl_get(worker_fd);
#endif

    pthread_t th;
    pthread_create(&th, NULL, pipe_relay_thread, ctx);
    pthread_detach(th);

    g_core->log(g_core, PORTAL_LOG_INFO, "node",
                "Pipe started: fd %d → localhost:%d", worker_fd, port);
    return 0;
}

/* --- Inbound peer handling --- */

static void on_inbound_data(int fd, uint32_t events, void *userdata)
{
    (void)userdata;
    if (events & EV_ERROR) {
        mark_peer_dead_by_fd(fd);
#ifdef HAS_SSL
        node_ssl_close(fd, fd_ssl_get(fd));
#endif
        g_core->fd_del(g_core, fd);
        close(fd);
        return;
    }

    void *ssl = NULL;
#ifdef HAS_SSL
    ssl = fd_ssl_get(fd);
#endif

    /* Read wire message */
    uint8_t hdr[4];
    ssize_t n = node_read_partial(fd, ssl, hdr, 4);
    if (n != 4) {
        mark_peer_dead_by_fd(fd);
#ifdef HAS_SSL
        node_ssl_close(fd, ssl);
#endif
        g_core->fd_del(g_core, fd);
        close(fd);
        return;
    }

    int32_t msg_len = portal_wire_read_length(hdr);
    if (msg_len <= 0 || msg_len > NODE_BUF_SIZE) return;

    uint8_t *buf = malloc((size_t)msg_len + 4);
    memcpy(buf, hdr, 4);
    size_t remaining = (size_t)msg_len;
    size_t got = 0;
    while (got < remaining) {
        ssize_t rd = node_read_partial(fd, ssl, buf + 4 + got, remaining - got);
        if (rd <= 0) { free(buf); return; }
        got += (size_t)rd;
    }

    /* Decode and route locally */
    portal_msg_t incoming = {0};
    if (portal_wire_decode_msg(buf, (size_t)msg_len + 4, &incoming) == 0) {
        portal_resp_t resp = {0};

        /* Check for PIPE request — switch fd to raw TCP mode */
        if (incoming.path && strcmp(incoming.path, "/tunnel/pipe") == 0) {
            const char *port_str = NULL;
            for (uint16_t i = 0; i < incoming.header_count; i++)
                if (strcmp(incoming.headers[i].key, "port") == 0)
                    port_str = incoming.headers[i].value;

            int pipe_ok = 0;
            if (port_str) {
                int port = atoi(port_str);
                if (port > 0 && start_pipe(fd, port) == 0) {
                    pipe_ok = 1;
                    resp.status = PORTAL_OK;
                    char ok_body[] = "PIPE";
                    resp.body = ok_body;
                    resp.body_len = 4;
                }
            }

            if (!pipe_ok)
                resp.status = PORTAL_UNAVAILABLE;

            /* Send response BEFORE switching to raw mode */
            uint8_t *resp_buf = NULL;
            size_t resp_len = 0;
            if (portal_wire_encode_resp(&resp, &resp_buf, &resp_len) == 0) {
                node_send(fd, ssl, resp_buf, resp_len);
                free(resp_buf);
            }
            resp.body = NULL;

            free(incoming.path);
            for (uint16_t hi = 0; hi < incoming.header_count; hi++) {
                free(incoming.headers[hi].key);
                free(incoming.headers[hi].value);
            }
            free(incoming.headers);
            free(incoming.body);
            if (incoming.ctx) {
                free(incoming.ctx->auth.user);
                free(incoming.ctx->auth.token);
                free(incoming.ctx);
            }
            free(buf);
            return;
        }

        /* Track inbound message */
        node_peer_t *src_peer = find_peer_by_fd(fd);
        if (src_peer) {
            src_peer->msgs_recv++;
            if (incoming.body_len > 0)
                src_peer->bytes_recv += incoming.body_len;
        }

        /* Normal message routing */
        g_core->send(g_core, &incoming, &resp);

        /* Encode and send response */
        uint8_t *resp_buf = NULL;
        size_t resp_len = 0;
        if (portal_wire_encode_resp(&resp, &resp_buf, &resp_len) == 0) {
            node_send(fd, ssl, resp_buf, resp_len);
            if (src_peer) {
                src_peer->msgs_sent++;
                src_peer->bytes_sent += resp_len;
            }
            free(resp_buf);
        }

        free(incoming.path);
        for (uint16_t i = 0; i < incoming.header_count; i++) {
            free(incoming.headers[i].key);
            free(incoming.headers[i].value);
        }
        free(incoming.headers);
        free(incoming.body);
        if (incoming.ctx) {
            free(incoming.ctx->auth.user);
            free(incoming.ctx->auth.token);
            free(incoming.ctx);
        }
        free(resp.body);
    }
    free(buf);
}

static void on_new_peer(int fd, uint32_t events, void *userdata)
{
    (void)events; (void)userdata;

    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    int client_fd = accept(fd, (struct sockaddr *)&addr, &alen);
    if (client_fd < 0) return;

    /* TCP keepalive on accepted connections */
    int ka = 1;
    setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof(ka));
#ifdef TCP_KEEPIDLE
    int kidle = 60;
    setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPIDLE, &kidle, sizeof(kidle));
#endif
#ifdef TCP_KEEPINTVL
    int kintvl = 30;
    setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPINTVL, &kintvl, sizeof(kintvl));
#endif
#ifdef TCP_KEEPCNT
    int kcnt = 3;
    setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPCNT, &kcnt, sizeof(kcnt));
#endif

    void *ssl = NULL;
#ifdef HAS_SSL
    if (g_tls_enabled) {
        ssl = node_tls_accept(client_fd);
        if (!ssl) {
            g_core->log(g_core, PORTAL_LOG_WARN, "node",
                        "TLS handshake failed from %s — rejected",
                        inet_ntoa(addr.sin_addr));
            close(client_fd);
            return;
        }
    }
#endif

    /* Wire protocol handshake */
    send_handshake(client_fd, ssl);
    char peer_name[PORTAL_MAX_MODULE_NAME];
    char remote_peers[NODE_MAX_PEERS][PORTAL_MAX_MODULE_NAME];
    int remote_peer_count = 0;
    int hrc = recv_handshake(client_fd, ssl, peer_name, sizeof(peer_name),
                              remote_peers, &remote_peer_count);
    if (hrc < 0) {
        if (hrc == -2)
            g_core->log(g_core, PORTAL_LOG_WARN, "node",
                        "Rejected peer from %s — bad federation key",
                        inet_ntoa(addr.sin_addr));
#ifdef HAS_SSL
        if (ssl) node_ssl_close(client_fd, ssl);
#endif
        close(client_fd);
        return;
    }

    /* Check if this is a worker connection from an already-known peer */
    node_peer_t *existing = find_peer_by_name(peer_name);
    if (existing) {
        if (existing->worker_count < NODE_MAX_THREADS) {
            pthread_mutex_lock(&existing->lock);
            worker_t *w = &existing->workers[existing->worker_count++];
            w->fd = client_fd;
            w->busy = 0;
#ifdef HAS_SSL
            w->ssl = ssl;
#endif
            pthread_mutex_unlock(&existing->lock);
        }
        g_core->fd_add(g_core, client_fd, EV_READ, on_inbound_data, NULL);
        g_core->log(g_core, PORTAL_LOG_DEBUG, "node",
                    "Worker connection from '%s' (%d/%d)%s",
                    peer_name, existing->worker_count, NODE_MAX_THREADS,
                    ssl ? " [TLS]" : "");
        return;
    }

    /* New peer */
    if (g_peer_count >= NODE_MAX_PEERS) {
#ifdef HAS_SSL
        if (ssl) node_ssl_close(client_fd, ssl);
#endif
        close(client_fd);
        return;
    }

    node_peer_t *peer = &g_peers[g_peer_count++];
    memset(peer, 0, sizeof(*peer));
    pthread_mutex_init(&peer->lock, NULL);
    snprintf(peer->name, sizeof(peer->name), "%s", peer_name);
    snprintf(peer->host, sizeof(peer->host), "%s", inet_ntoa(addr.sin_addr));
    peer->port = ntohs(addr.sin_port);
    peer->ctrl_fd = client_fd;
#ifdef HAS_SSL
    peer->ctrl_ssl = ssl;
#endif
    peer->is_inbound = 1;
    peer->worker_count = 0;
    peer->ready = 1;
    peer->connected_at = time(NULL);

    /* Register wildcard path for this peer */
    char path[PORTAL_MAX_PATH_LEN];
    snprintf(path, sizeof(path), "/%s/*", peer->name);
    int preg = g_core->path_register(g_core, path, "node");
    if (preg == 0) {
        g_core->path_set_access(g_core, path, PORTAL_ACCESS_RW);
        g_core->log(g_core, PORTAL_LOG_INFO, "node",
                    "Registered path '%s' for peer '%s'", path, peer->name);
    } else {
        g_core->log(g_core, PORTAL_LOG_ERROR, "node",
                    "FAILED to register path '%s' for peer '%s' (rc=%d)",
                    path, peer->name, preg);
    }
    snprintf(peer->paths[0], NODE_PEER_PATH_LEN, "%.*s",
                (int)(NODE_PEER_PATH_LEN - 1), path);
    peer->path_count = 1;

    g_core->fd_add(g_core, client_fd, EV_READ, on_inbound_data, NULL);

    g_core->log(g_core, PORTAL_LOG_INFO, "node",
                "Peer '%s' connected (inbound from %s)%s",
                peer_name, peer->host, ssl ? " [TLS]" : "");

    /* Register indirect peers advertised by this peer */
    int hub_idx = (int)(peer - g_peers);
    for (int rp = 0; rp < remote_peer_count; rp++)
        register_indirect_peer(remote_peers[rp], hub_idx);
}

/* --- Connect to a configured remote peer --- */

static int connect_to_peer(const char *name, const char *host, int port)
{
    int fd = create_connection(host, port);
    if (fd < 0) {
        g_core->log(g_core, PORTAL_LOG_WARN, "node",
                    "Cannot connect to '%s' at %s:%d", name, host, port);
        return -1;
    }

    void *ssl = NULL;
#ifdef HAS_SSL
    if (g_tls_enabled) {
        ssl = node_tls_connect(fd);
        if (!ssl) {
            g_core->log(g_core, PORTAL_LOG_WARN, "node",
                        "TLS connect to '%s' failed", name);
            close(fd);
            return -1;
        }
    }
#endif

    send_handshake(fd, ssl);
    char remote_name[PORTAL_MAX_MODULE_NAME];
    char remote_peers[NODE_MAX_PEERS][PORTAL_MAX_MODULE_NAME];
    int remote_peer_count = 0;
    int hrc = recv_handshake(fd, ssl, remote_name, sizeof(remote_name),
                              remote_peers, &remote_peer_count);
    if (hrc < 0) {
        if (hrc == -2)
            g_core->log(g_core, PORTAL_LOG_WARN, "node",
                        "Rejected by '%s' — federation key mismatch", name);
#ifdef HAS_SSL
        if (ssl) node_ssl_close(fd, ssl);
#endif
        close(fd);
        return -1;
    }

    if (g_peer_count >= NODE_MAX_PEERS) {
#ifdef HAS_SSL
        if (ssl) node_ssl_close(fd, ssl);
#endif
        close(fd);
        return -1;
    }

    node_peer_t *peer = &g_peers[g_peer_count++];
    memset(peer, 0, sizeof(*peer));
    pthread_mutex_init(&peer->lock, NULL);
    snprintf(peer->name, sizeof(peer->name), "%s",
             remote_name[0] ? remote_name : name);
    snprintf(peer->host, sizeof(peer->host), "%s", host);
    peer->port = port;
    peer->ctrl_fd = fd;
#ifdef HAS_SSL
    peer->ctrl_ssl = ssl;
#endif
    peer->is_inbound = 0;
    peer->dead = 0;
    snprintf(peer->cfg_host, sizeof(peer->cfg_host), "%s", host);
    peer->cfg_port = port;
    peer->worker_count = g_threads_per_peer;

    create_worker_connections(peer);
    peer->ready = 1;
    peer->connected_at = time(NULL);

    char path[PORTAL_MAX_PATH_LEN];
    snprintf(path, sizeof(path), "/%s/*", peer->name);
    g_core->path_register(g_core, path, "node");
    g_core->path_set_access(g_core, path, PORTAL_ACCESS_RW);
    snprintf(peer->paths[0], NODE_PEER_PATH_LEN, "%.*s",
                (int)(NODE_PEER_PATH_LEN - 1), path);
    peer->path_count = 1;

    g_core->fd_add(g_core, fd, EV_READ, on_inbound_data, NULL);

    g_core->log(g_core, PORTAL_LOG_INFO, "node",
                "Connected to peer '%s' at %s:%d (%d workers)%s",
                peer->name, host, port, peer->worker_count,
                ssl ? " [TLS]" : "");

    /* Register indirect peers advertised by this peer (hub discovery) */
    int hub_idx = (int)(peer - g_peers);
    for (int rp = 0; rp < remote_peer_count; rp++)
        register_indirect_peer(remote_peers[rp], hub_idx);

    return 0;
}

/* --- Peer health: mark dead + reconnect --- */

static void mark_peer_dead_by_fd(int fd)
{
    for (int i = 0; i < g_peer_count; i++) {
        node_peer_t *p = &g_peers[i];
        if (p->ctrl_fd == fd ||
            (p->worker_count > 0 && p->workers[0].fd == fd)) {
            if (!p->dead) {
                p->dead = 1;
                p->ready = 0;
                g_core->log(g_core, PORTAL_LOG_WARN, "node",
                            "Peer '%s' connection lost", p->name);
                /* Cascade: indirect peers through this hub are also dead */
                for (int k = 0; k < g_peer_count; k++) {
                    if (g_peers[k].is_indirect && g_peers[k].hub_idx == i) {
                        g_peers[k].dead = 1;
                        g_peers[k].ready = 0;
                        g_core->log(g_core, PORTAL_LOG_WARN, "node",
                                    "Indirect peer '%s' lost (hub '%s' down)",
                                    g_peers[k].name, p->name);
                    }
                }
            }
            return;
        }
        for (int j = 0; j < p->worker_count; j++) {
            if (p->workers[j].fd == fd) {
                p->workers[j].fd = -1;
#ifdef HAS_SSL
                p->workers[j].ssl = NULL;
#endif
                return;
            }
        }
    }
}

#ifdef HAS_SSL
static void tls_renew_timer_cb(void *userdata)
{
    (void)userdata;
    if (g_core && g_core->module_loaded(g_core, "acme")) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/acme/functions/renew");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            g_core->send(g_core, m, r);
            portal_msg_free(m); portal_resp_free(r);
        }
        reload_tls_contexts();
    }
}
#endif

/* Retry configured peers that aren't connected */
static void connect_configured_peers(void)
{
    if (!g_core) return;
    for (int i = 0; i < NODE_MAX_PEERS; i++) {
        char key[32];
        snprintf(key, sizeof(key), "peer%d", i);
        const char *val = g_core->config_get(g_core, "nodes", key);
        if (!val) continue;
        char pname[64] = {0}, phost[256] = {0};
        int pport = NODE_DEFAULT_PORT;
        if (sscanf(val, "%63[^=]=%255[^:]:%d", pname, phost, &pport) < 2) continue;
        /* Skip if peer exists in any state (avoid duplicates) */
        node_peer_t *existing = find_peer_any(pname);
        if (existing) continue;
        /* Peer not in list at all — try connecting */
        connect_to_peer(pname, phost, pport);
    }
}

/* Timer callback for reconnect (called by event loop) */
static void reconnect_timer_cb(void *userdata)
{
    (void)userdata;
    reconnect_dead_peers();
    connect_configured_peers();
}

static void reconnect_dead_peers(void)
{
    for (int i = 0; i < g_peer_count; i++) {
        node_peer_t *p = &g_peers[i];
        if (p->is_inbound || p->is_indirect || p->cfg_host[0] == '\0') continue;

        /* Check if peer needs reconnect:
         * - explicitly dead
         * - stuck connecting (not ready for > 30s)
         * - no working workers */
        if (p->ready && !p->dead) continue;
        if (!p->dead && !p->ready && p->connected_at > 0 &&
            (time(NULL) - p->connected_at) < 30) continue;  /* give it time */

        g_core->log(g_core, PORTAL_LOG_INFO, "node",
                    "Reconnecting '%s' — removing dead peer...", p->name);

        /* Close all fds (no SSL_free — just close raw fds) */
        if (p->ctrl_fd >= 0) {
            g_core->fd_del(g_core, p->ctrl_fd);
            close(p->ctrl_fd);
        }
        for (int j = 0; j < p->worker_count; j++) {
            if (p->workers[j].fd >= 0) {
                g_core->fd_del(g_core, p->workers[j].fd);
                close(p->workers[j].fd);
            }
        }
        /* Unregister paths */
        for (int j = 0; j < p->path_count; j++)
            g_core->path_unregister(g_core, p->paths[j]);

        /* Remove indirect peers that used this hub (backwards to avoid index shift) */
        for (int k = g_peer_count - 1; k >= 0; k--) {
            if (g_peers[k].is_indirect && g_peers[k].hub_idx == i) {
                g_core->log(g_core, PORTAL_LOG_INFO, "node",
                            "Removing indirect peer '%s'", g_peers[k].name);
                for (int jp = 0; jp < g_peers[k].path_count; jp++)
                    g_core->path_unregister(g_core, g_peers[k].paths[jp]);
                memmove(&g_peers[k], &g_peers[k + 1],
                        (size_t)(g_peer_count - k - 1) * sizeof(node_peer_t));
                g_peer_count--;
                if (k < i) i--;  /* hub index shifted */
            }
        }

        /* Save config for fresh connect */
        char save_host[256], save_name[PORTAL_MAX_MODULE_NAME];
        int save_port = p->cfg_port;
        snprintf(save_host, sizeof(save_host), "%s", p->cfg_host);
        snprintf(save_name, sizeof(save_name), "%s", p->name);

        /* Remove peer entry */
        pthread_mutex_destroy(&p->lock);
        memmove(p, p + 1, (size_t)(g_peer_count - i - 1) * sizeof(node_peer_t));
        g_peer_count--;
        i--;  /* re-check this index */

        /* Fresh connect (creates new peer entry) */
        connect_to_peer(save_name, save_host, save_port);
    }
}

/* ================================================================
 * Module lifecycle
 * ================================================================ */

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_peers, 0, sizeof(g_peers));
    g_peer_count = 0;
#ifdef HAS_SSL
    memset(g_fd_ssl, 0, sizeof(g_fd_ssl));
#endif

    const char *name = core->config_get(core, "node", "node_name");
    if (name) snprintf(g_node_name, sizeof(g_node_name), "%s", name);

    /* Read location from config, then override from persistent file */
    const char *loc = core->config_get(core, "node", "location");
    if (loc) snprintf(g_location, sizeof(g_location), "%s", loc);
    const char *gps = core->config_get(core, "node", "gps");
    if (gps) snprintf(g_gps, sizeof(g_gps), "%s", gps);
    {
        const char *dd = core->config_get(core, "core", "data_dir");
        if (dd) {
            char lpath[512];
            snprintf(lpath, sizeof(lpath), "%s/node_location.conf", dd);
            FILE *lf = fopen(lpath, "r");
            if (lf) {
                char line[300];
                while (fgets(line, sizeof(line), lf)) {
                    char *eq = strchr(line, '=');
                    if (!eq) continue;
                    *eq = '\0';
                    char *k = line, *v = eq + 1;
                    while (*k == ' ') k++;
                    while (*v == ' ') v++;
                    size_t vl = strlen(v);
                    while (vl > 0 && (v[vl-1] == '\n' || v[vl-1] == '\r')) v[--vl] = '\0';
                    if (strncmp(k, "location", 8) == 0 && v[0])
                        snprintf(g_location, sizeof(g_location), "%s", v);
                    else if (strncmp(k, "gps", 3) == 0 && v[0])
                        snprintf(g_gps, sizeof(g_gps), "%s", v);
                }
                fclose(lf);
            }
        }
    }

    const char *port_str = core->config_get(core, "node", "listen_port");
    if (port_str) g_listen_port = atoi(port_str);

    const char *threads_str = core->config_get(core, "node", "threads_per_peer");
    if (threads_str) g_threads_per_peer = atoi(threads_str);
    if (g_threads_per_peer < 1) g_threads_per_peer = 1;
    if (g_threads_per_peer > NODE_MAX_THREADS) g_threads_per_peer = NODE_MAX_THREADS;

    /* Federation key authentication */
    const char *fkey = core->config_get(core, "node", "federation_key");
    if (fkey && fkey[0]) {
        snprintf(g_federation_key, sizeof(g_federation_key), "%s", fkey);
        compute_sha256((const uint8_t *)fkey, strlen(fkey), g_key_hash);
        g_has_key = 1;
        core->log(core, PORTAL_LOG_INFO, "node",
                  "Federation key authentication enabled");
    } else {
        g_has_key = 0;
    }

    /* TLS configuration */
#ifdef HAS_SSL
    const char *tls_str = core->config_get(core, "node", "tls");
    if (tls_str && (strcmp(tls_str, "true") == 0 || strcmp(tls_str, "1") == 0))
        g_tls_enabled = 1;
    else
        g_tls_enabled = 0;

    const char *v;
    if ((v = core->config_get(core, "node", "cert_file")))
        snprintf(g_cert_file, sizeof(g_cert_file), "%s", v);
    if ((v = core->config_get(core, "node", "key_file")))
        snprintf(g_key_file, sizeof(g_key_file), "%s", v);
    if ((v = core->config_get(core, "node", "tls_verify")))
        g_tls_verify = (strcmp(v, "true") == 0 || strcmp(v, "1") == 0);

    /* Default cert paths from instance certs/ directory */
    if (g_tls_enabled && g_cert_file[0] == '\0') {
        const char *data_dir = core->config_get(core, "core", "data_dir");
        if (data_dir) {
            snprintf(g_cert_file, sizeof(g_cert_file), "%s/certs/server.crt", data_dir);
            snprintf(g_key_file, sizeof(g_key_file), "%s/certs/server.key", data_dir);
        }
    }

    if (g_tls_enabled) {
        if (init_tls_contexts() < 0) {
            core->log(core, PORTAL_LOG_ERROR, "node",
                      "TLS initialization failed — falling back to plain TCP");
            g_tls_enabled = 0;
        } else {
            core->log(core, PORTAL_LOG_INFO, "node",
                      "TLS enabled (cert: %s, verify: %s)",
                      g_cert_file, g_tls_verify ? "yes" : "no");
        }
    }
#endif

    /* TCP listener */
    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) {
        core->log(core, PORTAL_LOG_ERROR, "node", "socket() failed");
        return PORTAL_MODULE_FAIL;
    }

    int opt = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)g_listen_port);

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        core->log(core, PORTAL_LOG_ERROR, "node", "bind(%d) failed: %s",
                  g_listen_port, strerror(errno));
        close(g_listen_fd); g_listen_fd = -1;
        return PORTAL_MODULE_FAIL;
    }

    listen(g_listen_fd, 16);
    core->fd_add(core, g_listen_fd, EV_READ, on_new_peer, NULL);

    core->path_register(core, "/node/resources/status", "node");
    core->path_set_access(core, "/node/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/node/resources/peers", "node");
    core->path_set_access(core, "/node/resources/peers", PORTAL_ACCESS_READ);
    core->path_register(core, "/node/resources/peer/*", "node");
    core->path_set_access(core, "/node/resources/peer/*", PORTAL_ACCESS_READ);

    core->log(core, PORTAL_LOG_INFO, "node",
              "Node '%s' listening on port %d (%d threads/peer)%s",
              g_node_name, g_listen_port, g_threads_per_peer,
#ifdef HAS_SSL
              g_tls_enabled ? " [TLS]" : ""
#else
              ""
#endif
              );

    /* Reconnect timer — direct event loop, no cron dependency */
    core->timer_add(core, NODE_RECONNECT_SEC, reconnect_timer_cb, NULL);

#ifdef HAS_SSL
    /* Daily TLS cert renewal — direct timer, no cron dependency */
    if (g_tls_enabled)
        core->timer_add(core, 86400.0, tls_renew_timer_cb, NULL);
#endif

    /* Register function paths */
    core->path_register(core, "/node/functions/reconnect", "node");
    core->path_set_access(core, "/node/functions/reconnect", PORTAL_ACCESS_RW);
    core->path_register(core, "/node/functions/pipe", "node");
    core->path_set_access(core, "/node/functions/pipe", PORTAL_ACCESS_RW);
    core->path_register(core, "/node/functions/ping", "node");
    core->path_set_access(core, "/node/functions/ping", PORTAL_ACCESS_RW);
    core->path_register(core, "/node/functions/location", "node");
    core->path_set_access(core, "/node/functions/location", PORTAL_ACCESS_RW);
    core->path_register(core, "/node/functions/geolocate", "node");
    core->path_set_access(core, "/node/functions/geolocate", PORTAL_ACCESS_RW);
    core->path_register(core, "/node/functions/trace", "node");
    core->path_set_access(core, "/node/functions/trace", PORTAL_ACCESS_RW);
#ifdef HAS_SSL
    core->path_register(core, "/node/functions/reload_tls", "node");
    core->path_set_access(core, "/node/functions/reload_tls", PORTAL_ACCESS_RW);
    core->path_register(core, "/node/functions/renew_tls", "node");
    core->path_set_access(core, "/node/functions/renew_tls", PORTAL_ACCESS_RW);
#endif

    /* Connect to configured peers */
    for (int i = 0; i < NODE_MAX_PEERS; i++) {
        char key[32];
        snprintf(key, sizeof(key), "peer%d", i);
        const char *val = core->config_get(core, "nodes", key);
        if (!val) continue;

        char pname[64] = {0}, phost[256] = {0};
        int pport = NODE_DEFAULT_PORT;
        if (sscanf(val, "%63[^=]=%255[^:]:%d", pname, phost, &pport) >= 2)
            connect_to_peer(pname, phost, pport);
    }

    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    for (int i = 0; i < g_peer_count; i++) {
        node_peer_t *peer = &g_peers[i];
        for (int j = 0; j < peer->worker_count; j++) {
            if (peer->workers[j].fd >= 0) {
#ifdef HAS_SSL
                if (peer->workers[j].ssl)
                    node_ssl_close(peer->workers[j].fd, peer->workers[j].ssl);
#endif
                close(peer->workers[j].fd);
            }
        }
        if (peer->ctrl_fd >= 0) {
#ifdef HAS_SSL
            if (peer->ctrl_ssl)
                node_ssl_close(peer->ctrl_fd, peer->ctrl_ssl);
#endif
            core->fd_del(core, peer->ctrl_fd);
            close(peer->ctrl_fd);
        }
        for (int j = 0; j < peer->path_count; j++)
            core->path_unregister(core, peer->paths[j]);
        pthread_mutex_destroy(&peer->lock);
    }
    g_peer_count = 0;

    if (g_listen_fd >= 0) {
        core->fd_del(core, g_listen_fd);
        close(g_listen_fd);
        g_listen_fd = -1;
    }

    core->path_unregister(core, "/node/resources/status");
    core->path_unregister(core, "/node/resources/peers");
    core->path_unregister(core, "/node/resources/peer/*");
    core->path_unregister(core, "/node/functions/reconnect");
    core->path_unregister(core, "/node/functions/pipe");
    core->path_unregister(core, "/node/functions/ping");
    core->path_unregister(core, "/node/functions/trace");
    core->path_unregister(core, "/node/functions/location");
    core->path_unregister(core, "/node/functions/geolocate");
#ifdef HAS_SSL
    core->path_unregister(core, "/node/functions/reload_tls");
    core->path_unregister(core, "/node/functions/renew_tls");
    free_tls_contexts();
    memset(g_fd_ssl, 0, sizeof(g_fd_ssl));
#endif

    core->log(core, PORTAL_LOG_INFO, "node", "Node module unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

/* ================================================================
 * Message handler
 * ================================================================ */

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    if (strcmp(msg->path, "/node/resources/status") == 0) {
        char buf[1024];
        int n = snprintf(buf, sizeof(buf),
            "Node: %s\nLocation: %s\nGPS: %s\n"
            "Port: %d\nPeers: %d\nThreads/peer: %d\nTLS: %s\n",
            g_node_name,
            g_location[0] ? g_location : "(not set)",
            g_gps[0] ? g_gps : "(not set)",
            g_listen_port, g_peer_count, g_threads_per_peer,
#ifdef HAS_SSL
            g_tls_enabled ? "enabled" : "disabled"
#else
            "not compiled"
#endif
            );
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n + 1);
        return 0;
    }

    if (strcmp(msg->path, "/node/resources/peers") == 0) {
        char buf[8192];
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Connected peers:\n");
        for (int i = 0; i < g_peer_count; i++) {
            node_peer_t *p = &g_peers[i];
            int busy = 0;
            for (int j = 0; j < p->worker_count; j++)
                if (p->workers[j].busy) busy++;
            const char *tls_tag = "";
#ifdef HAS_SSL
            tls_tag = (p->ctrl_ssl || (p->worker_count > 0 && p->workers[0].ssl))
                      ? " [TLS]" : "";
#endif
            const char *route = p->is_indirect ? "indirect" :
                                (p->is_inbound ? "inbound" : "outbound");
            long uptime = p->connected_at ? (long)(time(NULL) - p->connected_at) : 0;
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "  %-16s %-18s [%s] %s workers:%d/%d%s"
                " msgs:%lu/%lu bytes:%lu/%lu up:%lds\n",
                p->name,
                p->is_indirect ? "(via hub)" : p->host,
                p->ready ? (p->dead ? "dead" : "ready") : "connecting",
                route, busy, p->worker_count, tls_tag,
                (unsigned long)p->msgs_sent, (unsigned long)p->msgs_recv,
                (unsigned long)p->bytes_sent, (unsigned long)p->bytes_recv,
                uptime);
        }
        if (g_peer_count == 0)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off + 1);
        return 0;
    }

    /* /node/resources/peer — detailed status for a specific peer (header: name) */
    if (strncmp(msg->path, "/node/resources/peer", 20) == 0) {
        const char *pname = NULL;
        for (uint16_t i = 0; i < msg->header_count; i++)
            if (strcmp(msg->headers[i].key, "name") == 0)
                pname = msg->headers[i].value;
        /* Also support /node/resources/peer/<name> */
        if (!pname && strlen(msg->path) > 21 && msg->path[20] == '/')
            pname = msg->path + 21;

        if (!pname) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }

        node_peer_t *p = find_peer_any(pname);
        if (!p) {
            char buf[128];
            int n = snprintf(buf, sizeof(buf), "Peer '%s' not found\n", pname);
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        int busy = 0;
        for (int j = 0; j < p->worker_count; j++)
            if (p->workers[j].busy) busy++;

        const char *tls_tag = "no";
#ifdef HAS_SSL
        if (p->ctrl_ssl || (p->worker_count > 0 && p->workers[0].ssl))
            tls_tag = "yes";
#endif
        long uptime = p->connected_at ? (long)(time(NULL) - p->connected_at) : 0;
        long hours = uptime / 3600, mins = (uptime % 3600) / 60, secs = uptime % 60;

        char buf[4096];
        int n = snprintf(buf, sizeof(buf),
            "Peer: %s\n"
            "Host: %s:%d\n"
            "Status: %s\n"
            "Route: %s%s%s\n"
            "TLS: %s\n"
            "Workers: %d total, %d busy\n"
            "Connected: %ldh %ldm %lds\n"
            "Messages sent: %lu\n"
            "Messages recv: %lu\n"
            "Bytes sent: %lu\n"
            "Bytes recv: %lu\n"
            "Errors: %lu\n",
            p->name,
            p->is_indirect ? "(via hub)" : p->host, p->port,
            p->ready ? (p->dead ? "dead" : "ready") : "connecting",
            p->is_indirect ? "indirect via " : (p->is_inbound ? "inbound" : "outbound"),
            p->is_indirect && p->hub_idx >= 0 && p->hub_idx < g_peer_count
                ? g_peers[p->hub_idx].name : "",
            "",
            tls_tag,
            p->worker_count, busy,
            hours, mins, secs,
            (unsigned long)p->msgs_sent,
            (unsigned long)p->msgs_recv,
            (unsigned long)p->bytes_sent,
            (unsigned long)p->bytes_recv,
            (unsigned long)p->errors);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* /node/functions/reconnect — called by cron */
    if (strcmp(msg->path, "/node/functions/reconnect") == 0) {
        reconnect_dead_peers();
        portal_resp_set_status(resp, PORTAL_OK);
        return 0;
    }

    /* Helper: persist location to config DB */
    /* Persist location to .conf file (survives restarts) */
    #define SAVE_NODE_CONF() do { \
        const char *_dd = core->config_get(core, "core", "data_dir"); \
        if (_dd) { \
            char _path[512]; \
            snprintf(_path, sizeof(_path), "%s/node_location.conf", _dd); \
            FILE *_f = fopen(_path, "w"); \
            if (_f) { \
                fprintf(_f, "location = %s\n", g_location); \
                fprintf(_f, "gps = %s\n", g_gps); \
                fclose(_f); \
            } \
        } \
    } while(0)

    /* /node/functions/location — set node location and/or GPS */
    if (strcmp(msg->path, "/node/functions/location") == 0) {
        const char *loc = NULL, *gps_val = NULL;
        for (uint16_t hi = 0; hi < msg->header_count; hi++) {
            if (strcmp(msg->headers[hi].key, "name") == 0) loc = msg->headers[hi].value;
            if (strcmp(msg->headers[hi].key, "gps") == 0) gps_val = msg->headers[hi].value;
        }
        if (loc)
            snprintf(g_location, sizeof(g_location), "%s", loc);
        if (gps_val)
            snprintf(g_gps, sizeof(g_gps), "%s", gps_val);
        SAVE_NODE_CONF();
        char buf[512];
        int n = snprintf(buf, sizeof(buf), "Location: %s\nGPS: %s\n",
                         g_location[0] ? g_location : "(not set)",
                         g_gps[0] ? g_gps : "(not set)");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* /node/functions/geolocate — auto-detect location from public IP */
    if (strcmp(msg->path, "/node/functions/geolocate") == 0) {
        /* Use ip-api.com free API (no key needed) */
        if (core->module_loaded(core, "http_client")) {
            portal_msg_t *hm = portal_msg_alloc();
            portal_resp_t *hr = portal_resp_alloc();
            if (hm && hr) {
                portal_msg_set_path(hm, "/httpc/functions/get");
                portal_msg_set_method(hm, PORTAL_METHOD_CALL);
                portal_msg_add_header(hm, "url",
                    "http://ip-api.com/json/?fields=city,regionName,country,lat,lon,query");
                core->send(core, hm, hr);
                if (hr->body && hr->body_len > 0) {
                    /* Parse JSON: "city":"X","regionName":"Y","country":"Z","lat":N,"lon":N */
                    char *body = hr->body;
                    char city[64] = "", region[64] = "", country[64] = "";
                    double lat = 0, lon = 0;
                    char *p;
                    if ((p = strstr(body, "\"city\":\""))) {
                        p += 8; int i = 0;
                        while (*p && *p != '"' && i < 63) city[i++] = *p++;
                        city[i] = '\0';
                    }
                    if ((p = strstr(body, "\"regionName\":\""))) {
                        p += 14; int i = 0;
                        while (*p && *p != '"' && i < 63) region[i++] = *p++;
                        region[i] = '\0';
                    }
                    if ((p = strstr(body, "\"country\":\""))) {
                        p += 11; int i = 0;
                        while (*p && *p != '"' && i < 63) country[i++] = *p++;
                        country[i] = '\0';
                    }
                    if ((p = strstr(body, "\"lat\":")))
                        lat = strtod(p + 6, NULL);
                    if ((p = strstr(body, "\"lon\":")))
                        lon = strtod(p + 6, NULL);

                    if (city[0])
                        snprintf(g_location, sizeof(g_location), "%s, %s, %s",
                                 city, region, country);
                    if (lat != 0 || lon != 0)
                        snprintf(g_gps, sizeof(g_gps), "%.6f,%.6f", lat, lon);
                    SAVE_NODE_CONF();

                    char buf[512];
                    int n = snprintf(buf, sizeof(buf),
                        "Location: %s\nGPS: %s\n",
                        g_location[0] ? g_location : "(not set)",
                        g_gps[0] ? g_gps : "(not set)");
                    portal_resp_set_status(resp, PORTAL_OK);
                    portal_resp_set_body(resp, buf, (size_t)n);
                } else {
                    portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
                    char err[] = "Geolocation failed\n";
                    portal_resp_set_body(resp, err, sizeof(err) - 1);
                }
                portal_msg_free(hm);
                portal_resp_free(hr);
            }
        } else {
            portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
            char err[] = "mod_http_client not loaded\n";
            portal_resp_set_body(resp, err, sizeof(err) - 1);
        }
        return 0;
    }

    /* /node/functions/ping — measure RTT to a peer */
    if (strcmp(msg->path, "/node/functions/ping") == 0) {
        const char *pname = NULL;
        for (uint16_t i = 0; i < msg->header_count; i++)
            if (strcmp(msg->headers[i].key, "name") == 0)
                pname = msg->headers[i].value;

        char buf[4096];
        size_t off = 0;

        if (pname && strcmp(pname, "all") != 0) {
            /* Ping single peer */
            node_peer_t *p = find_peer_by_name(pname);
            if (!p || !p->ready) {
                int n = snprintf(buf, sizeof(buf), "Peer '%s' not found or not ready\n", pname);
                portal_resp_set_status(resp, PORTAL_NOT_FOUND);
                portal_resp_set_body(resp, buf, (size_t)n);
                return -1;
            }
            if (p->worker_count == 0 && !p->is_indirect) {
                int n = snprintf(buf, sizeof(buf), "Peer '%s' has no workers\n", pname);
                portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
                portal_resp_set_body(resp, buf, (size_t)n);
                return -1;
            }

            /* Build a ping message to /core/status on remote */
            portal_msg_t ping_msg = {0};
            char ping_path[PORTAL_MAX_PATH_LEN];
            snprintf(ping_path, sizeof(ping_path), "/%s/core/status", pname);
            ping_msg.path = ping_path;
            ping_msg.method = PORTAL_METHOD_GET;

            portal_resp_t ping_resp = {0};
            uint64_t t0 = now_us();
            core->send(core, &ping_msg, &ping_resp);
            uint64_t t1 = now_us();
            double ms = (double)(t1 - t0) / 1000.0;

            const char *tls_tag = "";
#ifdef HAS_SSL
            if (p->ctrl_ssl || (p->worker_count > 0 && p->workers[0].ssl))
                tls_tag = " [TLS]";
#endif
            const char *route = p->is_indirect ? " (via hub)" :
                                (p->is_inbound ? " (inbound)" : "");
            off = (size_t)snprintf(buf, sizeof(buf),
                "%s: %.1fms%s%s\n",
                pname, ms, tls_tag, route);
            free(ping_resp.body);
        } else {
            /* Ping all peers */
            for (int i = 0; i < g_peer_count; i++) {
                node_peer_t *p = &g_peers[i];
                if (!p->ready || p->dead) continue;

                portal_msg_t ping_msg = {0};
                char ping_path[PORTAL_MAX_PATH_LEN];
                snprintf(ping_path, sizeof(ping_path), "/%s/core/status", p->name);
                ping_msg.path = ping_path;
                ping_msg.method = PORTAL_METHOD_GET;

                portal_resp_t ping_resp = {0};
                uint64_t t0 = now_us();
                core->send(core, &ping_msg, &ping_resp);
                uint64_t t1 = now_us();
                double ms = (double)(t1 - t0) / 1000.0;

                const char *tls_tag = "";
#ifdef HAS_SSL
                if (p->ctrl_ssl || (p->worker_count > 0 && p->workers[0].ssl))
                    tls_tag = " [TLS]";
#endif
                const char *route = p->is_indirect ? " (via hub)" :
                                    (p->is_inbound ? " (inbound)" : "");
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "  %-16s %.1fms%s%s\n",
                    p->name, ms, tls_tag, route);
                free(ping_resp.body);
            }
            if (g_peer_count == 0)
                off = (size_t)snprintf(buf, sizeof(buf), "(no peers)\n");
        }

        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    /* /node/functions/trace — traceroute to a path showing hops */
    if (strcmp(msg->path, "/node/functions/trace") == 0) {
        const char *target_path = NULL;
        for (uint16_t i = 0; i < msg->header_count; i++)
            if (strcmp(msg->headers[i].key, "path") == 0)
                target_path = msg->headers[i].value;

        if (!target_path) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            char err[] = "Need: path header\n";
            portal_resp_set_body(resp, err, sizeof(err) - 1);
            return -1;
        }

        char buf[4096];
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
            "Trace: %s\n", target_path);

        /* Hop 0: local */
        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
            "  hop 0: %s (local)          0.0ms\n", g_node_name);

        /* Check if path targets a remote peer */
        if (target_path[0] == '/') {
            const char *slash = strchr(target_path + 1, '/');
            if (slash) {
                char pname[PORTAL_MAX_MODULE_NAME];
                size_t nlen = (size_t)(slash - target_path - 1);
                if (nlen < sizeof(pname)) {
                    memcpy(pname, target_path + 1, nlen);
                    pname[nlen] = '\0';

                    node_peer_t *p = find_peer_by_name(pname);
                    if (p && p->ready) {
                        /* Hop 1: direct or hub */
                        if (p->is_indirect && p->hub_idx >= 0 &&
                            p->hub_idx < g_peer_count) {
                            /* Two hops: local → hub → target */
                            node_peer_t *hub = &g_peers[p->hub_idx];

                            /* Measure hop to hub */
                            portal_msg_t hm = {0};
                            char hp[PORTAL_MAX_PATH_LEN];
                            snprintf(hp, sizeof(hp), "/%s/core/status", hub->name);
                            hm.path = hp;
                            hm.method = PORTAL_METHOD_GET;
                            portal_resp_t hr = {0};
                            uint64_t t0 = now_us();
                            core->send(core, &hm, &hr);
                            uint64_t t1 = now_us();
                            double ms1 = (double)(t1 - t0) / 1000.0;
                            free(hr.body);

                            const char *tls1 = "";
#ifdef HAS_SSL
                            if (hub->ctrl_ssl || (hub->worker_count > 0 && hub->workers[0].ssl))
                                tls1 = " [TLS]";
#endif
                            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                                "  hop 1: %-16s   %.1fms%s (hub)\n",
                                hub->name, ms1, tls1);

                            /* Measure full path to target via hub */
                            portal_msg_t tm = {0};
                            tm.path = (char *)target_path;
                            tm.method = PORTAL_METHOD_GET;
                            portal_resp_t tr = {0};
                            t0 = now_us();
                            core->send(core, &tm, &tr);
                            t1 = now_us();
                            double ms2 = (double)(t1 - t0) / 1000.0;

                            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                                "  hop 2: %-16s   %.1fms%s\n",
                                pname, ms2, tls1);
                            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                                "  result: %d (%zu bytes)\n",
                                tr.status, tr.body_len);
                            free(tr.body);
                        } else {
                            /* One hop: local → target */
                            portal_msg_t tm = {0};
                            tm.path = (char *)target_path;
                            tm.method = PORTAL_METHOD_GET;
                            portal_resp_t tr = {0};
                            uint64_t t0 = now_us();
                            core->send(core, &tm, &tr);
                            uint64_t t1 = now_us();
                            double ms = (double)(t1 - t0) / 1000.0;

                            const char *tls_tag = "";
#ifdef HAS_SSL
                            if (p->ctrl_ssl || (p->worker_count > 0 && p->workers[0].ssl))
                                tls_tag = " [TLS]";
#endif
                            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                                "  hop 1: %-16s   %.1fms%s\n",
                                pname, ms, tls_tag);
                            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                                "  result: %d (%zu bytes)\n",
                                tr.status, tr.body_len);
                            free(tr.body);
                        }
                    } else {
                        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                            "  hop 1: %s — peer not found\n", pname);
                    }
                }
            } else {
                /* Local path */
                portal_msg_t lm = {0};
                lm.path = (char *)target_path;
                lm.method = PORTAL_METHOD_GET;
                portal_resp_t lr = {0};
                uint64_t t0 = now_us();
                core->send(core, &lm, &lr);
                uint64_t t1 = now_us();
                double ms = (double)(t1 - t0) / 1000.0;
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "  result: %d (%zu bytes) %.1fms (local)\n",
                    lr.status, lr.body_len, ms);
                free(lr.body);
            }
        }

        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

#ifdef HAS_SSL
    /* /node/functions/reload_tls — reload cert/key files */
    if (strcmp(msg->path, "/node/functions/reload_tls") == 0) {
        char buf[256];
        int n;
        if (!g_tls_enabled) {
            n = snprintf(buf, sizeof(buf), "TLS not enabled\n");
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
        } else if (reload_tls_contexts() == 0) {
            n = snprintf(buf, sizeof(buf), "TLS contexts reloaded\n");
            portal_resp_set_status(resp, PORTAL_OK);
        } else {
            n = snprintf(buf, sizeof(buf), "TLS reload failed\n");
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
        }
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* /node/functions/renew_tls — check + renew via mod_acme, then reload */
    if (strcmp(msg->path, "/node/functions/renew_tls") == 0) {
        char buf[1024];
        int n;

        if (!g_tls_enabled) {
            n = snprintf(buf, sizeof(buf), "TLS not enabled\n");
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            portal_resp_set_body(resp, buf, (size_t)n);
            return 0;
        }

        /* Check cert expiry via mod_acme */
        if (core->module_loaded(core, "acme")) {
            portal_msg_t *cm = portal_msg_alloc();
            portal_resp_t *cr = portal_resp_alloc();
            if (cm && cr) {
                portal_msg_set_path(cm, "/acme/functions/renew");
                portal_msg_set_method(cm, PORTAL_METHOD_CALL);
                core->send(core, cm, cr);

                if (cr->status == PORTAL_OK) {
                    /* Reload TLS contexts with (possibly renewed) certs */
                    reload_tls_contexts();
                    n = snprintf(buf, sizeof(buf),
                        "Renewal check complete, TLS reloaded\n");
                } else {
                    n = snprintf(buf, sizeof(buf),
                        "ACME renewal returned status %d\n", cr->status);
                }
                portal_msg_free(cm);
                portal_resp_free(cr);
            } else {
                n = snprintf(buf, sizeof(buf), "Memory allocation failed\n");
            }
        } else {
            /* No mod_acme — just reload contexts */
            reload_tls_contexts();
            n = snprintf(buf, sizeof(buf),
                "mod_acme not loaded, TLS contexts reloaded\n");
        }
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }
#endif /* HAS_SSL */

    /* /node/functions/pipe — raw TCP pipe through worker fd */
    if (strcmp(msg->path, "/node/functions/pipe") == 0) {
        const char *peer_name = NULL, *port_str = NULL;
        for (uint16_t hi = 0; hi < msg->header_count; hi++) {
            if (strcmp(msg->headers[hi].key, "peer") == 0) peer_name = msg->headers[hi].value;
            if (strcmp(msg->headers[hi].key, "port") == 0) port_str = msg->headers[hi].value;
        }
        if (!peer_name || !port_str) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }

        node_peer_t *peer = find_peer_by_name(peer_name);
        if (!peer || !peer->ready || peer->worker_count == 0) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            return -1;
        }

        worker_t *w = get_worker(peer);
        if (!w || w->fd < 0) {
            portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
            return -1;
        }

        /* Send PIPE request to remote via wire protocol */
        portal_msg_t pipe_msg = {0};
        char pipe_path[] = "/tunnel/pipe";
        pipe_msg.path = pipe_path;
        pipe_msg.method = PORTAL_METHOD_CALL;
        portal_header_t ph = { .key = "port", .value = (char *)port_str };
        pipe_msg.headers = &ph;
        pipe_msg.header_count = 1;

        portal_resp_t pipe_resp = {0};
        int rc = worker_send_recv(w, &pipe_msg, &pipe_resp);

        if (rc == 0 && pipe_resp.status == PORTAL_OK) {
            int plain_fd = w->fd;  /* default: return worker fd directly */

#ifdef HAS_SSL
            /* TLS: mod_tunnel can't read/write TLS directly.
             * Create socketpair: one end for TLS relay, other for tunnel.
             * Tunnel gets a plain TCP fd, TLS handled transparently. */
            if (w->ssl) {
                int sp[2];
                if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0) {
                    pipe_ctx_t *pctx = malloc(sizeof(*pctx));
                    pctx->worker_fd = w->fd;
                    pctx->service_fd = sp[0];  /* relay side */
                    pctx->worker_ssl = w->ssl;
                    plain_fd = sp[1];  /* tunnel gets this (plain) */

                    pthread_t th;
                    pthread_create(&th, NULL, pipe_relay_thread, pctx);
                    pthread_detach(th);
                }
            }
#endif

            char fd_str[16];
            int fd_n = snprintf(fd_str, sizeof(fd_str), "%d", plain_fd);
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, fd_str, (size_t)fd_n);
            w->busy = 2;  /* pipe mode */
            free(pipe_resp.body);
            core->log(core, PORTAL_LOG_INFO, "node",
                      "Pipe opened: %s:%s via fd %d%s",
                      peer_name, port_str, plain_fd,
                      plain_fd != w->fd ? " (TLS bridge)" : "");
        } else {
            release_worker(peer, w);
            portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
            free(pipe_resp.body);
        }
        return 0;
    }

    /* Route to remote peer: /<peer_name>/rest/of/path */
    const char *path = msg->path;
    if (path[0] == '/') {
        const char *slash = strchr(path + 1, '/');
        if (slash) {
            char peer_name[PORTAL_MAX_MODULE_NAME];
            size_t nlen = (size_t)(slash - path - 1);
            if (nlen < sizeof(peer_name)) {
                memcpy(peer_name, path + 1, nlen);
                peer_name[nlen] = '\0';

                node_peer_t *peer = find_peer_by_name(peer_name);
                core->log(core, PORTAL_LOG_DEBUG, "node",
                          "Route lookup: peer='%s' found=%d ready=%d workers=%d",
                          peer_name, peer ? 1 : 0,
                          peer ? peer->ready : 0,
                          peer ? peer->worker_count : 0);

                /* Indirect peer: forward full path through hub */
                if (peer && peer->ready && peer->is_indirect) {
                    int hi = peer->hub_idx;
                    if (hi >= 0 && hi < g_peer_count &&
                        g_peers[hi].ready && g_peers[hi].worker_count > 0) {
                        worker_t *w = get_worker(&g_peers[hi]);

                        /* Send full path including target node prefix —
                         * the hub will route it to the target node */
                        portal_msg_t remote_msg = *msg;

                        peer->msgs_sent++;
                        int rc = worker_send_recv(w, &remote_msg, resp);
                        release_worker(&g_peers[hi], w);

                        if (rc == 0) {
                            peer->msgs_recv++;
                            if (resp->body_len > 0)
                                peer->bytes_recv += resp->body_len;
                            core->log(core, PORTAL_LOG_DEBUG, "node",
                                      "Routed %s → %s via hub '%s' [%d]",
                                      msg->path, peer_name,
                                      g_peers[hi].name, resp->status);
                            return 0;
                        }
                        peer->errors++;
                        portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
                        return -1;
                    }
                }

                /* Direct peer: strip node prefix and forward */
                if (peer && peer->ready && peer->worker_count > 0) {
                    worker_t *w = get_worker(peer);

                    portal_msg_t remote_msg = *msg;
                    remote_msg.path = (char *)slash;

                    peer->msgs_sent++;
                    if (msg->body_len > 0)
                        peer->bytes_sent += msg->body_len;
                    int rc = worker_send_recv(w, &remote_msg, resp);
                    release_worker(peer, w);

                    if (rc == 0) {
                        peer->msgs_recv++;
                        if (resp->body_len > 0)
                            peer->bytes_recv += resp->body_len;
                        core->log(core, PORTAL_LOG_DEBUG, "node",
                                  "Routed %s → %s [%d]",
                                  msg->path, peer_name, resp->status);
                        return 0;
                    }

                    peer->errors++;
                    portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
                    return -1;
                }
            }
        }
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
