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
 * mod_node — Node Federation Module
 *
 * Connects Portal instances into a distributed network.
 * Remote paths transparently accessible as /node_name/path.
 * Wire protocol (PORTAL02) over TCP/TLS. Single-threaded, fully async:
 * all TCP/TLS/PORTAL02 handshakes + peer I/O drive through libev in
 * the core event loop. See Commits 4-7 of the scale-out refactor.
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
#include <fcntl.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <pty.h>
#include <signal.h>
#include <termios.h>

#include "../../src/core/core_hashtable.h"

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

#define NODE_MAX_PEERS        16384  /* sanity cap; peers are heap-allocated individually */
#define NODE_MAX_THREADS      16
#define NODE_BUF_SIZE         65536
#define NODE_DEFAULT_PORT     9700
#define NODE_DEFAULT_THREADS  4
#define NODE_HANDSHAKE_MAGIC  "PORTAL02"
#define NODE_RECONNECT_SEC    10
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
#endif

/* --- Persistent worker connections (NOT threads) ---
 *
 * A worker is one TCP/TLS connection to a peer. Since Commit 4d, all
 * outbound traffic goes through peer_send_wait() which round-robins
 * across workers and correlates responses via a per-fd FIFO. There is
 * no separate pthread per worker — the event loop drives everything. */

typedef struct {
    int            fd;          /* persistent TCP connection, -1 if dead */
    int            busy;        /* 1 = processing a request, 2 = pipe mode */
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

    /* Commit 6: exponential backoff state for outbound reconnect. Reset
     * to 0/0 when the peer reaches READY. reconnect_dead_peers skips this
     * peer until now_us() >= next_retry_us. */
    int            retry_count;
    uint64_t       next_retry_us;
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

/* Peer advertisement control — who sees who in `node peers` */
#define ADV_NONE      0   /* don't advertise any peers (default — privacy) */
#define ADV_ALL       1   /* advertise all direct peers (legacy behavior) */
#define ADV_WHITELIST 2   /* advertise only to peers in advertise_to list */
static int             g_advertise_mode = ADV_NONE;
static char            g_advertise_to[512] = "";  /* comma-separated whitelist */
/* Dynamic peer registry. Each peer is a separate heap allocation so pointers
 * returned by find_peer_* stay valid across growth of the pointer array.
 * g_peers_cap starts small and doubles on demand up to NODE_MAX_PEERS. */
static node_peer_t   **g_peers = NULL;
static int             g_peers_cap = 0;
static int             g_peer_count = 0;

/* Ensure the pointer array has room for at least `min_cap` entries.
 * Returns 0 on success, -1 on allocation failure. */
static int peers_ensure_capacity(int min_cap)
{
    if (g_peers_cap >= min_cap) return 0;
    int new_cap = g_peers_cap ? g_peers_cap : 64;
    while (new_cap < min_cap) new_cap *= 2;
    if (new_cap > NODE_MAX_PEERS) new_cap = NODE_MAX_PEERS;
    if (new_cap < min_cap) return -1;  /* hit hard cap */

    node_peer_t **nw = realloc(g_peers, (size_t)new_cap * sizeof(node_peer_t *));
    if (!nw) return -1;
    /* zero the new tail */
    for (int i = g_peers_cap; i < new_cap; i++) nw[i] = NULL;
    g_peers = nw;
    g_peers_cap = new_cap;
    return 0;
}

/* Allocate a new peer slot and return its index. Caller fills the fields.
 * Returns -1 if the hard cap is reached. */
static int peers_append(void)
{
    if (g_peer_count >= NODE_MAX_PEERS) return -1;
    if (peers_ensure_capacity(g_peer_count + 1) < 0) return -1;

    node_peer_t *p = calloc(1, sizeof(node_peer_t));
    if (!p) return -1;
    g_peers[g_peer_count] = p;
    return g_peer_count++;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Per-fd incremental read state (Commit 3: incremental inbound reader)
 *
 *  Each peer fd registered in the event loop carries an rx_state_t as
 *  libev userdata. The state accumulates bytes across multiple EV_READ
 *  wake-ups so we never block the loop waiting for a partial frame to
 *  complete. The fd must be non-blocking (set via set_nonblocking()).
 *
 *  Lifetime: allocated by node_fd_add_with_rx(), freed by
 *  node_fd_del_with_rx(). Tracked in g_rx_by_fd hashtable so the del-side
 *  can find it (core's fd_del doesn't give us the userdata back).
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Forward declaration — pending_req_t is defined below; rx_state_t
 * holds pointers to it as head/tail of the per-fd FIFO queue. */
struct pending_req;

typedef struct {
    /* ── rx side (Commit 3: incremental reader) ── */
    uint8_t *buf;        /* allocated read buffer */
    size_t   cap;        /* allocated capacity */
    size_t   len;        /* bytes currently in buf */
    size_t   need;       /* total bytes expected for current frame (0 = not parsed) */

    /* ── tx side (Commit 4b: dormant until Commit 4c wires it in) ── */
    uint8_t *tx_buf;     /* queued outbound wire bytes */
    size_t   tx_cap;     /* allocated capacity of tx_buf */
    size_t   tx_len;     /* bytes currently queued */
    size_t   tx_off;     /* bytes already sent from tx_buf */

    /* Currently-registered libev event mask (EV_READ, or EV_READ|EV_WRITE
     * when tx_buf has data to flush). Used by fd_state_ensure_writable() /
     * fd_state_stop_writable() to avoid redundant fd_modify calls. */
    uint32_t events;

    /* fd this state belongs to. Cached for helpers that need it when only
     * the state pointer is in hand (e.g., on_writable, pending_wait). */
    int      fd;

    /* Per-fd FIFO of outstanding outbound requests. Responses from the peer
     * match the head of this queue (TCP order guarantee). Fields managed
     * by Commit 4d's peer_send_wait / pending_wait — dormant until then. */
    struct pending_req *pending_head;
    struct pending_req *pending_tail;
    int      pending_count;

    /* ── Commit 5: async handshake state machine ──
     * Most fds are CONN_STATE_READY (normal traffic). Inbound fds in the
     * middle of the TLS + PORTAL02 handshake are in a transient state and
     * carry an hs_context_t with the scratch data needed to finish. */
    int      conn_state;       /* conn_state_t, default READY */
    uint64_t state_enter_us;   /* when we entered the current state */
    struct hs_context *hs;     /* handshake scratch; NULL for READY conns */

    /* ── Commit 7b: SSL* stored per-fd ──
     * Replaces the old g_fd_ssl[8192] static array. Direct pointer access,
     * no bounds check, no cap — rx_state_t is already in hand on every
     * hot path (it's the libev userdata). For peer worker fds the same
     * SSL* is also cached in peer->workers[i].ssl so cleanup paths that
     * only have the fd can resolve it via ssl_for_fd(). */
#ifdef HAS_SSL
    SSL     *ssl;
#endif
} rx_state_t;

/* Connection lifecycle states. Default for fds created via node_fd_add_with_rx
 * is READY (back-compat with Commits 3/4). Fds created via
 * node_fd_add_inbound_handshake start in TLS_ACCEPT. Commit 6 will add
 * TLS_CONNECT for the outbound side. */
typedef enum {
    CONN_STATE_READY = 0,       /* normal traffic (default) */
    CONN_STATE_TCP_CONNECTING,  /* outbound non-blocking connect() in flight */
    CONN_STATE_TLS_ACCEPT,      /* inbound SSL_do_handshake in flight */
    CONN_STATE_TLS_CONNECT,     /* outbound SSL_do_handshake in flight */
    CONN_STATE_HS_EXCHANGE,     /* sending + receiving PORTAL02 handshake */
    CONN_STATE_DEAD             /* cleanup pending */
} conn_state_t;

/* Scratch data for an in-progress handshake. Allocated only for transient
 * conns, freed by rx_free when the fd is cleaned up. Kept separate from
 * the ~160-byte fd_state_t to avoid bloating every steady-state conn. */
typedef struct hs_context {
    struct sockaddr_in peer_addr;   /* for logging and peer registration */

    /* Commit 6: outbound side needs a backref to the peer this fd is
     * building. Inbound leaves these NULL/0; for inbound, finalize_handshake
     * creates or looks up the peer by name from the received handshake bytes. */
    node_peer_t *peer;              /* NULL for inbound; set for outbound */
    int      is_outbound;           /* 1 = outbound, 0 = inbound */
    int      slot_hint;             /* for outbound: which workers[] slot to fill */

    /* Decoded peer info (filled by drive_hs_recv as bytes arrive) */
    char     peer_name[PORTAL_MAX_MODULE_NAME];

    /* Advertised peer list — populated incrementally. Using a dynamic
     * list avoids the 1 MB stack blowup the old synchronous path had. */
    char   **advertised;
    int      adv_count;
    int      adv_cap;

    /* Recv parse state */
    int      recv_phase;    /* 0 hdr, 1 name, 2 count, 3 pn_len, 4 pn, 5 done */
    uint16_t name_len;      /* filled at phase 1 */
    uint16_t peer_count;    /* filled at phase 2 */
    uint16_t next_pn_len;   /* filled at phase 3, consumed at phase 4 */

    /* Send state */
    int      send_queued;   /* 1 = PORTAL02 bytes already appended to tx_buf */
    int      send_done;     /* 1 = tx_buf fully drained */
    int      recv_done;     /* 1 = PORTAL02 handshake fully parsed */
} hs_context_t;

/* A single outstanding outbound request waiting for its response.
 *
 * Lifetime (when Commit 4d wires this up):
 *   1. Caller allocates on the stack or heap, fills ->resp and ->deadline_us.
 *   2. peer_send_wait pushes it to the tail of some fd's pending FIFO,
 *      appends the wire bytes to that fd's tx_buf, and calls pending_wait.
 *   3. pending_wait runs a nested ev_run(loop, EVRUN_ONCE) loop until
 *      ->done becomes 1 (set by on_inbound_data when it matches a response)
 *      or the deadline fires (pending_wait sets ->done and ->rc = -1).
 *   4. Caller reads ->rc and frees (if heap-allocated).
 *
 * No pthread mutex/cv — everything is single-threaded (core thread).
 */
typedef struct pending_req {
    uint64_t             deadline_us;  /* absolute deadline (now_us() + timeout) */
    int                  done;         /* 1 = response received or timeout/error */
    int                  rc;           /* 0 = ok, -1 = error/timeout */
    portal_resp_t       *resp;         /* caller-provided response destination */
    struct pending_req  *next;         /* FIFO linkage inside rx_state_t */
} pending_req_t;

/* Forward declarations for Commit 4b helpers defined below node_read_nb.
 * rx_free() references fd_state_fail_pending() to walk the FIFO when a
 * conn dies — the helper lives in the Commit 4b block further down. */
static void fd_state_fail_pending(rx_state_t *st);

/* Forward declarations for functions defined further down in the file
 * that are referenced by the Commit 4b helpers block (which is placed
 * after node_read_nb, itself before these functions are defined). */
static void mark_peer_dead_by_fd(int fd);
static uint64_t now_us(void);
static void register_indirect_peer(const char *name, int hub_idx);

static portal_ht_t g_rx_by_fd;      /* fd (as decimal string) → rx_state_t* */
static int         g_rx_ht_inited = 0;

static void rx_key(int fd, char *buf, size_t buflen)
{
    snprintf(buf, buflen, "%d", fd);
}

static rx_state_t *rx_alloc(int fd)
{
    rx_state_t *rx = calloc(1, sizeof(rx_state_t));
    if (rx) {
        rx->fd = fd;
        rx->events = EV_READ;   /* default; tx-path enables EV_WRITE lazily */
    }
    return rx;
}

static void hs_context_free(hs_context_t *hs)
{
    if (!hs) return;
    for (int i = 0; i < hs->adv_count; i++) free(hs->advertised[i]);
    free(hs->advertised);
    free(hs);
}

static void rx_free(rx_state_t *rx)
{
    if (!rx) return;
    /* Fail any pending waiters before freeing the state — Commit 4d
     * relies on this invariant so dying peers wake all their callers. */
    fd_state_fail_pending(rx);
    /* Commit 5: free transient handshake scratch and the SSL if we
     * own it (i.e., the handshake died before finalize_handshake
     * transferred ownership to a node_peer_t). Commit 7b: ssl lives
     * on rx now, so we just free rx->ssl directly. */
#ifdef HAS_SSL
    if (rx->conn_state != CONN_STATE_READY && rx->ssl) {
        SSL_free(rx->ssl);
        rx->ssl = NULL;
    }
#endif
    hs_context_free(rx->hs);
    free(rx->buf);
    free(rx->tx_buf);
    free(rx);
}

/* Reset rx_state_t for the next frame. Keeps the buffer allocated for
 * reuse; zeroes the lengths. */
static void rx_reset(rx_state_t *rx)
{
    rx->len = 0;
    rx->need = 0;
}

/* Set an fd to non-blocking mode. Must be called on every peer fd that is
 * registered in the event loop so the incremental reader can return to
 * libev between partial reads instead of blocking. */
static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Restore blocking mode. Used by worker_send_recv while the fd is
 * temporarily out of the event loop (via get_worker's fd_del). */
static int set_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

/* Forward declaration — on_inbound_data is defined much later */
static void on_inbound_data(int fd, uint32_t events, void *userdata);

/* Register an fd in the event loop with per-fd rx_state passed as userdata.
 * Creates a fresh rx_state_t, stores it in g_rx_by_fd, and calls fd_add. */
static int node_fd_add_with_rx(int fd)
{
    if (!g_rx_ht_inited) {
        portal_ht_init(&g_rx_by_fd, 256);
        g_rx_ht_inited = 1;
    }
    rx_state_t *rx = rx_alloc(fd);
    if (!rx) return -1;

    char key[16];
    rx_key(fd, key, sizeof(key));
    /* If a stale entry exists (shouldn't happen, but defend), free it */
    rx_state_t *old = portal_ht_get(&g_rx_by_fd, key);
    if (old) {
        rx_free(old);
        portal_ht_del(&g_rx_by_fd, key);
    }
    portal_ht_set(&g_rx_by_fd, key, rx);

    if (g_core->fd_add(g_core, fd, EV_READ, on_inbound_data, rx) < 0) {
        portal_ht_del(&g_rx_by_fd, key);
        rx_free(rx);
        return -1;
    }
    return 0;
}

/* Remove an fd from the event loop and free its rx_state. Safe to call on
 * fds that were registered without rx_state (the hashtable lookup returns
 * NULL and only fd_del is performed). */
static void node_fd_del_with_rx(int fd)
{
    if (g_rx_ht_inited) {
        char key[16];
        rx_key(fd, key, sizeof(key));
        rx_state_t *rx = portal_ht_get(&g_rx_by_fd, key);
        if (rx) {
            portal_ht_del(&g_rx_by_fd, key);
            rx_free(rx);
        }
    }
    g_core->fd_del(g_core, fd);
}

/* Non-blocking read that distinguishes would-block from hard error.
 * Returns:
 *    > 0    bytes read
 *    0      EOF (peer closed)
 *   -1      hard error (mark dead)
 *   -2      would block (retry on next event) */
static ssize_t node_read_nb(int fd, void *ssl_ptr, void *buf, size_t len)
{
#ifdef HAS_SSL
    SSL *ssl = (SSL *)ssl_ptr;
    if (ssl) {
        int n = SSL_read(ssl, buf, (int)len);
        if (n > 0) return n;
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            return -2;
        if (err == SSL_ERROR_ZERO_RETURN) return 0;   /* clean close */
        return -1;
    }
#else
    (void)ssl_ptr;
#endif
    ssize_t n = read(fd, buf, len);
    if (n > 0) return n;
    if (n == 0) return 0;   /* EOF */
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return -2;
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Outbound tx path + sync-over-async wait (Commits 4b/4c/4d, now active)
 *
 *  node_write_nb     — non-blocking SSL/plain write
 *  on_writable       — drains fd_state_t->tx_buf when libev fires EV_WRITE
 *  pending_wait      — nested ev_run(EVRUN_ONCE) until done or timeout
 *  peer_send_wait    — full round-trip wrapper for outbound /peer/... route
 *
 *  All of these are now wired into the hot path:
 *    - Commit 4c: inbound response send uses fd_state_tx_append + on_writable
 *    - Commit 4d: /peer/... route uses peer_send_wait + FIFO correlation
 *    - Commit 5/6: TLS handshake drive loop shares the same tx_buf infra
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Non-blocking write — mirrors node_read_nb return convention:
 *    > 0    bytes written
 *    0      peer closed (hard error treated same as -1)
 *   -1      hard error (mark peer dead)
 *   -2      would block (retry on next EV_WRITE event) */
static ssize_t node_write_nb(int fd, void *ssl_ptr, const void *buf, size_t len)
{
#ifdef HAS_SSL
    SSL *ssl = (SSL *)ssl_ptr;
    if (ssl) {
        int n = SSL_write(ssl, buf, (int)len);
        if (n > 0) return n;
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            return -2;
        return -1;
    }
#else
    (void)ssl_ptr;
#endif
    ssize_t n = write(fd, buf, len);
    if (n > 0) return n;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return -2;
    return -1;
}

/* Walk the FIFO pending queue and mark every entry as failed. Used by
 * rx_free (when a conn dies) so all in-flight callers get PORTAL_UNAVAILABLE
 * on their nested ev_run wakeup. Forward-declared above rx_free. */
static void fd_state_fail_pending(rx_state_t *st)
{
    pending_req_t *pr = st->pending_head;
    while (pr) {
        pending_req_t *next = pr->next;
        if (pr->resp) pr->resp->status = PORTAL_UNAVAILABLE;
        pr->rc = -1;
        pr->done = 1;
        pr = next;
    }
    st->pending_head = st->pending_tail = NULL;
    st->pending_count = 0;
}

/* Append wire bytes to the fd's tx_buf, growing the buffer as needed.
 * The actual socket write happens in on_writable(). Returns 0 on success,
 * -1 on allocation failure. */
static int fd_state_tx_append(rx_state_t *st, const void *data, size_t len)
{
    if (st->tx_len + len > st->tx_cap) {
        size_t ncap = st->tx_cap ? st->tx_cap : 4096;
        while (ncap < st->tx_len + len) ncap *= 2;
        uint8_t *nb = realloc(st->tx_buf, ncap);
        if (!nb) return -1;
        st->tx_buf = nb;
        st->tx_cap = ncap;
    }
    memcpy(st->tx_buf + st->tx_len, data, len);
    st->tx_len += len;
    return 0;
}

/* Ensure EV_WRITE is registered on this fd so on_writable fires when the
 * kernel can accept more data. Idempotent — skips the fd_modify call if
 * the fd already has EV_WRITE set. */
static void fd_state_ensure_writable(rx_state_t *st)
{
    if (!(st->events & EV_WRITE)) {
        st->events |= EV_WRITE;
        g_core->fd_modify(g_core, st->fd, st->events);
    }
}

/* Drop EV_WRITE from the fd's event mask once tx_buf is fully drained.
 * Keeps EV_READ active. */
static void fd_state_stop_writable(rx_state_t *st)
{
    if (st->events & EV_WRITE) {
        st->events = EV_READ;
        g_core->fd_modify(g_core, st->fd, st->events);
    }
}

/* Drain as much of tx_buf as possible without blocking. When the buffer
 * is empty, drop EV_WRITE. On hard error, mark the peer dead and fail all
 * pending waiters. Called by Commit 4c's on_inbound_data when libev
 * delivers EV_WRITE on the fd. */
static void on_writable(rx_state_t *st)
{
    if (!st || st->tx_len == 0) {
        if (st) fd_state_stop_writable(st);
        return;
    }
#ifdef HAS_SSL
    void *ssl = st->ssl;
#else
    void *ssl = NULL;
#endif
    while (st->tx_off < st->tx_len) {
        ssize_t n = node_write_nb(st->fd, ssl,
                                    st->tx_buf + st->tx_off,
                                    st->tx_len - st->tx_off);
        if (n > 0) {
            st->tx_off += (size_t)n;
        } else if (n == -2) {
            return;   /* would block — retry on next EV_WRITE */
        } else {
            mark_peer_dead_by_fd(st->fd);
            fd_state_fail_pending(st);
            return;
        }
    }
    /* Fully drained */
    st->tx_off = 0;
    st->tx_len = 0;
    fd_state_stop_writable(st);
}

/* Block the caller on a nested ev_run until pr->done becomes 1 or the
 * deadline fires. On timeout, unlinks pr from its owning FIFO and sets
 * rc = -1. libev supports re-entrant ev_run, so nested calls stack
 * safely as long as each level eventually completes or times out. */
static void pending_wait(rx_state_t *st, pending_req_t *pr)
{
    struct ev_loop *loop = (struct ev_loop *)g_core->ev_loop_get(g_core);
    while (!pr->done) {
        uint64_t now = now_us();
        if (now >= pr->deadline_us) {
            /* Unlink pr from the FIFO if still present */
            pending_req_t **link = &st->pending_head;
            while (*link && *link != pr) link = &(*link)->next;
            if (*link) {
                *link = pr->next;
                if (st->pending_tail == pr) {
                    st->pending_tail = st->pending_head;
                    while (st->pending_tail && st->pending_tail->next)
                        st->pending_tail = st->pending_tail->next;
                }
                st->pending_count--;
            }
            if (pr->resp) pr->resp->status = PORTAL_UNAVAILABLE;
            pr->rc = -1;
            pr->done = 1;
            break;
        }
        ev_run(loop, EVRUN_ONCE);
    }
}

/* Submit an outbound portal_msg_t to one of peer's worker fds and block
 * re-entrantly until a response arrives or timeout_us elapses. Returns
 * 0 on success (resp filled), -1 on error.
 *
 * Replaces the Commit-3 get_worker + worker_send_recv + release_worker
 * synchronous blocking path. No fd_del/fd_add churn. The core thread
 * pumps libev via pending_wait while the response is in flight. */
static int peer_send_wait(node_peer_t *peer, const portal_msg_t *msg,
                           portal_resp_t *resp, uint64_t timeout_us)
{
    if (!peer || !peer->ready || peer->dead)
        return -1;

    /* Round-robin pick a worker fd whose fd_state is registered */
    rx_state_t *st = NULL;
    int picked_idx = -1;
    for (int attempt = 0; attempt < peer->worker_count; attempt++) {
        int idx = (peer->next_worker + attempt) % peer->worker_count;
        if (peer->workers[idx].fd < 0) continue;
        if (peer->workers[idx].busy == 2) continue;   /* pipe mode */
        char key[16];
        rx_key(peer->workers[idx].fd, key, sizeof(key));
        rx_state_t *cand = portal_ht_get(&g_rx_by_fd, key);
        if (cand) {
            st = cand;
            picked_idx = idx;
            break;
        }
    }
    /* Inbound peers have ctrl_fd but no workers — use ctrl_fd */
    if (!st && peer->ctrl_fd >= 0) {
        char key[16];
        rx_key(peer->ctrl_fd, key, sizeof(key));
        st = portal_ht_get(&g_rx_by_fd, key);
    }
    if (!st) return -1;
    if (picked_idx >= 0)
        peer->next_worker = (picked_idx + 1) % peer->worker_count;

    /* Encode message into wire bytes */
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (portal_wire_encode_msg(msg, &wire, &wire_len) < 0)
        return -1;

    /* Append to tx_buf and enable EV_WRITE */
    if (fd_state_tx_append(st, wire, wire_len) < 0) {
        free(wire);
        return -1;
    }
    free(wire);
    fd_state_ensure_writable(st);

    /* Push a pending_req on the FIFO tail */
    pending_req_t *pr = calloc(1, sizeof(*pr));
    if (!pr) return -1;
    pr->resp = resp;
    pr->deadline_us = now_us() + timeout_us;
    pr->done = 0;
    pr->rc = -1;
    if (st->pending_tail) st->pending_tail->next = pr;
    else st->pending_head = pr;
    st->pending_tail = pr;
    st->pending_count++;

    /* Block on nested ev_run until done */
    pending_wait(st, pr);

    int rc = pr->rc;
    free(pr);
    return rc;
}

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
/* Commit 7b: fd_ssl_get/set/clear + g_fd_ssl[NODE_MAX_FDS] removed.
 * SSL* now lives on rx_state_t->ssl (per-fd state). The only fds that
 * carry SSL are those with a live rx_state_t in g_rx_by_fd, so the
 * static array was pure overhead — bounds check on every access plus
 * 64 KB of zero'd memory at module load. */

/* Helper: look up the SSL* for an fd when only the fd is in hand (e.g.
 * peer cleanup paths that don't have the rx pointer). Prefers peer
 * workers[].ssl / ctrl_ssl (the stable peer-level cache); falls back
 * to g_rx_by_fd only during the transient handshake window. */
static SSL *ssl_for_fd(int fd)
{
    if (fd < 0) return NULL;
    for (int i = 0; i < g_peer_count; i++) {
        node_peer_t *p = g_peers[i];
        if (p->ctrl_fd == fd && p->ctrl_ssl) return p->ctrl_ssl;
        for (int j = 0; j < p->worker_count; j++)
            if (p->workers[j].fd == fd && p->workers[j].ssl)
                return p->workers[j].ssl;
    }
    if (g_rx_ht_inited) {
        char key[16]; rx_key(fd, key, sizeof(key));
        rx_state_t *rx = portal_ht_get(&g_rx_by_fd, key);
        if (rx) return rx->ssl;
    }
    return NULL;
}

/* Commit 7: node_tls_connect / node_tls_accept removed. The async
 * drive_tls state machine (Commit 5/6) replaces both: SSL is created
 * in-place with SSL_set_{connect,accept}_state and driven by
 * SSL_do_handshake with WANT_READ/WANT_WRITE, never blocking. */

static void node_ssl_close(int fd, SSL *ssl)
{
    (void)fd;
    if (ssl) {
        /* Skip SSL_shutdown — just free. Shutdown on dead connections
         * can segfault on some OpenSSL versions (1.1.1 on Ubuntu 18.04) */
        SSL_free(ssl);
    }
    /* Commit 7b: no more per-fd SSL slot to clear — rx->ssl is freed
     * inside rx_free when the fd_state_t is reaped. */
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
 * ================================================================
 *
 * Handshake format (PORTAL02):
 *   8 bytes: magic "PORTAL02"
 *  32 bytes: SHA-256 of federation_key (or zeros if no key)
 *   2 bytes: node name length (big-endian)
 *   N bytes: node name
 *   2 bytes: peer count (number of connected peer names)
 *   For each peer: 2 bytes length + N bytes name
 *
 * Commit 7: the old blocking send_handshake / recv_handshake helpers are
 * gone. The async handshake is now driven by drive_hs_send_build +
 * drive_hs_recv (Commit 5/6) which feed/parse bytes through the event
 * loop via the per-fd hs_context_t scratch area. */

/* Commit 7: create_connection removed. node_fd_add_outbound_handshake
 * (Commit 6) does socket + non-blocking + keepalive + connect() inline
 * and drives completion via the event loop. */

/* Forward declarations */
static void on_inbound_data(int fd, uint32_t events, void *userdata);
static int peer_in_whitelist(const char *name);
static void mark_peer_dead_by_fd(int fd);
static void reconnect_dead_peers(void);

/* --- Peer registry: direct + indirect (hub-proxied) --- */

/* Register an indirect (hub-proxied) peer */
static void register_indirect_peer(const char *name, int hub_idx)
{
    /* Don't register ourselves or already-known peers */
    if (strcmp(name, g_node_name) == 0) return;
    for (int i = 0; i < g_peer_count; i++)
        if (strcmp(g_peers[i]->name, name) == 0) return;

    /* Whitelist mode: only register indirect peers if WE are in the
     * advertise_to list. This filters on the receiving side — the hub
     * sends its full peer list (ADV_ALL/ADV_WHITELIST), but only
     * whitelisted receivers actually register the indirect peers. */
    if (g_advertise_mode == ADV_WHITELIST &&
        !peer_in_whitelist(g_node_name))
        return;

    int idx = peers_append();
    if (idx < 0) return;
    node_peer_t *peer = g_peers[idx];
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
                    name, g_peers[hub_idx]->name);
    }
}

/* Commit 7: create_worker_connections removed. connect_to_peer_async
 * (Commit 6) kicks off N+1 parallel async handshakes — each one
 * independently drives TCP→TLS→PORTAL02 and attaches to the peer via
 * finalize_handshake when done. No serial spin-up. */

static node_peer_t *find_peer_by_name(const char *name)
{
    for (int i = 0; i < g_peer_count; i++)
        if (strcmp(g_peers[i]->name, name) == 0 && g_peers[i]->ready)
            return g_peers[i];
    return NULL;
}

/* Find peer by fd (for inbound counter tracking) */
static node_peer_t *find_peer_by_fd(int fd)
{
    for (int i = 0; i < g_peer_count; i++) {
        node_peer_t *p = g_peers[i];
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
        if (strcmp(g_peers[i]->name, name) == 0)
            return g_peers[i];
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
    /* Restore non-blocking mode before returning to the event loop */
    set_nonblocking(w->fd);
    node_fd_add_with_rx(w->fd);
}

/* Send a message through a worker and read response */
static int worker_send_recv(worker_t *w, const portal_msg_t *msg,
                             portal_resp_t *resp)
{
    /* The fd is non-blocking for the event loop, but worker_send_recv does
     * synchronous send+recv outside the loop (via get_worker's fd_del).
     * Temporarily switch to blocking so plain read/SSL_read behave the
     * old way; release_worker will set it back to non-blocking. */
    set_blocking(w->fd);

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
    set_nonblocking(wfd);
    node_fd_add_with_rx(wfd);
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

    /* Take the worker fd out of the event loop and restore blocking mode
     * for pipe_relay_thread's synchronous select-based byte relay. */
    node_fd_del_with_rx(worker_fd);
    set_blocking(worker_fd);

    pipe_ctx_t *ctx = malloc(sizeof(*ctx));
    ctx->worker_fd = worker_fd;
    ctx->service_fd = sfd;
#ifdef HAS_SSL
    ctx->worker_ssl = ssl_for_fd(worker_fd);
#endif

    pthread_t th;
    pthread_create(&th, NULL, pipe_relay_thread, ctx);
    pthread_detach(th);

    g_core->log(g_core, PORTAL_LOG_INFO, "node",
                "Pipe started: fd %d → localhost:%d", worker_fd, port);
    return 0;
}

/* ================================================================
 * Remote PTY shell — byte relay through worker fd ↔ PTY master
 * Like pipe_relay_thread but the "service" end is a PTY child process.
 * ================================================================ */

typedef struct {
    int  worker_fd;
    int  pty_fd;       /* PTY master */
    pid_t child_pid;
#ifdef HAS_SSL
    SSL *worker_ssl;
#endif
} shell_ctx_t;

static void *shell_pty_relay_thread(void *arg)
{
    shell_ctx_t *ctx = (shell_ctx_t *)arg;
    int wfd = ctx->worker_fd;
    int pfd = ctx->pty_fd;
    int maxfd = (wfd > pfd ? wfd : pfd) + 1;
    char buf[65536];
    void *wssl = NULL;

#ifdef HAS_SSL
    wssl = ctx->worker_ssl;
#endif

    /* Remove socket timeouts for raw relay */
    struct timeval notv = {0, 0};
    setsockopt(wfd, SOL_SOCKET, SO_RCVTIMEO, &notv, sizeof(notv));
    setsockopt(wfd, SOL_SOCKET, SO_SNDTIMEO, &notv, sizeof(notv));

    while (1) {
#ifdef HAS_SSL
        int has_pending = wssl && SSL_pending((SSL *)wssl) > 0;
#else
        int has_pending = 0;
#endif
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(wfd, &rfds);
        FD_SET(pfd, &rfds);

        struct timeval tv = {0, has_pending ? 0 : 100000};
        int rc = select(maxfd, &rfds, NULL, NULL, has_pending ? &tv : NULL);
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0) break;

        /* Federation → PTY (remote input) */
        if (FD_ISSET(wfd, &rfds) || has_pending) {
            do {
                ssize_t n = node_read_partial(wfd, wssl, buf, sizeof(buf));
                if (n <= 0) { if (FD_ISSET(wfd, &rfds)) goto done; else break; }
                ssize_t w = write(pfd, buf, (size_t)n);
                if (w < 0 && errno != EAGAIN) goto done;
#ifdef HAS_SSL
            } while (wssl && SSL_pending((SSL *)wssl) > 0);
#else
            } while (0);
#endif
        }

        /* PTY → Federation (remote output) */
        if (FD_ISSET(pfd, &rfds)) {
            ssize_t n = read(pfd, buf, sizeof(buf));
            if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
            if (n <= 0) break;  /* child exited or PTY closed */
            if (node_send(wfd, wssl, (uint8_t *)buf, (size_t)n) < 0) break;
        }
    }
done:
    /* Cleanup: kill child, close PTY */
    if (ctx->child_pid > 0) {
        kill(ctx->child_pid, SIGHUP);
        usleep(50000);
        kill(ctx->child_pid, SIGKILL);
        waitpid(ctx->child_pid, NULL, WNOHANG);
    }
    close(pfd);

#ifdef HAS_SSL
    if (wssl) {
        node_ssl_close(wfd, (SSL *)wssl);
        close(wfd);
        g_core->log(g_core, PORTAL_LOG_INFO, "node",
                    "Shell TLS relay closed (pid %d)", ctx->child_pid);
        free(ctx);
        return NULL;
    }
#endif
    /* Plain TCP: re-add fd to event loop for reuse */
    set_nonblocking(wfd);
    node_fd_add_with_rx(wfd);
    g_core->log(g_core, PORTAL_LOG_INFO, "node",
                "Shell relay closed (pid %d)", ctx->child_pid);
    free(ctx);
    return NULL;
}

static int start_shell(int worker_fd, int rows, int cols)
{
    struct winsize ws = {
        .ws_row = (unsigned short)(rows > 0 ? rows : 24),
        .ws_col = (unsigned short)(cols > 0 ? cols : 80)
    };

    int master_fd;
    pid_t pid = forkpty(&master_fd, NULL, NULL, &ws);
    if (pid < 0) return -1;

    if (pid == 0) {
        /* Child: exec login shell */
        setenv("TERM", "xterm-256color", 1);
        execl("/bin/bash", "bash", "-l", (char *)NULL);
        _exit(127);
    }

    /* Parent: set PTY master non-blocking for select loop */
    int flags = fcntl(master_fd, F_GETFL, 0);
    fcntl(master_fd, F_SETFL, flags | O_NONBLOCK);

    /* Take worker fd out of event loop → blocking mode for relay */
    node_fd_del_with_rx(worker_fd);
    set_blocking(worker_fd);

    shell_ctx_t *ctx = malloc(sizeof(*ctx));
    ctx->worker_fd = worker_fd;
    ctx->pty_fd = master_fd;
    ctx->child_pid = pid;
#ifdef HAS_SSL
    ctx->worker_ssl = ssl_for_fd(worker_fd);
#endif

    pthread_t th;
    pthread_create(&th, NULL, shell_pty_relay_thread, ctx);
    pthread_detach(th);

    g_core->log(g_core, PORTAL_LOG_INFO, "node",
                "Shell started: fd %d → PTY (pid %d, %dx%d)",
                worker_fd, pid, cols, rows);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Commit 5: async inbound handshake state machine
 *
 *  The old on_new_peer did SSL_accept + send_handshake + recv_handshake
 *  all synchronously, freezing the event loop for tens of ms per peer.
 *  The new path registers each accepted fd in CONN_STATE_TLS_ACCEPT with
 *  an hs_context_t, and on_inbound_data dispatches to drive_tls() /
 *  drive_hs_send() / drive_hs_recv() based on the conn state. Each helper
 *  returns to the loop on WANT_READ/WANT_WRITE/EAGAIN.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Set an fd's conn_state and refresh state_enter_us (for timeout sweep). */
static void conn_set_state(rx_state_t *rx, conn_state_t new_state)
{
    rx->conn_state = new_state;
    rx->state_enter_us = now_us();
}

/* Advertise a peer name into the hs_context's dynamic list. */
static int hs_adv_add(hs_context_t *hs, const char *name)
{
    if (hs->adv_count >= hs->adv_cap) {
        int nc = hs->adv_cap ? hs->adv_cap * 2 : 8;
        char **nv = realloc(hs->advertised, (size_t)nc * sizeof(char *));
        if (!nv) return -1;
        hs->advertised = nv;
        hs->adv_cap = nc;
    }
    hs->advertised[hs->adv_count] = strdup(name);
    if (!hs->advertised[hs->adv_count]) return -1;
    hs->adv_count++;
    return 0;
}

/* Cleanly close a transient handshake fd: remove from event loop (which
 * frees the rx_state_t via rx_free, which in turn SSL_frees and closes
 * the hs_context), then close the fd. */
static void hs_abort(int fd, const char *reason)
{
    /* Commit 6: for outbound handshakes, capture the peer pointer BEFORE
     * node_fd_del_with_rx frees the fd_state_t, so we can update its
     * retry backoff state after cleanup. */
    node_peer_t *outbound_peer = NULL;
    if (g_rx_ht_inited) {
        char key[16]; rx_key(fd, key, sizeof(key));
        rx_state_t *rx = portal_ht_get(&g_rx_by_fd, key);
        if (rx && rx->hs && rx->hs->is_outbound && rx->hs->peer &&
            rx->hs->peer->ready == 0) {
            outbound_peer = rx->hs->peer;
        }
    }

    if (g_core)
        g_core->log(g_core, PORTAL_LOG_WARN, "node",
                    "Handshake fd=%d aborted: %s", fd, reason);
    node_fd_del_with_rx(fd);
    close(fd);

    if (outbound_peer) {
        /* Only mark dead + back off if no other fd on this peer has
         * succeeded yet. If ctrl_fd was already set, another parallel
         * connect already made the peer ready; this is just one worker
         * that failed. */
        if (outbound_peer->ctrl_fd < 0) {
            outbound_peer->dead = 1;
            outbound_peer->retry_count++;
            uint64_t backoff[] = {1, 2, 5, 10, 30};
            int bi = outbound_peer->retry_count - 1;
            if (bi >= (int)(sizeof(backoff)/sizeof(backoff[0])))
                bi = (int)(sizeof(backoff)/sizeof(backoff[0])) - 1;
            outbound_peer->next_retry_us = now_us() + backoff[bi] * 1000000ULL;
        }
    }
}

/* Forward declaration — drive_hs_send_build is called by drive_tls at TLS
 * completion and defined further below. */
static void drive_hs_send_build(rx_state_t *rx);
static void finalize_handshake(rx_state_t *rx);

/* Run one step of the SSL handshake. Works for both accept and connect
 * sides — SSL_do_handshake retries whatever side was configured at
 * SSL_new + SSL_set_accept_state/SSL_set_connect_state time. Returns
 * 1 if handshake done, 0 if more I/O needed, -1 on hard error. */
#ifdef HAS_SSL
static int drive_tls(rx_state_t *rx)
{
    SSL *ssl = rx->ssl;
    if (!ssl) return -1;

    int rc = SSL_do_handshake(ssl);
    if (rc == 1) {
        /* TLS handshake complete. Move to HS_EXCHANGE and queue our
         * PORTAL02 handshake bytes into tx_buf. */
        conn_set_state(rx, CONN_STATE_HS_EXCHANGE);
        drive_hs_send_build(rx);
        return 1;
    }

    int err = SSL_get_error(ssl, rc);
    if (err == SSL_ERROR_WANT_READ) {
        /* Default fd_state_t events has EV_READ. Nothing to toggle. */
        return 0;
    }
    if (err == SSL_ERROR_WANT_WRITE) {
        fd_state_ensure_writable(rx);
        return 0;
    }
    /* Hard error */
    return -1;
}
#endif

/* Check if a peer name is in the comma-separated advertise_to whitelist */
static int peer_in_whitelist(const char *name)
{
    if (!name || !name[0] || !g_advertise_to[0]) return 0;
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", g_advertise_to);
    char *tok = strtok(buf, ",");
    while (tok) {
        while (*tok == ' ') tok++;
        char *end = tok + strlen(tok) - 1;
        while (end > tok && *end == ' ') *end-- = '\0';
        if (strcasecmp(tok, name) == 0) return 1;
        tok = strtok(NULL, ",");
    }
    return 0;
}

/* Build our PORTAL02 handshake bytes and queue them in tx_buf for draining.
 * Called once at TLS completion. Mirrors the bytes-on-wire format of the
 * old synchronous send_handshake(). */
static void drive_hs_send_build(rx_state_t *rx)
{
    if (!rx->hs || rx->hs->send_queued) return;

    uint8_t buf[4096];
    uint8_t *p = buf;

    memcpy(p, NODE_HANDSHAKE_MAGIC, 8); p += 8;

    if (g_has_key)
        memcpy(p, g_key_hash, NODE_KEY_HASH_LEN);
    else
        memset(p, 0, NODE_KEY_HASH_LEN);
    p += NODE_KEY_HASH_LEN;

    uint16_t nlen = (uint16_t)strlen(g_node_name);
    p[0] = (uint8_t)(nlen >> 8); p[1] = (uint8_t)(nlen & 0xff); p += 2;
    memcpy(p, g_node_name, nlen); p += nlen;

    /* Peer advertisement — controlled by advertise_peers config.
     * ADV_NONE (default): don't advertise any peers. Privacy-safe.
     * ADV_ALL: advertise all direct peers (legacy behavior).
     * ADV_WHITELIST: advertise all — but the RECEIVING side filters
     *   in register_indirect_peer() based on advertise_to whitelist.
     *   (We can't filter here because remote name isn't known yet.) */
    int peer_adv_count = 0;
    uint8_t *count_pos = p;
    p += 2;
    if (g_advertise_mode != ADV_NONE) {
        for (int i = 0; i < g_peer_count; i++) {
            if (!g_peers[i]->ready || g_peers[i]->is_indirect) continue;
            uint16_t pnlen = (uint16_t)strlen(g_peers[i]->name);
            if (p + 2 + pnlen > buf + sizeof(buf) - 2) break;
            p[0] = (uint8_t)(pnlen >> 8); p[1] = (uint8_t)(pnlen & 0xff); p += 2;
            memcpy(p, g_peers[i]->name, pnlen); p += pnlen;
            peer_adv_count++;
        }
    }
    count_pos[0] = (uint8_t)(peer_adv_count >> 8);
    count_pos[1] = (uint8_t)(peer_adv_count & 0xff);

    size_t total = (size_t)(p - buf);
    if (fd_state_tx_append(rx, buf, total) == 0) {
        fd_state_ensure_writable(rx);
        rx->hs->send_queued = 1;
    }
}

/* Incrementally parse incoming PORTAL02 handshake bytes from rx->buf.
 * The rx buffer is used as a sliding window: bytes accumulate as libev
 * delivers them, and each call consumes whatever whole fields have
 * arrived. Returns: 1 if handshake fully parsed, 0 if more bytes needed,
 * -1 on protocol error, -2 on auth failure (bad federation key). */
static int drive_hs_recv(rx_state_t *rx)
{
    if (!rx->hs) return -1;
    hs_context_t *hs = rx->hs;

    /* Phase 0: fixed header (8 magic + 32 key_hash + 2 name_len = 42 bytes) */
    if (hs->recv_phase == 0) {
        if (rx->len < 42) return 0;
        if (memcmp(rx->buf, NODE_HANDSHAKE_MAGIC, 8) != 0) return -1;
        if (g_has_key) {
            if (memcmp(rx->buf + 8, g_key_hash, NODE_KEY_HASH_LEN) != 0)
                return -2;
        }
        hs->name_len = ((uint16_t)rx->buf[40] << 8) | rx->buf[41];
        if (hs->name_len >= PORTAL_MAX_MODULE_NAME) return -1;
        hs->recv_phase = 1;
    }

    /* Phase 1: node name (hs->name_len bytes) */
    if (hs->recv_phase == 1) {
        size_t needed = (size_t)(42 + hs->name_len);
        if (rx->len < needed) return 0;
        memcpy(hs->peer_name, rx->buf + 42, hs->name_len);
        hs->peer_name[hs->name_len] = '\0';
        hs->recv_phase = 2;
    }

    /* Phase 2: 2 bytes advertised peer count */
    if (hs->recv_phase == 2) {
        size_t needed = (size_t)(42 + hs->name_len + 2);
        if (rx->len < needed) return 0;
        size_t off = (size_t)(42 + hs->name_len);
        hs->peer_count = ((uint16_t)rx->buf[off] << 8) | rx->buf[off + 1];
        hs->recv_phase = 3;
    }

    /* Phases 3 + 4 loop: for each advertised peer, read 2 bytes len + N bytes name */
    size_t off = (size_t)(42 + hs->name_len + 2);
    for (int k = 0; k < (int)hs->peer_count; k++) {
        /* Skip already-consumed entries by walking forward */
        if (k < hs->adv_count) {
            /* Advance offset past this entry: we need 2 + name_len of it */
            uint16_t skip_len;
            if (rx->len < off + 2) return 0;
            skip_len = ((uint16_t)rx->buf[off] << 8) | rx->buf[off + 1];
            off += 2;
            if (rx->len < off + skip_len) return 0;
            off += skip_len;
            continue;
        }
        /* Phase 3: read 2-byte length */
        if (rx->len < off + 2) return 0;
        hs->next_pn_len = ((uint16_t)rx->buf[off] << 8) | rx->buf[off + 1];
        off += 2;
        /* Phase 4: read name bytes */
        if (rx->len < off + hs->next_pn_len) return 0;
        if (hs->next_pn_len < PORTAL_MAX_MODULE_NAME) {
            char tmp[PORTAL_MAX_MODULE_NAME];
            memcpy(tmp, rx->buf + off, hs->next_pn_len);
            tmp[hs->next_pn_len] = '\0';
            hs_adv_add(hs, tmp);
        }
        /* else: oversized name, silently skip */
        off += hs->next_pn_len;
    }

    /* All peers consumed — handshake parse is complete. */
    hs->recv_phase = 5;
    return 1;
}

/* Called when both send + recv halves of the PORTAL02 handshake are done.
 * Two paths:
 *   - Inbound (hs->is_outbound == 0): look up or create the node_peer_t
 *     by the peer_name received from the wire.
 *   - Outbound (hs->is_outbound == 1): the node_peer_t is already known
 *     (hs->peer was set by connect_to_peer_async). Verify the received
 *     peer_name matches what we expected, then attach the fd. */
static void finalize_handshake(rx_state_t *rx)
{
    if (!rx->hs) return;
    hs_context_t *hs = rx->hs;
    int client_fd = rx->fd;

#ifdef HAS_SSL
    SSL *ssl = rx->ssl;
#else
    void *ssl = NULL;
#endif
    const char *tls_tag = ssl ? " [TLS]" : "";

    /* ── Outbound path (Commit 6) ─────────────────────────────────── */
    if (hs->is_outbound && hs->peer) {
        node_peer_t *peer = hs->peer;

        /* Attach fd to a worker slot. For OUTBOUND peers, ctrl_fd stays
         * -1 — all live fds live in workers[] only. This avoids a
         * double-free bug where portal_module_unload + reconnect_dead_peers
         * would call node_fd_del_with_rx twice on the same fd (once via
         * ctrl_fd, once via workers[0]), hitting a freed rx_state_t on
         * the second call. Display code at /node/resources/... already
         * falls back to workers[0].ssl when ctrl_ssl is NULL, and
         * find_peer_by_fd/ssl_for_fd/mark_peer_dead_by_fd already scan
         * both arrays. Inbound peers still use ctrl_fd (worker_count=0). */
        pthread_mutex_lock(&peer->lock);
        if (peer->worker_count < NODE_MAX_THREADS) {
            int slot = peer->worker_count++;
            peer->workers[slot].fd = client_fd;
            peer->workers[slot].busy = 0;
#ifdef HAS_SSL
            peer->workers[slot].ssl = ssl;
#endif
        }
        pthread_mutex_unlock(&peer->lock);

        /* First completion → register path + mark ready */
        if (!peer->ready) {
            char path[PORTAL_MAX_PATH_LEN];
            snprintf(path, sizeof(path), "/%s/*", peer->name);
            if (g_core->path_register(g_core, path, "node") == 0) {
                g_core->path_set_access(g_core, path, PORTAL_ACCESS_RW);
                snprintf(peer->paths[0], NODE_PEER_PATH_LEN, "%.*s",
                         (int)(NODE_PEER_PATH_LEN - 1), path);
                peer->path_count = 1;
            }
            peer->ready = 1;
            peer->dead = 0;
            peer->connected_at = time(NULL);
            /* Reset exponential backoff on successful connection */
            peer->retry_count = 0;
            peer->next_retry_us = 0;

            g_core->log(g_core, PORTAL_LOG_INFO, "node",
                        "Connected to peer '%s' at %s:%d (async, %d workers)%s",
                        peer->name, peer->host, peer->port,
                        g_threads_per_peer, tls_tag);

            /* Register indirect peers advertised during handshake */
            int hub_idx = -1;
            for (int i = 0; i < g_peer_count; i++) {
                if (g_peers[i] == peer) { hub_idx = i; break; }
            }
            if (hub_idx >= 0) {
                for (int rp = 0; rp < hs->adv_count; rp++)
                    register_indirect_peer(hs->advertised[rp], hub_idx);
            }
        } else {
            g_core->log(g_core, PORTAL_LOG_DEBUG, "node",
                        "Outbound worker connection to '%s' (%d/%d)%s",
                        peer->name, peer->worker_count,
                        g_threads_per_peer, tls_tag);
        }

        hs_context_free(rx->hs);
        rx->hs = NULL;
        conn_set_state(rx, CONN_STATE_READY);
        return;
    }

    /* ── Inbound path (Commit 5, updated: clean stale workers) ───── */

    /* Check if this fd is a worker connection from an already-known peer */
    node_peer_t *existing = find_peer_by_name(hs->peer_name);
    if (existing) {
        /* Kill stale workers before adding new one. A reconnecting
         * device may leave zombie fds that never got cleaned up. */
        pthread_mutex_lock(&existing->lock);
        for (int j = 0; j < existing->worker_count; j++) {
            int wfd = existing->workers[j].fd;
            if (wfd < 0) continue;
            char wkey[16];
            snprintf(wkey, sizeof(wkey), "%d", wfd);
            rx_state_t *wrx = portal_ht_get(&g_rx_by_fd, wkey);
            int stale = (!wrx || wrx->conn_state != CONN_STATE_READY);
            if (stale) {
                if (wrx) {
                    node_fd_del_with_rx(wfd);
                } else {
                    g_core->fd_del(g_core, wfd);
                }
                close(wfd);
                existing->workers[j].fd = -1;
#ifdef HAS_SSL
                existing->workers[j].ssl = NULL;
#endif
                g_core->log(g_core, PORTAL_LOG_INFO, "node",
                            "Cleaned stale worker fd=%d from '%s'",
                            wfd, existing->name);
            }
        }
        /* Compact: shift valid workers down */
        int w_out = 0;
        for (int j = 0; j < existing->worker_count; j++) {
            if (existing->workers[j].fd >= 0) {
                if (w_out != j)
                    existing->workers[w_out] = existing->workers[j];
                w_out++;
            }
        }
        existing->worker_count = w_out;

        /* Add new worker */
        if (existing->worker_count < NODE_MAX_THREADS) {
            worker_t *w = &existing->workers[existing->worker_count++];
            w->fd = client_fd;
            w->busy = 0;
#ifdef HAS_SSL
            w->ssl = ssl;
#endif
        }
        pthread_mutex_unlock(&existing->lock);
        /* Transition fd to READY; keep the rx_state_t registered. The
         * old blocking flow called node_fd_add_with_rx here; we already
         * have the fd in the event loop via node_fd_add_inbound_handshake,
         * so just free the handshake scratch and flip the state. */
        hs_context_free(rx->hs);
        rx->hs = NULL;
        conn_set_state(rx, CONN_STATE_READY);
        g_core->log(g_core, PORTAL_LOG_DEBUG, "node",
                    "Worker connection from '%s' (%d/%d)%s",
                    hs->peer_name, existing->worker_count,
                    NODE_MAX_THREADS, tls_tag);
        return;
    }

    /* New peer — allocate a node_peer_t and register path */
    int new_idx = peers_append();
    if (new_idx < 0) {
        hs_abort(client_fd, "peers_append failed (cap reached)");
        return;
    }

    node_peer_t *peer = g_peers[new_idx];
    pthread_mutex_init(&peer->lock, NULL);
    snprintf(peer->name, sizeof(peer->name), "%s", hs->peer_name);
    snprintf(peer->host, sizeof(peer->host), "%s",
             inet_ntoa(hs->peer_addr.sin_addr));
    peer->port = ntohs(hs->peer_addr.sin_port);
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

    g_core->log(g_core, PORTAL_LOG_INFO, "node",
                "Peer '%s' connected (inbound from %s)%s",
                peer->name, peer->host, tls_tag);

    /* Register indirect peers advertised by this peer */
    int hub_idx = new_idx;
    for (int rp = 0; rp < hs->adv_count; rp++)
        register_indirect_peer(hs->advertised[rp], hub_idx);

    /* Free handshake scratch and flip to READY */
    hs_context_free(rx->hs);
    rx->hs = NULL;
    conn_set_state(rx, CONN_STATE_READY);
}

/* Register an inbound accepted fd in the event loop starting from
 * CONN_STATE_TLS_ACCEPT. Allocates the rx_state_t, hs_context_t, and
 * SSL object. On error, frees everything and closes the fd. */
static int node_fd_add_inbound_handshake(int client_fd,
                                          const struct sockaddr_in *peer_addr)
{
    if (!g_rx_ht_inited) {
        portal_ht_init(&g_rx_by_fd, 256);
        g_rx_ht_inited = 1;
    }

    set_nonblocking(client_fd);

    rx_state_t *rx = rx_alloc(client_fd);
    if (!rx) return -1;

    rx->hs = calloc(1, sizeof(hs_context_t));
    if (!rx->hs) { free(rx); return -1; }
    rx->hs->peer_addr = *peer_addr;
    rx->hs->recv_phase = 0;

#ifdef HAS_SSL
    SSL *ssl = NULL;
    if (g_tls_enabled && g_ssl_server_ctx) {
        ssl = SSL_new(g_ssl_server_ctx);
        if (!ssl) { hs_context_free(rx->hs); free(rx); return -1; }
        SSL_set_fd(ssl, client_fd);
        SSL_set_accept_state(ssl);
        rx->ssl = ssl;
        conn_set_state(rx, CONN_STATE_TLS_ACCEPT);
    } else {
        /* No TLS — skip straight to HS_EXCHANGE */
        conn_set_state(rx, CONN_STATE_HS_EXCHANGE);
    }
#else
    conn_set_state(rx, CONN_STATE_HS_EXCHANGE);
#endif

    /* Register in the hashtable and event loop with EV_READ|EV_WRITE so
     * the first wakeup immediately drives the handshake forward. */
    char key[16];
    rx_key(client_fd, key, sizeof(key));
    portal_ht_set(&g_rx_by_fd, key, rx);

    rx->events = EV_READ | EV_WRITE;
    if (g_core->fd_add(g_core, client_fd, EV_READ | EV_WRITE,
                       on_inbound_data, rx) < 0) {
        portal_ht_del(&g_rx_by_fd, key);
        rx_free(rx);
        return -1;
    }

    /* If no TLS and we're already in HS_EXCHANGE state, queue the
     * PORTAL02 send bytes immediately so they go out on the first
     * on_writable callback. */
    if (rx->conn_state == CONN_STATE_HS_EXCHANGE)
        drive_hs_send_build(rx);

    return 0;
}

/* Commit 6: start an async outbound connect on a fresh non-blocking
 * socket. Allocates the fd_state_t + hs_context_t with peer backref set,
 * registers the fd in CONN_STATE_TCP_CONNECTING with EV_WRITE so libev
 * wakes us when connect() completes. Returns 0 on success, -1 on error
 * (peer's retry_count is NOT incremented here — the caller is expected
 * to handle backoff accounting).
 *
 * On immediate failure (socket, connect fails synchronously) the fd is
 * closed cleanly before returning -1. No dangling state. */
static int node_fd_add_outbound_handshake(node_peer_t *peer)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* TCP keepalive */
    int ka = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof(ka));
#ifdef TCP_KEEPIDLE
    int kidle = 60;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &kidle, sizeof(kidle));
#endif
#ifdef TCP_KEEPINTVL
    int kintvl = 30;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &kintvl, sizeof(kintvl));
#endif
#ifdef TCP_KEEPCNT
    int kcnt = 3;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &kcnt, sizeof(kcnt));
#endif

    if (set_nonblocking(fd) < 0) { close(fd); return -1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)peer->cfg_port);
    if (inet_pton(AF_INET, peer->cfg_host, &addr.sin_addr) <= 0) {
        close(fd);
        return -1;
    }

    int crc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (crc < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    /* Allocate fd_state_t and hs_context_t */
    if (!g_rx_ht_inited) {
        portal_ht_init(&g_rx_by_fd, 256);
        g_rx_ht_inited = 1;
    }
    rx_state_t *rx = rx_alloc(fd);
    if (!rx) { close(fd); return -1; }

    rx->hs = calloc(1, sizeof(hs_context_t));
    if (!rx->hs) { free(rx); close(fd); return -1; }
    rx->hs->peer_addr = addr;
    rx->hs->peer = peer;
    rx->hs->is_outbound = 1;
    rx->hs->recv_phase = 0;

    conn_set_state(rx, CONN_STATE_TCP_CONNECTING);

    char key[16];
    rx_key(fd, key, sizeof(key));
    portal_ht_set(&g_rx_by_fd, key, rx);

    rx->events = EV_READ | EV_WRITE;
    if (g_core->fd_add(g_core, fd, EV_READ | EV_WRITE,
                       on_inbound_data, rx) < 0) {
        portal_ht_del(&g_rx_by_fd, key);
        rx_free(rx);
        return -1;
    }

    return 0;
}

/* Commit 6: replaces the old blocking connect_to_peer. Creates a
 * node_peer_t and kicks off N parallel async connects (1 control +
 * g_threads_per_peer workers). Returns 0 on success, -1 if peers_append
 * fails or all socket creations fail.
 *
 * The peer starts in ready=0 state. finalize_handshake transitions it
 * to ready=1 after the first connection completes the full TLS +
 * PORTAL02 handshake. */
static int connect_to_peer_async(const char *name, const char *host, int port)
{
    /* If peer already exists (reconnect case), reuse it */
    node_peer_t *peer = NULL;
    for (int i = 0; i < g_peer_count; i++) {
        if (strcmp(g_peers[i]->name, name) == 0) {
            peer = g_peers[i];
            break;
        }
    }

    if (!peer) {
        int idx = peers_append();
        if (idx < 0) return -1;
        peer = g_peers[idx];
        pthread_mutex_init(&peer->lock, NULL);
        snprintf(peer->name, sizeof(peer->name), "%s", name);
        snprintf(peer->host, sizeof(peer->host), "%s", host);
        snprintf(peer->cfg_host, sizeof(peer->cfg_host), "%s", host);
        peer->port = port;
        peer->cfg_port = port;
        peer->is_inbound = 0;
        peer->is_indirect = 0;
        peer->ctrl_fd = -1;
        peer->worker_count = 0;
        peer->ready = 0;
        peer->dead = 0;
        peer->connected_at = 0;
        peer->retry_count = 0;
        peer->next_retry_us = 0;
    } else {
        /* Reconnect case — reset state so finalize_handshake will mark
         * it ready on first successful handshake */
        peer->ready = 0;
        peer->ctrl_fd = -1;
        peer->worker_count = 0;
    }

    /* Start N+1 parallel async connects: 1 for control + g_threads_per_peer
     * for workers. Each one independently drives the state machine. */
    int total = 1 + g_threads_per_peer;
    if (total > NODE_MAX_THREADS) total = NODE_MAX_THREADS;

    int started = 0;
    for (int i = 0; i < total; i++) {
        if (node_fd_add_outbound_handshake(peer) == 0)
            started++;
    }

    if (started == 0) {
        /* All socket creates failed — mark dead and back off */
        peer->dead = 1;
        peer->retry_count++;
        uint64_t backoff[] = {1, 2, 5, 10, 30};
        int bi = peer->retry_count - 1;
        if (bi >= (int)(sizeof(backoff)/sizeof(backoff[0])))
            bi = (int)(sizeof(backoff)/sizeof(backoff[0])) - 1;
        peer->next_retry_us = now_us() + backoff[bi] * 1000000ULL;
        return -1;
    }

    g_core->log(g_core, PORTAL_LOG_INFO, "node",
                "Async connect to '%s' at %s:%d started (%d/%d fds)",
                name, host, port, started, total);
    return 0;
}

/* Drive the handshake state machine. Called from on_inbound_data when
 * rx->conn_state is not READY. Handles both TLS and PORTAL02 phases.
 * Returns 0 on success (state progressed or waiting), -1 on hard error
 * (caller should abort the fd). */
static int drive_handshake(rx_state_t *rx, uint32_t events)
{
    /* Phase 0: TCP connect in progress (outbound). When libev fires
     * EV_WRITE, the socket is writable → connect() finished. Check
     * SO_ERROR to distinguish success from failure. */
    if (rx->conn_state == CONN_STATE_TCP_CONNECTING) {
        if (!(events & EV_WRITE))
            return 0;  /* wait for writable */
        int soerr = 0;
        socklen_t slen = sizeof(soerr);
        if (getsockopt(rx->fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) < 0)
            return -1;
        if (soerr != 0) {
            errno = soerr;
            return -1;
        }
        /* connect() succeeded. If TLS is enabled, create the SSL and
         * move to TLS_CONNECT; otherwise skip to HS_EXCHANGE. */
#ifdef HAS_SSL
        if (g_tls_enabled && g_ssl_client_ctx) {
            SSL *ssl = SSL_new(g_ssl_client_ctx);
            if (!ssl) return -1;
            SSL_set_fd(ssl, rx->fd);
            SSL_set_connect_state(ssl);
            rx->ssl = ssl;
            conn_set_state(rx, CONN_STATE_TLS_CONNECT);
        } else
#endif
        {
            conn_set_state(rx, CONN_STATE_HS_EXCHANGE);
            drive_hs_send_build(rx);
        }
        /* Drop EV_WRITE — the TLS/HS driver will re-enable if needed */
        fd_state_stop_writable(rx);
    }

    /* Phase A: TLS handshake. Handles both inbound (TLS_ACCEPT) and
     * outbound (TLS_CONNECT) — SSL_do_handshake is direction-agnostic. */
#ifdef HAS_SSL
    if (rx->conn_state == CONN_STATE_TLS_ACCEPT ||
        rx->conn_state == CONN_STATE_TLS_CONNECT) {
        int rc = drive_tls(rx);
        if (rc < 0) return -1;
        if (rc == 0) return 0;  /* want more I/O */
        /* rc == 1 → TLS done, fell through to HS_EXCHANGE */
    }
#else
    (void)events;
#endif

    /* Phase B: HS_EXCHANGE — send and recv concurrently */
    if (rx->conn_state == CONN_STATE_HS_EXCHANGE) {
        /* Send half: drain tx_buf when EV_WRITE fires. on_writable is
         * called from the main on_inbound_data entry block before us,
         * so by the time we're here tx_buf draining has already
         * progressed. Mark hs->send_done when fully drained. */
        if (rx->hs && rx->hs->send_queued && rx->tx_len == 0)
            rx->hs->send_done = 1;

        /* Recv half: drain bytes from the socket into rx->buf, then
         * parse what we have. We need to read bytes manually here
         * (the normal Phase 1-3 reader assumes a length-prefixed
         * framed message, which the handshake isn't). */
        (void)events;  /* we act based on rx state, not event mask */
        void *ssl = NULL;
#ifdef HAS_SSL
        ssl = rx->ssl;
#endif
        /* Make sure the rx buffer has room to grow */
        if (rx->cap < 4096) {
            uint8_t *nb = realloc(rx->buf, 4096);
            if (!nb) return -1;
            rx->buf = nb;
            rx->cap = 4096;
        }

        while (rx->len < rx->cap) {
            ssize_t n = node_read_nb(rx->fd, ssl, rx->buf + rx->len,
                                      rx->cap - rx->len);
            if (n > 0) {
                rx->len += (size_t)n;
                continue;
            }
            if (n == -2) break;  /* would block */
            /* EOF or hard error */
            return -1;
        }

        int prc = drive_hs_recv(rx);
        if (prc == -2) return -1;   /* auth failure */
        if (prc == -1) return -1;   /* protocol error */
        if (prc == 1 && rx->hs) rx->hs->recv_done = 1;

        if (rx->hs && rx->hs->send_done && rx->hs->recv_done) {
            /* Both halves complete — finalize */
            finalize_handshake(rx);
            /* After finalize, rx->conn_state == READY and rx->hs == NULL.
             * Reset rx_len so the incremental reader starts fresh for
             * the first real message. */
            rx->len = 0;
            rx->need = 0;
            return 0;
        }
    }

    return 0;
}

/* --- Inbound peer handling ---
 *
 * Incremental reader (Commit 3): on_inbound_data is invoked by libev when
 * the fd is readable. It accumulates bytes into a per-fd rx_state_t
 * across multiple invocations so a partial frame does not stall the
 * event loop. When a complete frame is in rx->buf, it's decoded and
 * dispatched, then rx_reset() prepares for the next frame.
 *
 * The fd MUST be non-blocking. node_read_nb() returns -2 if the read
 * would block; the callback returns and waits for the next libev event.
 */

static void on_inbound_data(int fd, uint32_t events, void *userdata)
{
    rx_state_t *rx = (rx_state_t *)userdata;
    if (events & EV_ERROR) {
        mark_peer_dead_by_fd(fd);
#ifdef HAS_SSL
        node_ssl_close(fd, rx ? rx->ssl : ssl_for_fd(fd));
        if (rx) rx->ssl = NULL;
#endif
        node_fd_del_with_rx(fd);
        close(fd);
        return;
    }

    if (!rx) {
        /* Defensive: fd was registered without rx_state (should not
         * happen after Commit 3). Close it to force a fresh registration. */
        node_fd_del_with_rx(fd);
        close(fd);
        return;
    }

    /* Commit 4c: handle EV_WRITE first — drain any queued response
     * bytes in rx->tx_buf. on_writable is a no-op if the buffer is
     * empty or already drained. */
    if (events & EV_WRITE)
        on_writable(rx);

    /* Commit 5: dispatch on connection state. Transient handshake
     * conns skip the normal incremental reader entirely. */
    if (rx->conn_state != CONN_STATE_READY) {
        int rc = drive_handshake(rx, events);
        if (rc < 0) {
            hs_abort(fd, "handshake driver returned error");
            return;
        }
        /* If handshake just finalized, rx->conn_state is now READY and
         * we fall through to the normal reader to start processing the
         * first post-handshake frame (rx->len was reset by finalize). */
        if (rx->conn_state != CONN_STATE_READY)
            return;
    }

    /* If libev only signaled EV_WRITE (no EV_READ), we're done. Common
     * when the only reason we were woken was because the socket became
     * writable after a partial drain. */
    if (!(events & EV_READ))
        return;

    void *ssl = NULL;
#ifdef HAS_SSL
    ssl = rx->ssl;
#endif

read_more:
    /* Phase 1: read the 4-byte length header if we don't have it yet */
    while (rx->len < 4) {
        if (!rx->buf) {
            rx->buf = malloc(4);
            if (!rx->buf) {
                mark_peer_dead_by_fd(fd);
                node_fd_del_with_rx(fd);
                close(fd);
                return;
            }
            rx->cap = 4;
        }
        ssize_t n = node_read_nb(fd, ssl, rx->buf + rx->len, 4 - rx->len);
        if (n > 0) {
            rx->len += (size_t)n;
        } else if (n == -2) {
            return;   /* would block — wait for next event */
        } else {
            /* EOF or hard error */
            mark_peer_dead_by_fd(fd);
#ifdef HAS_SSL
            node_ssl_close(fd, ssl);
#endif
            node_fd_del_with_rx(fd);
            close(fd);
            return;
        }
    }

    /* Phase 2: parse length header and ensure buffer capacity */
    if (rx->need == 0) {
        int32_t msg_len = portal_wire_read_length(rx->buf);
        if (msg_len <= 0 || msg_len > NODE_BUF_SIZE) {
            /* Invalid frame — treat as protocol error */
            mark_peer_dead_by_fd(fd);
#ifdef HAS_SSL
            node_ssl_close(fd, ssl);
#endif
            node_fd_del_with_rx(fd);
            close(fd);
            return;
        }
        rx->need = 4 + (size_t)msg_len;
        if (rx->need > rx->cap) {
            uint8_t *nb = realloc(rx->buf, rx->need);
            if (!nb) {
                mark_peer_dead_by_fd(fd);
                node_fd_del_with_rx(fd);
                close(fd);
                return;
            }
            rx->buf = nb;
            rx->cap = rx->need;
        }
    }

    /* Phase 3: read the body until we have rx->need bytes */
    while (rx->len < rx->need) {
        ssize_t n = node_read_nb(fd, ssl, rx->buf + rx->len, rx->need - rx->len);
        if (n > 0) {
            rx->len += (size_t)n;
        } else if (n == -2) {
            return;   /* would block — wait for next event */
        } else {
            mark_peer_dead_by_fd(fd);
#ifdef HAS_SSL
            node_ssl_close(fd, ssl);
#endif
            node_fd_del_with_rx(fd);
            close(fd);
            return;
        }
    }

    /* Phase 4: we have a complete frame at rx->buf, length rx->need.
     *
     * Commit 4d: distinguish response-vs-request by checking the pending
     * FIFO on this conn. If pending_head is non-null, we are expecting a
     * response to an outbound peer_send_wait call — decode as
     * portal_resp_t, match to the head of the queue, and wake the waiter.
     * Otherwise, decode as portal_msg_t and dispatch locally.
     *
     * TCP byte-order guarantee means responses on a given conn arrive in
     * the same order the requests were sent (FIFO). Single-threaded mod_node
     * dispatch ensures the peer never interleaves a new request with a
     * response on the same conn — known latent limitation: a handler that
     * recursively core->sends to the same peer could break FIFO order.
     * Not an active bug in SSIP's flow. */

    if (rx->pending_head) {
        /* Response match to the oldest pending request on this conn */
        pending_req_t *pr = rx->pending_head;
        portal_resp_t tmp = {0};
        int decoded = portal_wire_decode_resp(rx->buf, rx->need, &tmp);
        if (decoded == 0 && pr->resp) {
            /* Transfer ownership of decoded fields into the caller's resp.
             * Zero the tmp aliases so we don't double-free if the caller
             * later runs portal_resp_free on pr->resp. */
            pr->resp->status = tmp.status;
            pr->resp->header_count = tmp.header_count;
            pr->resp->headers = tmp.headers;   tmp.headers = NULL;
            pr->resp->body = tmp.body;         tmp.body = NULL;
            pr->resp->body_len = tmp.body_len;
            pr->rc = 0;
        } else {
            /* Decode failed — fail the waiter. tmp contents (if any) will
             * be freed below via the cleanup block. */
            if (pr->resp) pr->resp->status = PORTAL_INTERNAL_ERROR;
            pr->rc = -1;
            if (tmp.headers) {
                for (uint16_t i = 0; i < tmp.header_count; i++) {
                    free(tmp.headers[i].key);
                    free(tmp.headers[i].value);
                }
                free(tmp.headers);
            }
            free(tmp.body);
        }
        pr->done = 1;

        /* Pop pr from FIFO head */
        rx->pending_head = pr->next;
        if (rx->pending_tail == pr) rx->pending_tail = NULL;
        rx->pending_count--;
        /* pr itself is freed by the waiter in peer_send_wait */

        rx_reset(rx);
#ifdef HAS_SSL
        if (ssl && SSL_pending((SSL *)ssl) > 0) goto read_more;
#endif
        return;
    }

    /* No pending request on this conn → incoming frame is a REQUEST from
     * the peer. Dispatch exactly like the pre-refactor reader did. */
    uint8_t *buf = rx->buf;
    int32_t msg_len = (int32_t)(rx->need - 4);

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
            /* start_pipe took ownership of the fd and called fd_del,
             * which freed our rx_state_t. Do NOT touch rx after this. */
            return;
        }

        /* Check for SHELL request — switch fd to PTY relay mode */
        if (incoming.path && strcmp(incoming.path, "/tunnel/shell") == 0) {
            int rows = 24, cols = 80;
            for (uint16_t i = 0; i < incoming.header_count; i++) {
                if (strcmp(incoming.headers[i].key, "rows") == 0)
                    rows = atoi(incoming.headers[i].value);
                if (strcmp(incoming.headers[i].key, "cols") == 0)
                    cols = atoi(incoming.headers[i].value);
            }

            int shell_ok = 0;
            if (start_shell(fd, rows, cols) == 0) {
                shell_ok = 1;
                resp.status = PORTAL_OK;
                char ok_body[] = "SHELL";
                resp.body = ok_body;
                resp.body_len = 5;
            }

            if (!shell_ok)
                resp.status = PORTAL_UNAVAILABLE;

            /* Send response BEFORE switching to raw relay mode */
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
            /* start_shell took ownership of the fd and called fd_del,
             * which freed our rx_state_t. Do NOT touch rx after this. */
            return;
        }

        /* Track inbound message */
        node_peer_t *src_peer = find_peer_by_fd(fd);
        if (src_peer) {
            src_peer->msgs_recv++;
            if (incoming.body_len > 0)
                src_peer->bytes_recv += incoming.body_len;
        }

        /* Federation trust: the peer already authenticated via federation_key
         * during the TLS handshake. Attach local root credentials so the
         * core router grants full access to federated requests. Without this,
         * the remote user's token (from a different node's user DB) would
         * fail the local auth check → ACCESS DENIED. */
        if (g_federation_key[0]) {
            if (!incoming.ctx)
                incoming.ctx = calloc(1, sizeof(portal_ctx_t));
            if (incoming.ctx) {
                free(incoming.ctx->auth.user);
                free(incoming.ctx->auth.token);
                incoming.ctx->auth.user = strdup("root");
                incoming.ctx->auth.token = strdup("__federation__");
            }
        }

        /* Normal message routing */
        g_core->send(g_core, &incoming, &resp);

        /* Commit 4c: queue the encoded response in rx->tx_buf and
         * enable EV_WRITE on the fd. on_writable (called by the next
         * libev wakeup, which is usually immediate because the socket
         * is almost always writable) will drain it without blocking
         * the event loop. */
        uint8_t *resp_buf = NULL;
        size_t resp_len = 0;
        if (portal_wire_encode_resp(&resp, &resp_buf, &resp_len) == 0) {
            if (fd_state_tx_append(rx, resp_buf, resp_len) == 0) {
                fd_state_ensure_writable(rx);
                if (src_peer) {
                    src_peer->msgs_sent++;
                    src_peer->bytes_sent += resp_len;
                }
            } else {
                /* Allocation failure — drop the response. The peer will
                 * eventually time out waiting for it, which mirrors
                 * the pre-Commit-4c behavior on a failed node_send. */
                if (src_peer) src_peer->errors++;
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
    /* Reset rx_state for the next frame; keep rx->buf allocated for reuse */
    rx_reset(rx);

    /* If the TLS socket has more data buffered internally, libev will NOT
     * wake us again because the underlying fd is empty. Loop back and drain. */
#ifdef HAS_SSL
    if (ssl && SSL_pending((SSL *)ssl) > 0) goto read_more;
#endif
}

static void on_new_peer(int fd, uint32_t events, void *userdata)
{
    (void)events; (void)userdata;

    /* Commit 5: non-blocking accept loop. Drain the listener's backlog
     * by looping accept4(SOCK_NONBLOCK) until it returns EAGAIN. Each
     * accepted fd starts in CONN_STATE_TLS_ACCEPT; the handshake is
     * driven asynchronously by on_inbound_data + drive_handshake. */
    for (;;) {
        struct sockaddr_in addr;
        socklen_t alen = sizeof(addr);
        int client_fd = accept4(fd, (struct sockaddr *)&addr, &alen,
                                 SOCK_NONBLOCK);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                break;
            if (g_core)
                g_core->log(g_core, PORTAL_LOG_WARN, "node",
                            "accept4 failed: %s", strerror(errno));
            break;
        }

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

        /* Register the fd in TLS_ACCEPT state. The driver kicks off
         * SSL_do_handshake on the first readable/writable event. */
        if (node_fd_add_inbound_handshake(client_fd, &addr) < 0) {
            g_core->log(g_core, PORTAL_LOG_WARN, "node",
                        "Failed to register inbound handshake for %s",
                        inet_ntoa(addr.sin_addr));
            close(client_fd);
            continue;
        }
    }
}

/* Commit 7: connect_to_peer removed. connect_to_peer_async (Commit 6) is
 * the sole entry point for establishing outbound peer connections. It
 * kicks off N+1 parallel non-blocking connect() calls; each fd drives
 * the TCP→TLS→PORTAL02 handshake through the event loop and attaches
 * to the peer via finalize_handshake when done. */

/* --- Peer health: mark dead + reconnect --- */

static void mark_peer_dead_by_fd(int fd)
{
    for (int i = 0; i < g_peer_count; i++) {
        node_peer_t *p = g_peers[i];
        if (p->ctrl_fd == fd ||
            (p->worker_count > 0 && p->workers[0].fd == fd)) {
            if (!p->dead) {
                p->dead = 1;
                p->ready = 0;
                g_core->log(g_core, PORTAL_LOG_WARN, "node",
                            "Peer '%s' connection lost", p->name);
                /* Cascade: indirect peers through this hub are also dead */
                for (int k = 0; k < g_peer_count; k++) {
                    if (g_peers[k]->is_indirect && g_peers[k]->hub_idx == i) {
                        g_peers[k]->dead = 1;
                        g_peers[k]->ready = 0;
                        g_core->log(g_core, PORTAL_LOG_WARN, "node",
                                    "Indirect peer '%s' lost (hub '%s' down)",
                                    g_peers[k]->name, p->name);
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
                /* Compact: shift remaining workers down */
                for (int k = j; k < p->worker_count - 1; k++)
                    p->workers[k] = p->workers[k + 1];
                p->worker_count--;
                /* If no workers left and ctrl_fd dead, mark peer dead */
                if (p->worker_count == 0 && p->ctrl_fd < 0) {
                    p->dead = 1;
                    p->ready = 0;
                    g_core->log(g_core, PORTAL_LOG_WARN, "node",
                                "Peer '%s' all workers lost", p->name);
                }
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
        /* Peer not in list at all — try connecting (Commit 6: async) */
        connect_to_peer_async(pname, phost, pport);
    }
}

/* Timer callback for reconnect (called by event loop) */
static void reconnect_timer_cb(void *userdata)
{
    (void)userdata;
    reconnect_dead_peers();
    connect_configured_peers();
}

/* Remove the peer at index `i` from g_peers[]. Frees the peer struct and
 * shifts the pointer array down. Caller must have already closed fds and
 * unregistered paths. Also decrements hub_idx of any indirect peers whose
 * hub was at a higher index. */
static void peers_remove_at(int i)
{
    if (i < 0 || i >= g_peer_count) return;
    node_peer_t *p = g_peers[i];

    pthread_mutex_destroy(&p->lock);
    free(p);

    /* Shift the pointer array (O(n), acceptable for infrequent removals) */
    if (i < g_peer_count - 1) {
        memmove(&g_peers[i], &g_peers[i + 1],
                (size_t)(g_peer_count - i - 1) * sizeof(node_peer_t *));
    }
    g_peers[g_peer_count - 1] = NULL;
    g_peer_count--;

    /* Fix up hub_idx of any indirect peer whose hub index is now stale */
    for (int k = 0; k < g_peer_count; k++) {
        if (g_peers[k]->is_indirect && g_peers[k]->hub_idx > i)
            g_peers[k]->hub_idx--;
    }
}

static void reconnect_dead_peers(void)
{
    /* Sweep stale inbound peers: not ready for > 60s, or dead */
    for (int i = g_peer_count - 1; i >= 0; i--) {
        node_peer_t *p = g_peers[i];
        if (!p->is_inbound) continue;
        int stale = (p->dead) ||
                    (!p->ready && p->connected_at > 0 &&
                     (time(NULL) - p->connected_at) > 60);
        if (!stale) continue;

        g_core->log(g_core, PORTAL_LOG_INFO, "node",
                    "Removing stale inbound peer '%s'", p->name);
        for (int j = 0; j < p->worker_count; j++) {
            if (p->workers[j].fd >= 0) {
                node_fd_del_with_rx(p->workers[j].fd);
                close(p->workers[j].fd);
            }
        }
        if (p->ctrl_fd >= 0) {
            node_fd_del_with_rx(p->ctrl_fd);
            close(p->ctrl_fd);
        }
        for (int j = 0; j < p->path_count; j++)
            g_core->path_unregister(g_core, p->paths[j]);
        peers_remove_at(i);
    }

    /* Reconnect outbound peers */
    for (int i = 0; i < g_peer_count; i++) {
        node_peer_t *p = g_peers[i];
        if (p->is_inbound || p->is_indirect || p->cfg_host[0] == '\0') continue;

        /* Check if peer needs reconnect:
         * - explicitly dead
         * - stuck connecting (not ready for > 30s)
         * - no working workers */
        if (p->ready && !p->dead) continue;
        if (!p->dead && !p->ready && p->connected_at > 0 &&
            (time(NULL) - p->connected_at) < 30) continue;  /* give it time */

        /* Commit 6: respect exponential backoff — skip this peer until
         * next_retry_us has passed. */
        if (p->next_retry_us > 0 && now_us() < p->next_retry_us)
            continue;

        g_core->log(g_core, PORTAL_LOG_INFO, "node",
                    "Reconnecting '%s' — removing dead peer...", p->name);

        /* Close all fds (no SSL_free — just close raw fds).
         * node_fd_del_with_rx frees the rx_state_t registered on each fd.
         * Workers first, then ctrl_fd, skipping duplicates. */
        for (int j = 0; j < p->worker_count; j++) {
            int wfd = p->workers[j].fd;
            if (wfd >= 0) {
                node_fd_del_with_rx(wfd);
                close(wfd);
                p->workers[j].fd = -1;
                if (p->ctrl_fd == wfd) {
                    p->ctrl_fd = -1;
#ifdef HAS_SSL
                    p->ctrl_ssl = NULL;
#endif
                }
            }
        }
        if (p->ctrl_fd >= 0) {
            node_fd_del_with_rx(p->ctrl_fd);
            close(p->ctrl_fd);
            p->ctrl_fd = -1;
        }
        /* Unregister paths */
        for (int j = 0; j < p->path_count; j++)
            g_core->path_unregister(g_core, p->paths[j]);

        /* Remove indirect peers that used this hub (walk backwards;
         * peers_remove_at fixes hub_idx shifts for us) */
        for (int k = g_peer_count - 1; k >= 0; k--) {
            if (k >= g_peer_count) continue;   /* count changed under us */
            if (g_peers[k]->is_indirect && g_peers[k]->hub_idx == i) {
                g_core->log(g_core, PORTAL_LOG_INFO, "node",
                            "Removing indirect peer '%s'", g_peers[k]->name);
                for (int jp = 0; jp < g_peers[k]->path_count; jp++)
                    g_core->path_unregister(g_core, g_peers[k]->paths[jp]);
                peers_remove_at(k);
                if (k < i) i--;  /* the hub index shifted down */
            }
        }

        /* Save config for fresh connect */
        char save_host[256], save_name[PORTAL_MAX_MODULE_NAME];
        int save_port = p->cfg_port;
        snprintf(save_host, sizeof(save_host), "%s", p->cfg_host);
        snprintf(save_name, sizeof(save_name), "%s", p->name);

        /* Remove peer entry */
        peers_remove_at(i);
        i--;  /* re-check this index */

        /* Commit 6: fresh async connect. Respects exponential backoff via
         * peer->retry_count + next_retry_us, which connect_to_peer_async
         * resets on success. */
        (void)save_host; (void)save_port;  /* peer already has cfg_host/cfg_port */
        connect_to_peer_async(save_name, save_host, save_port);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Commit 5: handshake timeout sweep
 *
 *  Walks g_rx_by_fd once per second. Any fd_state_t whose conn_state is
 *  not READY and whose state_enter_us is older than the per-state timeout
 *  is killed cleanly. This protects against peers that accept TCP but
 *  stall mid-TLS or mid-PORTAL02.
 * ═══════════════════════════════════════════════════════════════════════════ */

#define HS_TIMEOUT_TCP_US    (5ULL * 1000000ULL)   /* 5 s for non-blocking connect() */
#define HS_TIMEOUT_TLS_US    (10ULL * 1000000ULL)  /* 10 s for SSL_do_handshake */
#define HS_TIMEOUT_EXCHANGE_US (5ULL * 1000000ULL) /* 5 s for PORTAL02 exchange */

typedef struct {
    int *fds_to_kill;
    int  count;
    int  cap;
    uint64_t now;
} hs_sweep_ctx_t;

static void hs_sweep_cb(const char *key, void *value, void *userdata)
{
    (void)key;
    rx_state_t *rx = (rx_state_t *)value;
    hs_sweep_ctx_t *ctx = (hs_sweep_ctx_t *)userdata;
    if (rx->conn_state == CONN_STATE_READY) return;
    if (rx->conn_state == CONN_STATE_DEAD) return;

    uint64_t age = ctx->now - rx->state_enter_us;
    uint64_t limit = HS_TIMEOUT_EXCHANGE_US;
    if (rx->conn_state == CONN_STATE_TCP_CONNECTING)
        limit = HS_TIMEOUT_TCP_US;
    else if (rx->conn_state == CONN_STATE_TLS_ACCEPT ||
             rx->conn_state == CONN_STATE_TLS_CONNECT)
        limit = HS_TIMEOUT_TLS_US;

    if (age < limit) return;

    /* Capture the fd — we can't modify the hashtable during iteration */
    if (ctx->count >= ctx->cap) {
        int nc = ctx->cap ? ctx->cap * 2 : 16;
        int *nf = realloc(ctx->fds_to_kill, (size_t)nc * sizeof(int));
        if (!nf) return;
        ctx->fds_to_kill = nf;
        ctx->cap = nc;
    }
    ctx->fds_to_kill[ctx->count++] = rx->fd;
}

static void hs_sweep_timer_cb(void *userdata)
{
    (void)userdata;
    if (!g_rx_ht_inited) return;

    hs_sweep_ctx_t ctx = {0};
    ctx.now = now_us();
    portal_ht_iter(&g_rx_by_fd, hs_sweep_cb, &ctx);

    for (int i = 0; i < ctx.count; i++) {
        hs_abort(ctx.fds_to_kill[i], "handshake timeout");
    }
    free(ctx.fds_to_kill);
}

/* ================================================================
 * CLI command handlers (registered via portal_cli_register)
 * ================================================================ */

static void cli_send(int fd, const char *s)
{
    if (s) write(fd, s, strlen(s));
}

static void cli_get_path(int fd, const char *path)
{
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (!m || !r) return;
    portal_msg_set_path(m, path);
    portal_msg_set_method(m, PORTAL_METHOD_GET);
    g_core->send(g_core, m, r);
    if (r->body) write(fd, r->body, r->body_len);
    portal_msg_free(m); portal_resp_free(r);
}

static int cli_ping(portal_core_t *core, int fd,
                     const char *line, const char *args)
{
    (void)line;
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (m && r) {
        portal_msg_set_path(m, "/node/functions/ping");
        portal_msg_set_method(m, PORTAL_METHOD_CALL);
        portal_msg_add_header(m, "name", (args && *args) ? args : "all");
        core->send(core, m, r);
        if (r->body)
            write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
        else
            cli_send(fd, (args && *args) ? "(ping failed)\n" : "(no peers)\n");
        portal_msg_free(m); portal_resp_free(r);
    }
    return 0;
}

static int cli_tracert(portal_core_t *core, int fd,
                        const char *line, const char *args)
{
    (void)line;
    if (!args || !*args) { cli_send(fd, "Usage: tracert <path>\n"); return -1; }
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (m && r) {
        portal_msg_set_path(m, "/node/functions/trace");
        portal_msg_set_method(m, PORTAL_METHOD_CALL);
        portal_msg_add_header(m, "path", args);
        core->send(core, m, r);
        if (r->body)
            write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
        else
            cli_send(fd, "(trace failed)\n");
        portal_msg_free(m); portal_resp_free(r);
    }
    return 0;
}

static int cli_node_status(portal_core_t *core, int fd,
                            const char *line, const char *args)
{
    (void)line;
    if (args && *args) {
        /* node status <peer> — show local peer info + remote location */
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            char path[PORTAL_MAX_PATH_LEN];
            snprintf(path, sizeof(path), "/node/resources/peer/%s", args);
            portal_msg_set_path(m, path);
            portal_msg_set_method(m, PORTAL_METHOD_GET);
            core->send(core, m, r);
            if (r->body)
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
            else
                cli_send(fd, "(peer not found)\n");
            portal_msg_free(m); portal_resp_free(r);
        }
        /* Also query remote node status for location/GPS */
        m = portal_msg_alloc();
        r = portal_resp_alloc();
        if (m && r) {
            char path[PORTAL_MAX_PATH_LEN];
            snprintf(path, sizeof(path), "/%s/node/resources/status", args);
            portal_msg_set_path(m, path);
            portal_msg_set_method(m, PORTAL_METHOD_GET);
            core->send(core, m, r);
            if (r->body && r->body_len > 0) {
                const char *body = r->body;
                const char *loc = strstr(body, "Location:");
                const char *gps = strstr(body, "GPS:");
                if (loc) {
                    const char *end = strchr(loc, '\n');
                    if (end) write(fd, loc, (size_t)(end - loc + 1));
                }
                if (gps) {
                    const char *end = strchr(gps, '\n');
                    if (end) write(fd, gps, (size_t)(end - gps + 1));
                }
            }
            portal_msg_free(m); portal_resp_free(r);
        }
    } else {
        cli_get_path(fd, "/node/resources/status");
    }
    return 0;
}

static int cli_node_peers(portal_core_t *core, int fd,
                           const char *line, const char *args)
{
    (void)core; (void)line; (void)args;
    cli_get_path(fd, "/node/resources/peers");
    return 0;
}

static int cli_node_ping(portal_core_t *core, int fd,
                          const char *line, const char *args)
{
    (void)line;
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (m && r) {
        portal_msg_set_path(m, "/node/functions/ping");
        portal_msg_set_method(m, PORTAL_METHOD_CALL);
        portal_msg_add_header(m, "name", (args && *args) ? args : "all");
        core->send(core, m, r);
        if (r->body)
            write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
        else
            cli_send(fd, (args && *args) ? "(ping failed)\n" : "(no peers)\n");
        portal_msg_free(m); portal_resp_free(r);
    }
    return 0;
}

static int cli_node_trace(portal_core_t *core, int fd,
                           const char *line, const char *args)
{
    (void)line;
    if (!args || !*args) { cli_send(fd, "Usage: node trace <path>\n"); return -1; }
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (m && r) {
        portal_msg_set_path(m, "/node/functions/trace");
        portal_msg_set_method(m, PORTAL_METHOD_CALL);
        portal_msg_add_header(m, "path", args);
        core->send(core, m, r);
        if (r->body)
            write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
        else
            cli_send(fd, "(trace failed)\n");
        portal_msg_free(m); portal_resp_free(r);
    }
    return 0;
}

static int cli_node_location(portal_core_t *core, int fd,
                              const char *line, const char *args)
{
    (void)line;
    if (!args || !*args) { cli_send(fd, "Usage: node location <name>\n"); return -1; }
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (m && r) {
        portal_msg_set_path(m, "/node/functions/location");
        portal_msg_set_method(m, PORTAL_METHOD_CALL);
        portal_msg_add_header(m, "name", args);
        core->send(core, m, r);
        if (r->body)
            write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
        portal_msg_free(m); portal_resp_free(r);
    }
    return 0;
}

static int cli_node_gps(portal_core_t *core, int fd,
                         const char *line, const char *args)
{
    (void)line;
    if (!args || !*args) { cli_send(fd, "Usage: node gps <coords>\n"); return -1; }
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (m && r) {
        portal_msg_set_path(m, "/node/functions/location");
        portal_msg_set_method(m, PORTAL_METHOD_CALL);
        portal_msg_add_header(m, "gps", args);
        core->send(core, m, r);
        if (r->body)
            write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
        portal_msg_free(m); portal_resp_free(r);
    }
    return 0;
}

static int cli_node_geolocate(portal_core_t *core, int fd,
                               const char *line, const char *args)
{
    (void)line; (void)args;
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (m && r) {
        portal_msg_set_path(m, "/node/functions/geolocate");
        portal_msg_set_method(m, PORTAL_METHOD_CALL);
        core->send(core, m, r);
        if (r->body)
            write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
        else
            cli_send(fd, "(geolocation failed)\n");
        portal_msg_free(m); portal_resp_free(r);
    }
    return 0;
}

static portal_cli_entry_t node_cli_cmds[] = {
    { .words = "ping",             .handler = cli_ping,            .summary = "Ping federation peer(s)" },
    { .words = "tracert",          .handler = cli_tracert,         .summary = "Trace route through federation" },
    { .words = "node status",      .handler = cli_node_status,     .summary = "Node status [peer]" },
    { .words = "node peers",       .handler = cli_node_peers,      .summary = "List federation peers" },
    { .words = "node ping",        .handler = cli_node_ping,       .summary = "Ping federation peer(s)" },
    { .words = "node trace",       .handler = cli_node_trace,      .summary = "Trace route through federation" },
    { .words = "node location",    .handler = cli_node_location,   .summary = "Set node location name" },
    { .words = "node gps",         .handler = cli_node_gps,        .summary = "Set node GPS coordinates" },
    { .words = "node geolocate",   .handler = cli_node_geolocate,  .summary = "Auto-detect node location from IP" },
    { .words = "node",             .handler = cli_node_status,     .summary = "Node federation status" },
    { .words = NULL }
};

/* ================================================================
 * Module lifecycle
 * ================================================================ */

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    /* Initialize dynamic peer registry (starts with 64 slot capacity) */
    g_peers = NULL;
    g_peers_cap = 0;
    g_peer_count = 0;
    peers_ensure_capacity(64);

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

    /* Peer advertisement control (default: none — privacy-safe) */
    v = core->config_get(core, "node", "advertise_peers");
    if (v && strcmp(v, "all") == 0)
        g_advertise_mode = ADV_ALL;
    else if (v && strcmp(v, "whitelist") == 0)
        g_advertise_mode = ADV_WHITELIST;
    else
        g_advertise_mode = ADV_NONE;

    v = core->config_get(core, "node", "advertise_to");
    if (v) snprintf(g_advertise_to, sizeof(g_advertise_to), "%s", v);

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

    listen(g_listen_fd, 128);     /* larger backlog for reconnect storms */
    set_nonblocking(g_listen_fd);  /* Commit 5: async accept loop */
    core->fd_add(core, g_listen_fd, EV_READ, on_new_peer, NULL);

    core->path_register(core, "/node/resources/status", "node");
    core->path_set_access(core, "/node/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/node/resources/status", "Federation node: name, port, TLS, peer count, threads/peer");
    core->path_register(core, "/node/resources/peers", "node");
    core->path_set_access(core, "/node/resources/peers", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/node/resources/peers", "Connected peers: name, IP, state, workers, traffic stats");
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
    /* Commit 5: 1 Hz sweep for stuck handshakes */
    core->timer_add(core, 1.0, hs_sweep_timer_cb, NULL);

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
    core->path_register(core, "/node/functions/shell", "node");
    core->path_set_access(core, "/node/functions/shell", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/node/functions/shell", "Open PTY shell on peer. Headers: peer, rows, cols. Returns fd for raw relay.");
    core->path_register(core, "/node/functions/ping", "node");
    core->path_set_access(core, "/node/functions/ping", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/node/functions/ping", "Measure RTT to peer. Header: name (or 'all')");
    core->path_register(core, "/node/functions/location", "node");
    core->path_set_access(core, "/node/functions/location", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/node/functions/location", "Set node location text. Header: name");
    core->path_register(core, "/node/functions/geolocate", "node");
    core->path_set_access(core, "/node/functions/geolocate", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/node/functions/geolocate", "Auto-detect location from public IP");
    core->path_register(core, "/node/functions/trace", "node");
    core->path_set_access(core, "/node/functions/trace", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/node/functions/trace", "Traceroute through federation. Header: path");
#ifdef HAS_SSL
    core->path_register(core, "/node/functions/reload_tls", "node");
    core->path_set_access(core, "/node/functions/reload_tls", PORTAL_ACCESS_RW);
    core->path_register(core, "/node/functions/renew_tls", "node");
    core->path_set_access(core, "/node/functions/renew_tls", PORTAL_ACCESS_RW);
#endif

    /* Register CLI commands */
    for (int i = 0; node_cli_cmds[i].words; i++)
        portal_cli_register(core, &node_cli_cmds[i], "node");

    /* Connect to configured peers */
    for (int i = 0; i < NODE_MAX_PEERS; i++) {
        char key[32];
        snprintf(key, sizeof(key), "peer%d", i);
        const char *val = core->config_get(core, "nodes", key);
        if (!val) continue;

        char pname[64] = {0}, phost[256] = {0};
        int pport = NODE_DEFAULT_PORT;
        if (sscanf(val, "%63[^=]=%255[^:]:%d", pname, phost, &pport) >= 2)
            connect_to_peer_async(pname, phost, pport);
    }

    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    for (int i = 0; i < g_peer_count; i++) {
        node_peer_t *peer = g_peers[i];
        /* Close worker fds first, then ctrl_fd — and skip ctrl_fd if it
         * happens to duplicate a worker (legacy inbound/outbound split).
         * Zero each fd after close so any stale reference can't re-free. */
        for (int j = 0; j < peer->worker_count; j++) {
            int wfd = peer->workers[j].fd;
            if (wfd >= 0) {
#ifdef HAS_SSL
                if (peer->workers[j].ssl) {
                    node_ssl_close(wfd, peer->workers[j].ssl);
                    peer->workers[j].ssl = NULL;
                }
#endif
                node_fd_del_with_rx(wfd);
                close(wfd);
                peer->workers[j].fd = -1;
                /* If ctrl_fd pointed to this same fd, clear it so we
                 * don't double-free below. */
                if (peer->ctrl_fd == wfd) {
                    peer->ctrl_fd = -1;
#ifdef HAS_SSL
                    peer->ctrl_ssl = NULL;
#endif
                }
            }
        }
        if (peer->ctrl_fd >= 0) {
#ifdef HAS_SSL
            if (peer->ctrl_ssl) {
                node_ssl_close(peer->ctrl_fd, peer->ctrl_ssl);
                peer->ctrl_ssl = NULL;
            }
#endif
            node_fd_del_with_rx(peer->ctrl_fd);
            close(peer->ctrl_fd);
            peer->ctrl_fd = -1;
        }
        for (int j = 0; j < peer->path_count; j++)
            core->path_unregister(core, peer->paths[j]);
        pthread_mutex_destroy(&peer->lock);
        free(peer);
        g_peers[i] = NULL;
    }
    g_peer_count = 0;
    free(g_peers);
    g_peers = NULL;
    g_peers_cap = 0;

    /* Destroy the rx_state hashtable (any remaining entries are freed) */
    if (g_rx_ht_inited) {
        for (size_t i = 0; i < g_rx_by_fd.capacity; i++) {
            if (g_rx_by_fd.entries[i].occupied == 1)
                rx_free(g_rx_by_fd.entries[i].value);
        }
        portal_ht_destroy(&g_rx_by_fd);
        g_rx_ht_inited = 0;
    }

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
    core->path_unregister(core, "/node/functions/shell");
    core->path_unregister(core, "/node/functions/ping");
    core->path_unregister(core, "/node/functions/trace");
    core->path_unregister(core, "/node/functions/location");
    core->path_unregister(core, "/node/functions/geolocate");
#ifdef HAS_SSL
    core->path_unregister(core, "/node/functions/reload_tls");
    core->path_unregister(core, "/node/functions/renew_tls");
    free_tls_contexts();
#endif

    portal_cli_unregister_module(core, "node");
    core->log(core, PORTAL_LOG_INFO, "node", "Node module unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

/* ================================================================
 * Message handler
 * ================================================================ */

/* ── Shell worker thread: get_worker + worker_send_recv in background ── */

typedef struct {
    int            local_fd;     /* socketpair end — relay to caller */
    node_peer_t   *peer;         /* target peer (or hub for indirect) */
    worker_t      *worker;       /* pre-acquired worker (fd already removed from ev loop) */
    int            rows;
    int            cols;
    char           target[PORTAL_MAX_MODULE_NAME]; /* actual target peer name */
    int            indirect;     /* 1 = routing through hub */
} shell_connect_ctx_t;

static void *shell_connect_thread(void *arg)
{
    shell_connect_ctx_t *c = (shell_connect_ctx_t *)arg;
    int lfd = c->local_fd;
    worker_t *w = c->worker;  /* already acquired on main thread */

    /* Send /tunnel/shell via blocking I/O on the worker fd.
     * For indirect peers: send /<target>/tunnel/shell so the hub routes it. */
    portal_msg_t smsg = {0};
    char spath[256];
    if (c->indirect)
        snprintf(spath, sizeof(spath), "/%s/tunnel/shell", c->target);
    else
        snprintf(spath, sizeof(spath), "/tunnel/shell");
    smsg.path = spath;
    smsg.method = PORTAL_METHOD_CALL;
    char rs[16], cs[16];
    snprintf(rs, sizeof(rs), "%d", c->rows);
    snprintf(cs, sizeof(cs), "%d", c->cols);
    portal_header_t sh[2] = {
        { .key = "rows", .value = rs },
        { .key = "cols", .value = cs }
    };
    smsg.headers = sh;
    smsg.header_count = 2;

    portal_resp_t sr = {0};
    int rc = worker_send_recv(w, &smsg, &sr);

    if (rc < 0 || sr.status != PORTAL_OK) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "node",
                    "Shell: /tunnel/shell failed on peer '%s' (rc=%d status=%d)",
                    c->peer->name, rc, sr.status);
        /* Cannot call release_worker from background thread (libev not thread-safe).
         * Just close the worker fd — it's already removed from the event loop. */
        close(w->fd);
        w->fd = -1;
        w->busy = 0;
        free(sr.body);
        close(lfd);
        free(c);
        return NULL;
    }
    free(sr.body);

    g_core->log(g_core, PORTAL_LOG_INFO, "node",
                "Shell connected to '%s' via worker fd %d", c->peer->name, w->fd);

    /* Worker fd is now in raw shell mode — relay between lfd and worker fd.
     * worker_send_recv already set it to blocking mode. */
    w->busy = 2;  /* pipe mode — won't be returned to pool */

    int wfd = w->fd;
    void *wssl = NULL;
#ifdef HAS_SSL
    wssl = w->ssl;
#endif

    /* Remove socket timeouts for relay */
    struct timeval notv = {0, 0};
    setsockopt(wfd, SOL_SOCKET, SO_RCVTIMEO, &notv, sizeof(notv));
    setsockopt(wfd, SOL_SOCKET, SO_SNDTIMEO, &notv, sizeof(notv));

    int maxfd = (lfd > wfd ? lfd : wfd) + 1;
    char buf[65536];

    while (1) {
#ifdef HAS_SSL
        int has_p = wssl && SSL_pending((SSL *)wssl) > 0;
#else
        int has_p = 0;
#endif
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lfd, &rfds);
        FD_SET(wfd, &rfds);
        struct timeval stv = {0, has_p ? 0 : 100000};
        int sel = select(maxfd, &rfds, NULL, NULL, has_p ? &stv : NULL);
        if (sel < 0 && errno == EINTR) continue;
        if (sel < 0) break;

        /* local → remote (client input) */
        if (FD_ISSET(lfd, &rfds)) {
            ssize_t n = read(lfd, buf, sizeof(buf));
            if (n <= 0) break;
            if (node_send(wfd, wssl, (uint8_t *)buf, (size_t)n) < 0) break;
        }
        /* remote → local (PTY output) */
        if (FD_ISSET(wfd, &rfds) || has_p) {
            do {
                ssize_t n = node_read_partial(wfd, wssl, buf, sizeof(buf));
                if (n <= 0) { if (FD_ISSET(wfd, &rfds)) goto shell_done; else break; }
                if (send_all(lfd, (uint8_t *)buf, (size_t)n) < 0) goto shell_done;
#ifdef HAS_SSL
            } while (wssl && SSL_pending((SSL *)wssl) > 0);
#else
            } while (0);
#endif
        }
    }
shell_done:
    close(lfd);

    /* Clean up worker fd — close it, don't return to pool.
     * Cannot call node_fd_add_with_rx from background thread (libev). */
#ifdef HAS_SSL
    if (wssl)
        node_ssl_close(wfd, (SSL *)wssl);
#endif
    close(wfd);
    w->fd = -1;
    w->busy = 0;
    g_core->log(g_core, PORTAL_LOG_INFO, "node",
                "Shell relay closed (peer '%s')", c->peer->name);

    free(c);
    return NULL;
}

/* ── Shell indirect thread: message-based relay for indirect (via hub) peers ── */

static void *shell_indirect_thread(void *arg)
{
    shell_connect_ctx_t *c = (shell_connect_ctx_t *)arg;
    int lfd = c->local_fd;
    char session_id[32] = {0};

    /* 1. Open PTY session on remote peer via federation routing */
    {
        char spath[256];
        snprintf(spath, sizeof(spath), "/%s/shell/functions/open", c->target);
        portal_msg_t *om = portal_msg_alloc();
        portal_resp_t *or_resp = portal_resp_alloc();
        if (!om || !or_resp) goto indirect_fail;

        portal_msg_set_path(om, spath);
        portal_msg_set_method(om, PORTAL_METHOD_CALL);
        char rs[16], cs[16];
        snprintf(rs, sizeof(rs), "%d", c->rows);
        snprintf(cs, sizeof(cs), "%d", c->cols);
        portal_msg_add_header(om, "rows", rs);
        portal_msg_add_header(om, "cols", cs);
        /* Attach root auth for federation */
        if (!om->ctx) om->ctx = calloc(1, sizeof(portal_ctx_t));
        if (om->ctx) {
            om->ctx->auth.user = strdup("root");
            om->ctx->auth.token = strdup("__federation__");
            portal_labels_add(&om->ctx->auth.labels, "root");
        }
        g_core->send(g_core, om, or_resp);

        if (or_resp->status == PORTAL_OK && or_resp->body && or_resp->body_len > 0) {
            snprintf(session_id, sizeof(session_id), "%.*s",
                     (int)(or_resp->body_len > 31 ? 31 : or_resp->body_len),
                     (char *)or_resp->body);
            session_id[strcspn(session_id, "\r\n")] = '\0';
        }
        portal_msg_free(om);
        portal_resp_free(or_resp);

        if (!session_id[0]) {
            g_core->log(g_core, PORTAL_LOG_ERROR, "node",
                        "Shell indirect: failed to open session on '%s'", c->target);
            goto indirect_fail;
        }
    }

    g_core->log(g_core, PORTAL_LOG_INFO, "node",
                "Shell indirect connected to '%s' session '%s'", c->target, session_id);

    /* 2. Relay loop: read local fd → write to remote, poll remote → write to local */
    {
        char buf[65536];
        char rpath[256], wpath[256];
        snprintf(rpath, sizeof(rpath), "/%s/shell/functions/read", c->target);
        snprintf(wpath, sizeof(wpath), "/%s/shell/functions/write", c->target);

        while (1) {
            /* Check for input from CLI client (non-blocking) */
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(lfd, &rfds);
            struct timeval tv = {0, 50000}; /* 50ms = 20Hz poll */
            int sel = select(lfd + 1, &rfds, NULL, NULL, &tv);

            if (sel < 0 && errno == EINTR) continue;
            if (sel < 0) break;

            /* Client input → remote PTY write */
            if (sel > 0 && FD_ISSET(lfd, &rfds)) {
                ssize_t n = read(lfd, buf, sizeof(buf));
                if (n <= 0) break; /* client disconnected */

                portal_msg_t *wm = portal_msg_alloc();
                portal_resp_t *wr = portal_resp_alloc();
                if (wm && wr) {
                    portal_msg_set_path(wm, wpath);
                    portal_msg_set_method(wm, PORTAL_METHOD_CALL);
                    portal_msg_add_header(wm, "session", session_id);
                    portal_msg_set_body(wm, buf, (size_t)n);
                    if (!wm->ctx) wm->ctx = calloc(1, sizeof(portal_ctx_t));
                    if (wm->ctx) { wm->ctx->auth.user = strdup("root"); wm->ctx->auth.token = strdup("__federation__"); portal_labels_add(&wm->ctx->auth.labels, "root"); }
                    g_core->send(g_core, wm, wr);
                    portal_msg_free(wm); portal_resp_free(wr);
                }
            }

            /* Remote PTY read → client output */
            {
                portal_msg_t *rm = portal_msg_alloc();
                portal_resp_t *rr = portal_resp_alloc();
                if (rm && rr) {
                    portal_msg_set_path(rm, rpath);
                    portal_msg_set_method(rm, PORTAL_METHOD_CALL);
                    portal_msg_add_header(rm, "session", session_id);
                    if (!rm->ctx) rm->ctx = calloc(1, sizeof(portal_ctx_t));
                    if (rm->ctx) { rm->ctx->auth.user = strdup("root"); rm->ctx->auth.token = strdup("__federation__"); portal_labels_add(&rm->ctx->auth.labels, "root"); }
                    g_core->send(g_core, rm, rr);

                    if (rr->status == PORTAL_NOT_FOUND) {
                        /* Session ended on remote side */
                        portal_msg_free(rm); portal_resp_free(rr);
                        break;
                    }
                    if (rr->body && rr->body_len > 0) {
                        ssize_t w = send(lfd, rr->body, rr->body_len, MSG_NOSIGNAL);
                        if (w < 0) { portal_msg_free(rm); portal_resp_free(rr); break; }
                    }
                    portal_msg_free(rm); portal_resp_free(rr);
                }
            }
        }
    }

    /* 3. Close remote session */
    {
        char cpath[256];
        snprintf(cpath, sizeof(cpath), "/%s/shell/functions/close", c->target);
        portal_msg_t *cm = portal_msg_alloc();
        portal_resp_t *cr = portal_resp_alloc();
        if (cm && cr) {
            portal_msg_set_path(cm, cpath);
            portal_msg_set_method(cm, PORTAL_METHOD_CALL);
            portal_msg_add_header(cm, "session", session_id);
            if (!cm->ctx) cm->ctx = calloc(1, sizeof(portal_ctx_t));
            if (cm->ctx) { cm->ctx->auth.user = strdup("root"); cm->ctx->auth.token = strdup("__federation__"); portal_labels_add(&cm->ctx->auth.labels, "root"); }
            g_core->send(g_core, cm, cr);
            portal_msg_free(cm); portal_resp_free(cr);
        }
    }

    g_core->log(g_core, PORTAL_LOG_INFO, "node",
                "Shell indirect relay closed (peer '%s')", c->target);
    close(lfd);
    free(c);
    return NULL;

indirect_fail:
    close(lfd);
    free(c);
    return NULL;
}

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
            node_peer_t *p = g_peers[i];
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
                ? g_peers[p->hub_idx]->name : "",
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
                node_peer_t *p = g_peers[i];
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
                            node_peer_t *hub = g_peers[p->hub_idx];

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

    /* /node/functions/shell — PTY shell on remote peer via dedicated connection.
     * Opens a NEW TCP(+TLS) connection to the peer in a background thread,
     * sends /tunnel/shell, then relays raw bytes. Never touches the worker
     * pool, never blocks the event loop.
     *
     * Returns immediately with a socketpair fd. The background thread
     * connects, handshakes, and starts relaying. If the connection fails,
     * the fd is closed (relay thread exits, CLI sees session ended). */
    if (strcmp(msg->path, "/node/functions/shell") == 0) {
        const char *peer_name = NULL;
        const char *rows_str = "24", *cols_str = "80";
        for (uint16_t hi = 0; hi < msg->header_count; hi++) {
            if (strcmp(msg->headers[hi].key, "peer") == 0) peer_name = msg->headers[hi].value;
            if (strcmp(msg->headers[hi].key, "rows") == 0) rows_str = msg->headers[hi].value;
            if (strcmp(msg->headers[hi].key, "cols") == 0) cols_str = msg->headers[hi].value;
        }
        if (!peer_name) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }

        node_peer_t *peer = find_peer_by_name(peer_name);
        if (!peer || !peer->ready) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            return -1;
        }

        /* Create socketpair: sp[0] = background thread side, sp[1] = caller side */
        int sp[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            return -1;
        }

        shell_connect_ctx_t *ctx = calloc(1, sizeof(*ctx));
        ctx->local_fd = sp[0];
        ctx->rows = atoi(rows_str);
        ctx->cols = atoi(cols_str);
        snprintf(ctx->target, sizeof(ctx->target), "%s", peer_name);
        ctx->indirect = peer->is_indirect;

        if (peer->is_indirect) {
            /* Indirect peers: can't do raw fd relay through hub.
             * Use message-based relay via g_core->send() in a thread. */
            ctx->peer = NULL;
            ctx->worker = NULL;
        } else {
            /* Direct peers: raw fd relay through worker */
            ctx->peer = peer;
            worker_t *w = get_worker(peer);
            if (!w || w->fd < 0) {
                close(sp[0]); close(sp[1]);
                free(ctx);
                portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
                return -1;
            }
            ctx->worker = w;
        }

        pthread_t th;
        if (peer->is_indirect)
            pthread_create(&th, NULL, shell_indirect_thread, ctx);
        else
            pthread_create(&th, NULL, shell_connect_thread, ctx);
        pthread_detach(th);

        /* Return sp[1] to caller — immediately, no blocking */
        char fd_str[16];
        int fd_n = snprintf(fd_str, sizeof(fd_str), "%d", sp[1]);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, fd_str, (size_t)fd_n);
        core->log(core, PORTAL_LOG_INFO, "node",
                  "Shell opening on peer '%s' (fd %d)", peer_name, sp[1]);
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

                /* Indirect peer: forward full path through hub.
                 * Commit 4d: uses peer_send_wait (non-blocking tx + FIFO
                 * pending + nested ev_run). No fd_del/fd_add churn; the
                 * core thread pumps libev while blocked on the response. */
                if (peer && peer->ready && peer->is_indirect) {
                    int hi = peer->hub_idx;
                    if (hi >= 0 && hi < g_peer_count &&
                        g_peers[hi]->ready && g_peers[hi]->worker_count > 0) {
                        peer->msgs_sent++;
                        int rc = peer_send_wait(g_peers[hi], msg, resp,
                                                30ULL * 1000000ULL);
                        if (rc == 0) {
                            peer->msgs_recv++;
                            if (resp->body_len > 0)
                                peer->bytes_recv += resp->body_len;
                            core->log(core, PORTAL_LOG_DEBUG, "node",
                                      "Routed %s → %s via hub '%s' [%d]",
                                      msg->path, peer_name,
                                      g_peers[hi]->name, resp->status);
                            return 0;
                        }
                        peer->errors++;
                        portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
                        return -1;
                    }
                }

                /* Direct peer: strip node prefix and forward.
                 * Commit 4d: peer_send_wait drives this non-blocking with
                 * a FIFO pending queue per conn. The core thread pumps
                 * libev inside pending_wait while waiting for the response. */
                if (peer && peer->ready &&
                    (peer->worker_count > 0 || peer->ctrl_fd >= 0)) {
                    portal_msg_t remote_msg = *msg;
                    remote_msg.path = (char *)slash;

                    peer->msgs_sent++;
                    if (msg->body_len > 0)
                        peer->bytes_sent += msg->body_len;
                    int rc = peer_send_wait(peer, &remote_msg, resp,
                                             30ULL * 1000000ULL);
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
