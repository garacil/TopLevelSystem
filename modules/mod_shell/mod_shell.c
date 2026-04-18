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
 * mod_shell — Remote interactive shell via federation (PTY mode)
 *
 * Opens a real pseudo-terminal per session. Supports interactive programs
 * like htop, vi, top, less, sudo. The PTY provides a full terminal
 * environment with $TERM, signal handling, and job control.
 *
 * Two modes:
 *   1. Single command: /shell/functions/exec?cmd=uptime (stateless, popen)
 *   2. PTY session:    /shell/functions/open  → session_id
 *                      /shell/functions/write → send input to PTY
 *                      /shell/functions/read  → read output from PTY
 *                      /shell/functions/close → terminate session
 *
 * The CLI "shell <peer>" command uses mode 2 transparently.
 *
 * Paths:
 *   /shell/functions/exec    RW (access_label)  Single command (stateless)
 *   /shell/functions/open    RW (access_label)  Open PTY session → session_id
 *   /shell/functions/write   RW (access_label)  Send input to PTY session
 *   /shell/functions/read    RW (access_label)  Read output from PTY session
 *   /shell/functions/close   RW (access_label)  Close PTY session
 *   /shell/functions/resize  RW (access_label)  Set terminal size (rows, cols)
 *
 * Events:
 *   /events/shell/exec       Single command executed
 *   /events/shell/session     PTY session opened/closed
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <pty.h>
#include <time.h>
#include <termios.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <pwd.h>
#include <grp.h>

#ifdef HAS_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

#include "portal/portal.h"

/* ── Constants ── */

#define SHELL_MAX_SESSIONS  32
#define SHELL_READ_BUF      65536
#define SHELL_SESSION_TTL    3600  /* auto-close after 1 hour of inactivity */

/* ── PTY Session ── */

typedef struct {
    int    active;
    int    master_fd;       /* PTY master side */
    pid_t  child_pid;       /* shell process */
    char   session_id[32];  /* unique identifier */
    time_t last_activity;
    int    rows;
    int    cols;
} shell_session_t;

/* ── Configuration ── */

static struct {
    int  timeout;
    char shell[64];
    int  allow_exec;
    int  max_output;
    int  session_ttl;
    char access_label[64];  /* group/label required to use shell (default: root) */

    /* Dial-back shell channel */
    int  shell_port;
    char shell_bind[64];
    char shell_tls_cert[256];
    char shell_tls_key[256];
    char shell_advertise_host[128];
    char shell_login_binary[128];
    int  shell_dial_timeout;
} g_cfg;

static portal_core_t *g_core;
static shell_session_t g_sessions[SHELL_MAX_SESSIONS];
static int g_session_counter;

/* ═══════════════════════════════════════════════════════════════════════════
 *  Dial-back shell channel — globals + data structures
 *
 *  Architecture:
 *
 *    initiator (Portal instance running the CLI)
 *      │ 1. generate session_id (32 random hex)
 *      │ 2. register pending_shell entry
 *      │ 3. send /<peer>/shell/functions/dialback_request via federation
 *      │    (one tiny message on existing ctrl_fd — NO worker pool burn)
 *      │ 4. wait on condvar (shell_dial_timeout seconds)
 *      ▼
 *    target device (remote peer)
 *      │ 5. spawn dialback_thread
 *      │ 6. TCP connect to reply_host:reply_port
 *      │ 7. TLS client handshake
 *      │ 8. SSL_write session_id + '\n'
 *      │ 9. forkpty + execl /bin/login   (real PAM auth, real user UID)
 *      │ 10. relay PTY master ↔ TLS fd   (dedicated pthread)
 *      ▼
 *    initiator (back at step 4)
 *      │ 11. listener thread accept() → spawn accept_handler_thread
 *      │ 12. TLS accept + SSL_read session_id line
 *      │ 13. look up pending_shell by session_id, create socketpair(plain,tls_bridge)
 *      │ 14. signal waiter with plain end → handle_open_remote returns that fd
 *      │ 15. accept_handler_thread runs tls_bridge: plain end ↔ TLS fd (dedicated pthread)
 *      ▼
 *    CLI relays user terminal ↔ plain end.  When either side closes,
 *    both pthreads exit cleanly. Federation is untouched.
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct pending_shell {
    char            session_id[65];   /* 32 bytes → 64 hex + NUL */
    pthread_mutex_t lock;
    pthread_cond_t  cond;
    int             ready;            /* 0 = waiting, 1 = fd_out valid or error */
    int             fd_out;           /* plain side of bridge socketpair; -1 = error */
    time_t          created;
    struct pending_shell *next;
} pending_shell_t;

static pending_shell_t *g_pending_head = NULL;
static pthread_mutex_t  g_pending_lock = PTHREAD_MUTEX_INITIALIZER;

static int          g_listen_fd       = -1;
static pthread_t    g_listen_thread;
static volatile int g_listener_running = 0;

#ifdef HAS_SSL
static SSL_CTX     *g_server_ssl_ctx  = NULL;
static SSL_CTX     *g_client_ssl_ctx  = NULL;
#endif

typedef struct {
    char session_id[65];
    char reply_host[128];
    int  reply_port;
    int  rows;
    int  cols;
} dialback_ctx_t;

/* ── Module descriptor ── */

static portal_module_info_t info = {
    .name        = "shell",
    .version     = "2.0.0",
    .description = "Remote interactive shell via federation (PTY)",
    .soft_deps   = NULL
};

portal_module_info_t *portal_module_info(void) { return &info; }

/* ── Session management ── */

static shell_session_t *session_find(const char *id)
{
    for (int i = 0; i < SHELL_MAX_SESSIONS; i++)
        if (g_sessions[i].active && strcmp(g_sessions[i].session_id, id) == 0)
            return &g_sessions[i];
    return NULL;
}

static shell_session_t *session_create(void)
{
    for (int i = 0; i < SHELL_MAX_SESSIONS; i++) {
        if (!g_sessions[i].active) {
            memset(&g_sessions[i], 0, sizeof(shell_session_t));
            g_sessions[i].active = 1;
            g_sessions[i].last_activity = time(NULL);
            g_sessions[i].rows = 24;
            g_sessions[i].cols = 80;
            snprintf(g_sessions[i].session_id, sizeof(g_sessions[i].session_id),
                     "sh%d_%ld", ++g_session_counter, (long)time(NULL));
            return &g_sessions[i];
        }
    }
    return NULL;
}

static void session_close(shell_session_t *s)
{
    if (!s || !s->active) return;
    if (s->child_pid > 0) {
        kill(s->child_pid, SIGTERM);
        usleep(100000); /* 100ms grace */
        kill(s->child_pid, SIGKILL);
        waitpid(s->child_pid, NULL, WNOHANG);
    }
    if (s->master_fd >= 0)
        close(s->master_fd);
    s->active = 0;
}

/* ── Stateless exec (backward compat) ── */

static int handle_exec(portal_core_t *core, const portal_msg_t *msg,
                       portal_resp_t *resp)
{
    if (!g_cfg.allow_exec) {
        portal_resp_set_status(resp, PORTAL_FORBIDDEN);
        portal_resp_set_body(resp, "shell execution disabled\n", 25);
        return -1;
    }

    const char *cmd = NULL;
    const char *cwd = NULL;
    int timeout = g_cfg.timeout;

    for (uint16_t i = 0; i < msg->header_count; i++) {
        if (strcmp(msg->headers[i].key, "cmd") == 0) cmd = msg->headers[i].value;
        if (strcmp(msg->headers[i].key, "cwd") == 0) cwd = msg->headers[i].value;
        if (strcmp(msg->headers[i].key, "timeout") == 0) {
            int t = atoi(msg->headers[i].value);
            if (t > 0 && t <= 300) timeout = t;
        }
    }

    if (!cmd || !cmd[0]) {
        portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
        portal_resp_set_body(resp, "missing header: cmd\n", 20);
        return -1;
    }

    char full[4096];
    if (cwd && cwd[0] && strcmp(cwd, "/") != 0)
        snprintf(full, sizeof(full), "cd '%s' 2>/dev/null && %s", cwd, cmd);
    else
        snprintf(full, sizeof(full), "%s", cmd);

    /* Execute via popen (stateless) */
    char shell_cmd[4200];
    snprintf(shell_cmd, sizeof(shell_cmd), "%s -c '%s' 2>&1", g_cfg.shell, full);

    alarm((unsigned)timeout);
    FILE *p = popen(shell_cmd, "r");
    if (!p) { alarm(0); portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR); return -1; }

    size_t cap = 4096, pos = 0;
    char *buf = malloc(cap);
    while (buf && pos < (size_t)g_cfg.max_output) {
        size_t n = fread(buf + pos, 1, cap - pos - 1, p);
        if (n == 0) break;
        pos += n;
        if (pos + 256 >= cap) { cap *= 2; char *nb = realloc(buf, cap); if (nb) buf = nb; else break; }
    }
    alarm(0);
    int status = pclose(p);
    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

    if (buf) buf[pos] = '\0';

    /* Audit */
    char evt[512];
    int elen = snprintf(evt, sizeof(evt), "cmd=%s exit=%d", cmd, exit_code);
    core->event_emit(core, "/events/shell/exec", evt, (size_t)elen);
    core->log(core, PORTAL_LOG_INFO, "shell", "exec: %s (exit %d, %zu bytes)", cmd, exit_code, pos);

    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, buf ? buf : "(no output)\n", buf ? pos : 12);
    free(buf);
    return 0;
}

/* ── PTY session: open ── */

static int handle_open(portal_core_t *core, const portal_msg_t *msg,
                       portal_resp_t *resp)
{
    (void)msg;
    if (!g_cfg.allow_exec) {
        portal_resp_set_status(resp, PORTAL_FORBIDDEN);
        portal_resp_set_body(resp, "shell execution disabled\n", 25);
        return -1;
    }

    shell_session_t *s = session_create();
    if (!s) {
        portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
        portal_resp_set_body(resp, "max sessions reached\n", 21);
        return -1;
    }

    /* Set initial terminal size */
    for (uint16_t i = 0; i < msg->header_count; i++) {
        if (strcmp(msg->headers[i].key, "rows") == 0) s->rows = atoi(msg->headers[i].value);
        if (strcmp(msg->headers[i].key, "cols") == 0) s->cols = atoi(msg->headers[i].value);
    }

    struct winsize ws = { .ws_row = (unsigned short)s->rows, .ws_col = (unsigned short)s->cols };

    /* Fork with PTY */
    s->child_pid = forkpty(&s->master_fd, NULL, NULL, &ws);
    if (s->child_pid < 0) {
        s->active = 0;
        portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
        portal_resp_set_body(resp, "forkpty failed\n", 15);
        return -1;
    }

    if (s->child_pid == 0) {
        /* Child: exec shell */
        setenv("TERM", "xterm-256color", 1);
        /* Inherit locale from the system — don't force a specific one */
        execl(g_cfg.shell, g_cfg.shell, "-l", (char *)NULL);
        _exit(127);
    }

    /* Parent: set master non-blocking */
    int flags = fcntl(s->master_fd, F_GETFL, 0);
    fcntl(s->master_fd, F_SETFL, flags | O_NONBLOCK);

    core->log(core, PORTAL_LOG_INFO, "shell",
              "PTY session %s opened (pid %d, %dx%d)",
              s->session_id, s->child_pid, s->cols, s->rows);

    char body[128];
    int n = snprintf(body, sizeof(body), "%s\n", s->session_id);
    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, body, (size_t)n);
    return 0;
}

/* ── PTY session: write (send input) ── */

static int handle_write(portal_core_t *core, const portal_msg_t *msg,
                        portal_resp_t *resp)
{
    (void)core;
    const char *sid = NULL;
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, "session") == 0) sid = msg->headers[i].value;

    if (!sid) {
        portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
        portal_resp_set_body(resp, "missing header: session\n", 24);
        return -1;
    }

    shell_session_t *s = session_find(sid);
    if (!s) {
        portal_resp_set_status(resp, PORTAL_NOT_FOUND);
        portal_resp_set_body(resp, "session not found\n", 18);
        return -1;
    }

    s->last_activity = time(NULL);

    /* Write the body (raw bytes) to the PTY master */
    if (msg->body && msg->body_len > 0) {
        ssize_t w = write(s->master_fd, msg->body, msg->body_len);
        (void)w;
    }

    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, "ok\n", 3);
    return 0;
}

/* ── PTY session: read (get output) ── */

static int handle_read(portal_core_t *core, const portal_msg_t *msg,
                       portal_resp_t *resp)
{
    (void)core;
    const char *sid = NULL;
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, "session") == 0) sid = msg->headers[i].value;

    if (!sid) {
        portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
        portal_resp_set_body(resp, "missing header: session\n", 24);
        return -1;
    }

    shell_session_t *s = session_find(sid);
    if (!s) {
        portal_resp_set_status(resp, PORTAL_NOT_FOUND);
        portal_resp_set_body(resp, "session not found\n", 18);
        return -1;
    }

    s->last_activity = time(NULL);

    /* Check if child is still alive */
    int wstatus;
    if (waitpid(s->child_pid, &wstatus, WNOHANG) > 0) {
        /* Child exited — drain remaining output and close */
        char buf[SHELL_READ_BUF];
        ssize_t n = read(s->master_fd, buf, sizeof(buf) - 1);
        session_close(s);
        if (n > 0) {
            buf[n] = '\0';
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, buf, (size_t)n);
        } else {
            /* Return 404 so the CLI timer auto-disconnects */
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            portal_resp_set_body(resp, "session ended\n", 14);
        }
        return 0;
    }

    /* Read available output (non-blocking) */
    char buf[SHELL_READ_BUF];
    ssize_t total = 0;

    /* Non-blocking read — returns immediately if no data available */
    ssize_t n = read(s->master_fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        total = n;
        buf[total] = '\0';
    }

    if (total > 0) {
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)total);
    } else {
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, "", 0);
    }
    return 0;
}

/* ── PTY session: close ── */

static int handle_close(portal_core_t *core, const portal_msg_t *msg,
                        portal_resp_t *resp)
{
    const char *sid = NULL;
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, "session") == 0) sid = msg->headers[i].value;

    if (!sid) {
        portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
        portal_resp_set_body(resp, "missing header: session\n", 24);
        return -1;
    }

    shell_session_t *s = session_find(sid);
    if (!s) {
        portal_resp_set_status(resp, PORTAL_NOT_FOUND);
        portal_resp_set_body(resp, "session not found\n", 18);
        return -1;
    }

    core->log(core, PORTAL_LOG_INFO, "shell",
              "PTY session %s closed (pid %d)", s->session_id, s->child_pid);
    session_close(s);

    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, "closed\n", 7);
    return 0;
}

/* ── PTY session: resize ── */

static int handle_resize(portal_core_t *core, const portal_msg_t *msg,
                         portal_resp_t *resp)
{
    (void)core;
    const char *sid = NULL;
    int rows = 0, cols = 0;
    for (uint16_t i = 0; i < msg->header_count; i++) {
        if (strcmp(msg->headers[i].key, "session") == 0) sid = msg->headers[i].value;
        if (strcmp(msg->headers[i].key, "rows") == 0) rows = atoi(msg->headers[i].value);
        if (strcmp(msg->headers[i].key, "cols") == 0) cols = atoi(msg->headers[i].value);
    }

    if (!sid) {
        portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
        return -1;
    }

    shell_session_t *s = session_find(sid);
    if (!s) {
        portal_resp_set_status(resp, PORTAL_NOT_FOUND);
        return -1;
    }

    if (rows > 0 && cols > 0) {
        struct winsize ws = { .ws_row = (unsigned short)rows, .ws_col = (unsigned short)cols };
        ioctl(s->master_fd, TIOCSWINSZ, &ws);
        s->rows = rows;
        s->cols = cols;
    }

    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, "resized\n", 8);
    return 0;
}

/* ── Maintenance: clean up expired sessions ── */

static void maintenance_tick(void *userdata)
{
    (void)userdata;
    time_t now = time(NULL);
    for (int i = 0; i < SHELL_MAX_SESSIONS; i++) {
        if (g_sessions[i].active &&
            (now - g_sessions[i].last_activity) > g_cfg.session_ttl) {
            g_core->log(g_core, PORTAL_LOG_WARN, "shell",
                        "Session %s expired (inactive %lds)",
                        g_sessions[i].session_id,
                        (long)(now - g_sessions[i].last_activity));
            session_close(&g_sessions[i]);
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Dial-back shell channel — implementation
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Generate a cryptographically random 32-byte session id, hex-encoded. */
static void gen_session_id(char *out, size_t outlen)
{
    uint8_t buf[32];
#ifdef HAS_SSL
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        /* Fallback — should never happen with a working OpenSSL */
        for (size_t i = 0; i < sizeof(buf); i++)
            buf[i] = (uint8_t)(rand() & 0xff);
    }
#else
    for (size_t i = 0; i < sizeof(buf); i++)
        buf[i] = (uint8_t)(rand() & 0xff);
#endif
    static const char hex[] = "0123456789abcdef";
    size_t j = 0;
    for (size_t i = 0; i < sizeof(buf) && j + 2 < outlen; i++) {
        out[j++] = hex[buf[i] >> 4];
        out[j++] = hex[buf[i] & 0x0f];
    }
    out[j] = '\0';
}

static void pending_add(pending_shell_t *ps)
{
    pthread_mutex_lock(&g_pending_lock);
    ps->next = g_pending_head;
    g_pending_head = ps;
    pthread_mutex_unlock(&g_pending_lock);
}

/* Look up by session_id and unlink in one atomic pass. The caller now owns
 * the struct and is responsible for eventually destroying the mutex/cond
 * and freeing it. Returns NULL if no match. */
static pending_shell_t *pending_take(const char *session_id)
{
    pthread_mutex_lock(&g_pending_lock);
    pending_shell_t **pp = &g_pending_head;
    while (*pp) {
        if (strcmp((*pp)->session_id, session_id) == 0) {
            pending_shell_t *hit = *pp;
            *pp = hit->next;
            hit->next = NULL;
            pthread_mutex_unlock(&g_pending_lock);
            return hit;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&g_pending_lock);
    return NULL;
}

/* Try to find our own first non-loopback IPv4 to tell the device where to
 * dial back to. Returns 0 on success (out filled, NUL-terminated), -1 on
 * failure. Used when shell_advertise_host is empty in config. */
static int resolve_self_ipv4(char *out, size_t outlen)
{
    struct ifaddrs *ifs = NULL;
    if (getifaddrs(&ifs) != 0) return -1;
    int rc = -1;
    for (struct ifaddrs *it = ifs; it; it = it->ifa_next) {
        if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET) continue;
        if (it->ifa_flags & IFF_LOOPBACK) continue;
        struct sockaddr_in *sin = (struct sockaddr_in *)it->ifa_addr;
        const char *p = inet_ntop(AF_INET, &sin->sin_addr, out, (socklen_t)outlen);
        if (p) { rc = 0; break; }
    }
    freeifaddrs(ifs);
    return rc;
}

/* Blocking select-based byte-relay between a plain fd and a TLS socket.
 * Runs in its own pthread on both sides of the dial-back channel.
 *
 * CRITICAL: plain_fd may be a PTY master (device side, forkpty returned)
 * OR a Unix socketpair end (server side, accept_handler_thread bridge).
 * We use write()/read() — NOT send()/recv() — because send() on a
 * non-socket fd (like a PTY master) returns -1 with ENOTSOCK and would
 * tear the session down on the first keystroke. write() works on both. */
static ssize_t write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t left = len;
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w > 0) { p += w; left -= (size_t)w; continue; }
        if (w < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        return -1;
    }
    return (ssize_t)len;
}

static void tls_plain_relay(int plain_fd, int tls_fd, void *ssl_ptr)
{
    (void)tls_fd; /* unused when !HAS_SSL; kept for symmetry */
    char buf[65536];
    int pfd = plain_fd;
    int tfd = tls_fd;
    int maxfd = (pfd > tfd ? pfd : tfd) + 1;
#ifdef HAS_SSL
    SSL *ssl = (SSL *)ssl_ptr;
#else
    (void)ssl_ptr;
#endif

    while (1) {
#ifdef HAS_SSL
        int has_pending = ssl && SSL_pending(ssl) > 0;
#else
        int has_pending = 0;
#endif
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(pfd, &rfds);
        FD_SET(tfd, &rfds);
        struct timeval tv = {0, has_pending ? 0 : 100000};
        int sel = select(maxfd, &rfds, NULL, NULL, has_pending ? &tv : NULL);
        if (sel < 0 && errno == EINTR) continue;
        if (sel < 0) break;

        /* plain → tls */
        if (FD_ISSET(pfd, &rfds)) {
            ssize_t n = read(pfd, buf, sizeof(buf));
            if (n <= 0) break;
#ifdef HAS_SSL
            if (ssl) {
                if (SSL_write(ssl, buf, (int)n) <= 0) break;
            } else
#endif
            if (write_all(tfd, buf, (size_t)n) < 0) break;
        }
        /* tls → plain */
        if (FD_ISSET(tfd, &rfds) || has_pending) {
#ifdef HAS_SSL
            if (ssl) {
                do {
                    int n = SSL_read(ssl, buf, sizeof(buf));
                    if (n <= 0) return;
                    if (write_all(pfd, buf, (size_t)n) < 0) return;
                } while (SSL_pending(ssl) > 0);
            } else
#endif
            {
                ssize_t n = read(tfd, buf, sizeof(buf));
                if (n <= 0) return;
                if (write_all(pfd, buf, (size_t)n) < 0) return;
            }
        }
    }
}

/* ─── Server-side: listener + accept handler ─────────────────────────── */

static void *accept_handler_thread(void *arg)
{
    int cfd = (int)(intptr_t)arg;

    /* Short read-timeout during the session_id handshake so a silent
     * attacker or broken dial doesn't park the thread forever. */
    struct timeval tv = {5, 0};
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    void *ssl_any = NULL;
#ifdef HAS_SSL
    SSL *ssl = NULL;
    if (g_server_ssl_ctx) {
        ssl = SSL_new(g_server_ssl_ctx);
        if (!ssl) { close(cfd); return NULL; }
        SSL_set_fd(ssl, cfd);
        if (SSL_accept(ssl) != 1) {
            SSL_free(ssl);
            close(cfd);
            return NULL;
        }
        ssl_any = ssl;
    }
#endif

    /* Read session_id line (max 80 chars). */
    char line[96];
    int pos = 0;
    while (pos < (int)sizeof(line) - 1) {
        char ch;
        int n;
#ifdef HAS_SSL
        if (ssl) n = SSL_read(ssl, &ch, 1);
        else
#endif
        n = (int)recv(cfd, &ch, 1, 0);
        if (n <= 0) goto bail;
        if (ch == '\n' || ch == '\r') break;
        line[pos++] = ch;
    }
    line[pos] = '\0';
    if (pos == 0) goto bail;

    pending_shell_t *ps = pending_take(line);
    if (!ps) {
        g_core->log(g_core, PORTAL_LOG_WARN, "shell",
                    "dial-back: unknown session_id '%.8s...' — dropping", line);
        goto bail;
    }

    /* Build the bridge: plain (handed to caller) ↔ TLS (held by this thread). */
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) {
        pthread_mutex_lock(&ps->lock);
        ps->fd_out = -1;
        ps->ready = 1;
        pthread_cond_signal(&ps->cond);
        pthread_mutex_unlock(&ps->lock);
        goto bail_ps;
    }

    /* Clear timeouts — raw relay mode from here on. */
    struct timeval notv = {0, 0};
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &notv, sizeof(notv));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &notv, sizeof(notv));

    pthread_mutex_lock(&ps->lock);
    ps->fd_out = sp[1];
    ps->ready = 1;
    pthread_cond_signal(&ps->cond);
    pthread_mutex_unlock(&ps->lock);

    g_core->log(g_core, PORTAL_LOG_INFO, "shell",
                "dial-back: session '%.8s...' attached, starting TLS relay",
                ps->session_id);

    tls_plain_relay(sp[0], cfd, ssl_any);

    close(sp[0]);
    g_core->log(g_core, PORTAL_LOG_INFO, "shell",
                "dial-back: session '%.8s...' closed", ps->session_id);

bail_ps:
    pthread_mutex_destroy(&ps->lock);
    pthread_cond_destroy(&ps->cond);
    free(ps);
bail:
#ifdef HAS_SSL
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
#endif
    close(cfd);
    return NULL;
}

static void *listener_thread(void *arg)
{
    (void)arg;
    while (g_listener_running) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int cfd = accept(g_listen_fd, (struct sockaddr *)&caddr, &clen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            if (!g_listener_running) break;
            usleep(100000);
            continue;
        }
        pthread_t t;
        if (pthread_create(&t, NULL, accept_handler_thread,
                           (void *)(intptr_t)cfd) != 0) {
            close(cfd);
            continue;
        }
        pthread_detach(t);
    }
    return NULL;
}

static int start_listener(void)
{
    if (g_cfg.shell_port <= 0) return 0;   /* disabled */

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "shell",
                    "dial-back: socket() failed: %s", strerror(errno));
        return -1;
    }
    int one = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)g_cfg.shell_port);
    if (g_cfg.shell_bind[0] == '\0' ||
        inet_pton(AF_INET, g_cfg.shell_bind, &addr.sin_addr) <= 0) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "shell",
                    "dial-back: bind %s:%d failed: %s",
                    g_cfg.shell_bind[0] ? g_cfg.shell_bind : "0.0.0.0",
                    g_cfg.shell_port, strerror(errno));
        close(g_listen_fd);
        g_listen_fd = -1;
        return -1;
    }
    if (listen(g_listen_fd, 16) < 0) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "shell",
                    "dial-back: listen() failed: %s", strerror(errno));
        close(g_listen_fd);
        g_listen_fd = -1;
        return -1;
    }
    g_listener_running = 1;
    if (pthread_create(&g_listen_thread, NULL, listener_thread, NULL) != 0) {
        g_listener_running = 0;
        close(g_listen_fd);
        g_listen_fd = -1;
        return -1;
    }
    g_core->log(g_core, PORTAL_LOG_INFO, "shell",
                "dial-back: listening on %s:%d (TLS=%s)",
                g_cfg.shell_bind[0] ? g_cfg.shell_bind : "0.0.0.0",
                g_cfg.shell_port,
#ifdef HAS_SSL
                g_server_ssl_ctx ? "yes" : "no"
#else
                "no"
#endif
                );
    return 0;
}

static void stop_listener(void)
{
    if (g_listen_fd < 0) return;
    g_listener_running = 0;
    shutdown(g_listen_fd, SHUT_RDWR);
    close(g_listen_fd);
    g_listen_fd = -1;
    pthread_join(g_listen_thread, NULL);
}

/* ─── Device-side: dial-back thread ──────────────────────────────────── */

static void *dialback_thread(void *arg)
{
    dialback_ctx_t *c = (dialback_ctx_t *)arg;

    /* 1. TCP connect to initiator. */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { free(c); return NULL; }
    struct timeval cto = {10, 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &cto, sizeof(cto));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &cto, sizeof(cto));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)c->reply_port);

    if (inet_pton(AF_INET, c->reply_host, &addr.sin_addr) <= 0) {
        struct addrinfo hints = { .ai_family = AF_INET };
        struct addrinfo *res = NULL;
        if (getaddrinfo(c->reply_host, NULL, &hints, &res) != 0 || !res) {
            g_core->log(g_core, PORTAL_LOG_ERROR, "shell",
                        "dial-back: cannot resolve '%s'", c->reply_host);
            close(fd); free(c); return NULL;
        }
        addr.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
        freeaddrinfo(res);
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "shell",
                    "dial-back: connect %s:%d failed: %s",
                    c->reply_host, c->reply_port, strerror(errno));
        close(fd); free(c); return NULL;
    }

    /* 2. TLS client handshake. */
    void *ssl_any = NULL;
#ifdef HAS_SSL
    SSL *ssl = NULL;
    if (g_client_ssl_ctx) {
        ssl = SSL_new(g_client_ssl_ctx);
        if (!ssl) { close(fd); free(c); return NULL; }
        SSL_set_fd(ssl, fd);
        if (SSL_connect(ssl) != 1) {
            g_core->log(g_core, PORTAL_LOG_ERROR, "shell",
                        "dial-back: TLS handshake to %s:%d failed",
                        c->reply_host, c->reply_port);
            SSL_free(ssl); close(fd); free(c); return NULL;
        }
        ssl_any = ssl;
    }
#endif

    /* 3. Announce session_id (terminated by '\n'). */
    char line[80];
    int ln = snprintf(line, sizeof(line), "%s\n", c->session_id);
    int wrote;
#ifdef HAS_SSL
    if (ssl) wrote = (SSL_write(ssl, line, ln) == ln) ? ln : -1;
    else
#endif
    wrote = (int)send(fd, line, (size_t)ln, MSG_NOSIGNAL);
    if (wrote != ln) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "shell",
                    "dial-back: session_id send failed");
#ifdef HAS_SSL
        if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
#endif
        close(fd); free(c); return NULL;
    }

    /* 4. forkpty + exec /bin/login. */
    struct winsize ws = {
        .ws_row = (unsigned short)(c->rows > 0 ? c->rows : 24),
        .ws_col = (unsigned short)(c->cols > 0 ? c->cols : 80)
    };
    int master_fd;
    pid_t pid = forkpty(&master_fd, NULL, NULL, &ws);
    if (pid < 0) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "shell",
                    "dial-back: forkpty failed: %s", strerror(errno));
#ifdef HAS_SSL
        if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
#endif
        close(fd); free(c); return NULL;
    }
    if (pid == 0) {
        /* Child — we ARE the PTY slave process (stdin/stdout/stderr all
         * point at /dev/pts/N courtesy of forkpty). Prompt for the
         * username ourselves, validate it, then exec `/bin/su -l <user>`.
         *
         * This deliberately avoids /bin/login: modern util-linux 2.40
         * on AlmaLinux 10 rejects forkpty'd PTYs with "FATAL: bad tty"
         * because its check_tty() logic expects to be invoked by getty
         * with additional setup we don't do. /bin/su is simpler, uses
         * PAM for auth exactly like login does, drops to the user's
         * UID, runs their login shell, and writes utmp/wtmp cleanly. */
        setenv("TERM", "xterm-256color", 1);

        /* Small host banner then username prompt. */
        char banner[256];
        char host[64] = "portal";
        gethostname(host, sizeof(host));
        host[sizeof(host) - 1] = '\0';
        int bn = snprintf(banner, sizeof(banner), "\r\n%s login: ", host);
        if (bn > 0) (void)!write(STDOUT_FILENO, banner, (size_t)bn);

        /* Read a login name. Character-at-a-time so we can echo it
         * (PTY default is canonical + echo, but some clients disable
         * echo; this makes the prompt visible consistently). Cap the
         * name to something sane. */
        char user[33];
        int upos = 0;
        while (upos < (int)sizeof(user) - 1) {
            char ch;
            ssize_t n = read(STDIN_FILENO, &ch, 1);
            if (n <= 0) _exit(1);
            if (ch == '\r' || ch == '\n') break;
            if (ch == 0x7f || ch == 0x08) {           /* backspace */
                if (upos > 0) { upos--; (void)!write(STDOUT_FILENO, "\b \b", 3); }
                continue;
            }
            /* Accept alnum + ._- only — typical POSIX username set. */
            if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                  (ch >= '0' && ch <= '9') ||
                   ch == '.' || ch == '_' || ch == '-'))
                continue;
            user[upos++] = ch;
        }
        user[upos] = '\0';
        (void)!write(STDOUT_FILENO, "\r\n", 2);
        if (upos == 0) _exit(1);

        /* Strip any lingering shell metacharacters defensively — the
         * above filter already rejected them, but belt-and-braces for
         * a value we are about to pass to /bin/su. */
        for (char *p = user; *p; p++) {
            if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                  (*p >= '0' && *p <= '9') ||
                   *p == '.' || *p == '_' || *p == '-')) {
                _exit(1);
            }
        }

        /* CRITICAL SECURITY STEP — drop privileges before exec'ing su.
         *
         * Portal runs as root. If we exec /bin/su while still root, su
         * sees our euid=0 and SKIPS the PAM password prompt entirely:
         * the user typing "monitor<Enter>" at our login prompt would
         * land in monitor's shell with zero authentication. That is a
         * full remote unauthenticated privilege escalation.
         *
         * Drop to an unprivileged account (nobody, UID 65534 as
         * fallback). /bin/su is SUID root so it still has the power to
         * become the target user AFTER it validates the password via
         * PAM — the setuid-to-nobody only strips the "caller is root"
         * exemption that lets su skip the auth step. */
        struct passwd *pw_nobody = getpwnam("nobody");
        uid_t nob_uid = pw_nobody ? pw_nobody->pw_uid : 65534;
        gid_t nob_gid = pw_nobody ? pw_nobody->pw_gid : 65534;
        if (setgroups(0, NULL) != 0 ||
            setgid(nob_gid) != 0 ||
            setuid(nob_uid) != 0) {
            /* If we can't drop privileges — we must NOT continue,
             * because exec'ing su as root would be the security bug
             * above. Print an error and exit; the dial-back session
             * closes cleanly on the other side. */
            dprintf(STDOUT_FILENO,
                "\r\nshell: failed to drop privileges (%s); aborting "
                "login for safety.\r\n", strerror(errno));
            _exit(1);
        }
        /* Also close any inherited listen/connection fds from the
         * parent (they are still visible via /proc/<pid>/fd). The
         * exec will close them via CLOEXEC if set — which Portal
         * doesn't guarantee — so be explicit. Keep 0/1/2 (PTY slave). */
        for (int cfd = 3; cfd < 1024; cfd++) close(cfd);

        const char *su_bin = g_cfg.shell_login_binary[0]
            ? g_cfg.shell_login_binary : "/bin/su";
        execl(su_bin, "su", "-l", user, (char *)NULL);
        /* Fallback never runs when we reach here as nobody — /bin/bash
         * wouldn't be useful, so just log the exec failure and exit. */
        dprintf(STDOUT_FILENO, "\r\nexec %s failed: %s\r\n",
                su_bin, strerror(errno));
        _exit(127);
    }

    g_core->log(g_core, PORTAL_LOG_INFO, "shell",
                "dial-back: session '%.8s...' /bin/login pid=%d",
                c->session_id, pid);

    /* 5. Relay PTY master ↔ TLS fd until either end closes. */
    tls_plain_relay(master_fd, fd, ssl_any);

    /* 6. Clean up child + TLS + socket. */
    kill(pid, SIGHUP);
    usleep(50000);
    kill(pid, SIGKILL);
    waitpid(pid, NULL, WNOHANG);
    close(master_fd);
#ifdef HAS_SSL
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
#endif
    close(fd);
    g_core->log(g_core, PORTAL_LOG_INFO, "shell",
                "dial-back: session '%.8s...' closed", c->session_id);
    free(c);
    return NULL;
}

/* Handler called on the target device when the initiator asks it to
 * dial back. Headers: session_id, reply_host, reply_port, [rows, cols].
 * Returns immediately — the heavy work runs in dialback_thread. */
static int handle_dialback_request(portal_core_t *core,
                                    const portal_msg_t *msg,
                                    portal_resp_t *resp)
{
    (void)core;
    const char *sid = NULL, *rhost = NULL, *rport_s = NULL;
    const char *rows_s = "24", *cols_s = "80";
    for (uint16_t i = 0; i < msg->header_count; i++) {
        if (!strcmp(msg->headers[i].key, "session_id")) sid = msg->headers[i].value;
        if (!strcmp(msg->headers[i].key, "reply_host")) rhost = msg->headers[i].value;
        if (!strcmp(msg->headers[i].key, "reply_port")) rport_s = msg->headers[i].value;
        if (!strcmp(msg->headers[i].key, "rows")) rows_s = msg->headers[i].value;
        if (!strcmp(msg->headers[i].key, "cols")) cols_s = msg->headers[i].value;
    }
    if (!sid || !rhost || !rport_s) {
        portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
        portal_resp_set_body(resp, "missing session_id/reply_host/reply_port\n", 41);
        return -1;
    }
    int port = atoi(rport_s);
    if (port <= 0 || port > 65535) {
        portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
        return -1;
    }
    dialback_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
        return -1;
    }
    snprintf(ctx->session_id, sizeof(ctx->session_id), "%s", sid);
    snprintf(ctx->reply_host, sizeof(ctx->reply_host), "%s", rhost);
    ctx->reply_port = port;
    ctx->rows = atoi(rows_s);
    ctx->cols = atoi(cols_s);

    pthread_t t;
    if (pthread_create(&t, NULL, dialback_thread, ctx) != 0) {
        free(ctx);
        portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
        return -1;
    }
    pthread_detach(t);

    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, "dialing\n", 8);
    return 0;
}

/* Handler called on the INITIATOR side by the CLI (or any caller) to open
 * a shell on a remote peer via the dial-back channel. Header: peer. Optional
 * headers: rows, cols, timeout. Returns the fd number (as ASCII body) that
 * the caller relays plaintext bytes to/from. */
static int handle_open_remote(portal_core_t *core,
                              const portal_msg_t *msg,
                              portal_resp_t *resp)
{
    if (g_listen_fd < 0) {
        portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
        portal_resp_set_body(resp,
            "shell dial-back listener not enabled (set shell_port in mod_shell.conf)\n", 72);
        return -1;
    }

    const char *peer = NULL;
    const char *rows_s = "24", *cols_s = "80";
    int wait_secs = g_cfg.shell_dial_timeout;
    for (uint16_t i = 0; i < msg->header_count; i++) {
        if (!strcmp(msg->headers[i].key, "peer")) peer = msg->headers[i].value;
        if (!strcmp(msg->headers[i].key, "rows")) rows_s = msg->headers[i].value;
        if (!strcmp(msg->headers[i].key, "cols")) cols_s = msg->headers[i].value;
        if (!strcmp(msg->headers[i].key, "timeout")) wait_secs = atoi(msg->headers[i].value);
    }
    if (!peer || !peer[0]) {
        portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
        portal_resp_set_body(resp, "missing header: peer\n", 21);
        return -1;
    }
    if (wait_secs < 1) wait_secs = 1;
    if (wait_secs > 60) wait_secs = 60;

    /* Determine the hostname/IP to tell the device to dial back to. */
    char host[128];
    if (g_cfg.shell_advertise_host[0]) {
        snprintf(host, sizeof(host), "%s", g_cfg.shell_advertise_host);
    } else if (resolve_self_ipv4(host, sizeof(host)) != 0) {
        portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
        portal_resp_set_body(resp,
            "cannot determine advertise host (set shell_advertise_host)\n", 60);
        return -1;
    }

    pending_shell_t *ps = calloc(1, sizeof(*ps));
    if (!ps) {
        portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
        return -1;
    }
    gen_session_id(ps->session_id, sizeof(ps->session_id));
    pthread_mutex_init(&ps->lock, NULL);
    pthread_cond_init(&ps->cond, NULL);
    ps->fd_out = -1;
    ps->created = time(NULL);
    pending_add(ps);

    /* Send /<peer>/shell/functions/dialback_request via federation. */
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    char path[256];
    snprintf(path, sizeof(path), "/%s/shell/functions/dialback_request", peer);
    portal_msg_set_path(m, path);
    portal_msg_set_method(m, PORTAL_METHOD_CALL);
    char port_s[8];
    snprintf(port_s, sizeof(port_s), "%d", g_cfg.shell_port);
    portal_msg_add_header(m, "session_id", ps->session_id);
    portal_msg_add_header(m, "reply_host", host);
    portal_msg_add_header(m, "reply_port", port_s);
    portal_msg_add_header(m, "rows", rows_s);
    portal_msg_add_header(m, "cols", cols_s);
    if (!m->ctx) m->ctx = calloc(1, sizeof(portal_ctx_t));
    if (m->ctx) {
        m->ctx->auth.user = strdup("root");
        m->ctx->auth.token = strdup("__federation__");
        portal_labels_add(&m->ctx->auth.labels, "root");
    }
    int rc = core->send(core, m, r);
    int remote_status = r ? r->status : -1;
    portal_msg_free(m);
    portal_resp_free(r);
    if (rc < 0 || remote_status != PORTAL_OK) {
        /* Take the pending entry out — no dial-back will come. */
        pending_shell_t *hit = pending_take(ps->session_id);
        if (hit) {
            pthread_mutex_destroy(&hit->lock);
            pthread_cond_destroy(&hit->cond);
            free(hit);
        }
        portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
        char err[128];
        int n = snprintf(err, sizeof(err),
                         "peer '%s' did not accept dial-back request (status=%d)\n",
                         peer, remote_status);
        portal_resp_set_body(resp, err, (size_t)n);
        return -1;
    }

    /* Wait on condvar for the accept_handler_thread to hand us a bridge fd. */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += wait_secs;
    int timeout = 0;
    pthread_mutex_lock(&ps->lock);
    while (!ps->ready) {
        int wr = pthread_cond_timedwait(&ps->cond, &ps->lock, &ts);
        if (wr == ETIMEDOUT) { timeout = 1; break; }
    }
    int fd = ps->fd_out;
    pthread_mutex_unlock(&ps->lock);

    if (timeout) {
        /* Take it out so a late dial-back doesn't crash. */
        pending_shell_t *hit = pending_take(ps->session_id);
        if (hit) {
            pthread_mutex_destroy(&hit->lock);
            pthread_cond_destroy(&hit->cond);
            free(hit);
        }
        portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
        portal_resp_set_body(resp, "dial-back timeout\n", 18);
        return -1;
    }
    if (fd < 0) {
        portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
        portal_resp_set_body(resp, "dial-back failed\n", 17);
        return -1;
    }

    /* Success — accept_handler_thread now owns ps and will free it when
     * the relay ends. Return fd to caller as ASCII body. */
    char body[16];
    int n = snprintf(body, sizeof(body), "%d", fd);
    portal_resp_set_status(resp, PORTAL_OK);
    portal_resp_set_body(resp, body, (size_t)n);
    core->log(core, PORTAL_LOG_INFO, "shell",
              "dial-back: opened shell to peer '%s' session '%.8s...' fd=%d",
              peer, ps->session_id, fd);
    return 0;
}

#ifdef HAS_SSL
static SSL_CTX *build_server_ctx(void)
{
    SSL_CTX *c = SSL_CTX_new(TLS_server_method());
    if (!c) return NULL;
    SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION);

    const char *cert = g_cfg.shell_tls_cert[0] ? g_cfg.shell_tls_cert : NULL;
    const char *key  = g_cfg.shell_tls_key[0]  ? g_cfg.shell_tls_key  : NULL;

    /* Fall back to the instance's federation cert if shell ones aren't set. */
    char fed_cert[256], fed_key[256];
    if (!cert || !key) {
        const char *c2 = g_core->config_get(g_core, "node", "cert_file");
        const char *k2 = g_core->config_get(g_core, "node", "key_file");
        if (c2) { snprintf(fed_cert, sizeof(fed_cert), "%s", c2); cert = fed_cert; }
        if (k2) { snprintf(fed_key,  sizeof(fed_key),  "%s", k2); key  = fed_key;  }
    }
    if (!cert || !key) {
        g_core->log(g_core, PORTAL_LOG_WARN, "shell",
                    "dial-back: no TLS cert configured — listener disabled");
        SSL_CTX_free(c);
        return NULL;
    }
    if (SSL_CTX_use_certificate_file(c, cert, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(c, key, SSL_FILETYPE_PEM) != 1) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "shell",
                    "dial-back: failed to load cert/key (%s / %s)", cert, key);
        SSL_CTX_free(c);
        return NULL;
    }
    return c;
}

static SSL_CTX *build_client_ctx(void)
{
    SSL_CTX *c = SSL_CTX_new(TLS_client_method());
    if (!c) return NULL;
    SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION);
    /* Dial-back validates session_id not peer identity — a self-signed
     * cert on the other end is fine; the pre-shared random session_id
     * is the authenticator. */
    SSL_CTX_set_verify(c, SSL_VERIFY_NONE, NULL);
    return c;
}
#endif

/* ── Lifecycle ── */

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(&g_cfg, 0, sizeof(g_cfg));
    memset(g_sessions, 0, sizeof(g_sessions));

    const char *v;
    v = core->config_get(core, "shell", "timeout");
    g_cfg.timeout = v ? atoi(v) : 10;
    if (g_cfg.timeout < 1) g_cfg.timeout = 1;
    if (g_cfg.timeout > 300) g_cfg.timeout = 300;

    v = core->config_get(core, "shell", "shell");
    snprintf(g_cfg.shell, sizeof(g_cfg.shell), "%s", v ? v : "/bin/bash");

    v = core->config_get(core, "shell", "allow_exec");
    g_cfg.allow_exec = v ? (strcmp(v, "true") == 0 || strcmp(v, "1") == 0 || strcmp(v, "yes") == 0) : 1;

    v = core->config_get(core, "shell", "max_output");
    g_cfg.max_output = v ? atoi(v) : 65536;

    v = core->config_get(core, "shell", "session_ttl");
    g_cfg.session_ttl = v ? atoi(v) : SHELL_SESSION_TTL;

    v = core->config_get(core, "shell", "access_label");
    snprintf(g_cfg.access_label, sizeof(g_cfg.access_label), "%s",
             v ? v : "root");

    /* Dial-back shell channel config. Default 2223 — 2222 is taken by
     * mod_ssh on most instances. Change this value in the config if your
     * deployment binds 2223 for something else. */
    v = core->config_get(core, "shell", "shell_port");
    g_cfg.shell_port = v ? atoi(v) : 2223;
    if (g_cfg.shell_port < 0 || g_cfg.shell_port > 65535) g_cfg.shell_port = 0;

    v = core->config_get(core, "shell", "shell_bind");
    snprintf(g_cfg.shell_bind, sizeof(g_cfg.shell_bind), "%s",
             v && *v ? v : "0.0.0.0");

    v = core->config_get(core, "shell", "shell_tls_cert");
    snprintf(g_cfg.shell_tls_cert, sizeof(g_cfg.shell_tls_cert), "%s", v ? v : "");

    v = core->config_get(core, "shell", "shell_tls_key");
    snprintf(g_cfg.shell_tls_key, sizeof(g_cfg.shell_tls_key), "%s", v ? v : "");

    v = core->config_get(core, "shell", "shell_advertise_host");
    snprintf(g_cfg.shell_advertise_host, sizeof(g_cfg.shell_advertise_host),
             "%s", v ? v : "");

    v = core->config_get(core, "shell", "shell_login_binary");
    snprintf(g_cfg.shell_login_binary, sizeof(g_cfg.shell_login_binary), "%s",
             v && *v ? v : "/bin/su");

    v = core->config_get(core, "shell", "shell_dial_timeout");
    g_cfg.shell_dial_timeout = v ? atoi(v) : 10;
    if (g_cfg.shell_dial_timeout < 1) g_cfg.shell_dial_timeout = 1;
    if (g_cfg.shell_dial_timeout > 60) g_cfg.shell_dial_timeout = 60;

#ifdef HAS_SSL
    if (g_cfg.shell_port > 0) {
        g_server_ssl_ctx = build_server_ctx();
        g_client_ssl_ctx = build_client_ctx();
    }
#endif

    /* Ignore SIGPIPE — the dial-back relay uses write() on sockets and
     * PTY masters; without this, a peer-closed socket or child-exited
     * PTY would kill the Portal process via SIGPIPE on the next write. */
    signal(SIGPIPE, SIG_IGN);

    /* Register paths */
    core->path_register(core, "/shell/functions/exec", "shell");
    core->path_set_access(core, "/shell/functions/exec", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/shell/functions/exec", "Execute a command (stateless). Header: cmd, optional: cwd, timeout");
    core->path_add_label(core, "/shell/functions/exec", g_cfg.access_label);

    core->path_register(core, "/shell/functions/open", "shell");
    core->path_set_access(core, "/shell/functions/open", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/shell/functions/open", "Open PTY session. Returns session_id. Optional headers: rows, cols");
    core->path_add_label(core, "/shell/functions/open", g_cfg.access_label);

    core->path_register(core, "/shell/functions/write", "shell");
    core->path_set_access(core, "/shell/functions/write", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/shell/functions/write", "Send input to PTY. Header: session. Body: raw bytes");
    core->path_add_label(core, "/shell/functions/write", g_cfg.access_label);

    core->path_register(core, "/shell/functions/read", "shell");
    core->path_set_access(core, "/shell/functions/read", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/shell/functions/read", "Read output from PTY. Header: session");
    core->path_add_label(core, "/shell/functions/read", g_cfg.access_label);

    core->path_register(core, "/shell/functions/close", "shell");
    core->path_set_access(core, "/shell/functions/close", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/shell/functions/close", "Close PTY session. Header: session");
    core->path_add_label(core, "/shell/functions/close", g_cfg.access_label);

    core->path_register(core, "/shell/functions/resize", "shell");
    core->path_set_access(core, "/shell/functions/resize", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/shell/functions/resize", "Resize PTY terminal. Headers: session, rows, cols");
    core->path_add_label(core, "/shell/functions/resize", g_cfg.access_label);

    /* Dial-back channel paths */
    core->path_register(core, "/shell/functions/open_remote", "shell");
    core->path_set_access(core, "/shell/functions/open_remote", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/shell/functions/open_remote",
        "Open a shell on a remote peer via dial-back. Header: peer. Returns fd (plaintext bridge end).");
    core->path_add_label(core, "/shell/functions/open_remote", g_cfg.access_label);

    core->path_register(core, "/shell/functions/dialback_request", "shell");
    core->path_set_access(core, "/shell/functions/dialback_request", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/shell/functions/dialback_request",
        "Remote-initiated: asks this host to dial back and run /bin/login in a PTY. Headers: session_id, reply_host, reply_port, rows, cols.");
    core->path_add_label(core, "/shell/functions/dialback_request", g_cfg.access_label);

    /* Events */
    portal_labels_t labels = {0};
    core->event_register(core, "/events/shell/exec", "Command executed", &labels);
    core->event_register(core, "/events/shell/session", "PTY session opened/closed", &labels);

    /* Session cleanup timer */
    core->timer_add(core, 60.0, maintenance_tick, core);

    /* Dial-back listener (if enabled) */
    start_listener();

    core->log(core, PORTAL_LOG_INFO, "shell",
              "v%s ready (PTY, timeout: %ds, shell: %s, max_sessions: %d, exec: %s, dial-back %s)",
              info.version, g_cfg.timeout, g_cfg.shell, SHELL_MAX_SESSIONS,
              g_cfg.allow_exec ? "enabled" : "DISABLED",
              g_cfg.shell_port > 0 ? "on" : "off");

    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    /* Stop dial-back listener FIRST — accept loop exits, no new connections. */
    stop_listener();

    /* Drop any pending shell requests — their accept threads won't run now. */
    pthread_mutex_lock(&g_pending_lock);
    while (g_pending_head) {
        pending_shell_t *n = g_pending_head->next;
        /* Wake any waiters so handle_open_remote can return instead of
         * blocking on the condvar forever. */
        pthread_mutex_lock(&g_pending_head->lock);
        g_pending_head->fd_out = -1;
        g_pending_head->ready = 1;
        pthread_cond_broadcast(&g_pending_head->cond);
        pthread_mutex_unlock(&g_pending_head->lock);
        g_pending_head = n;
    }
    pthread_mutex_unlock(&g_pending_lock);

#ifdef HAS_SSL
    if (g_server_ssl_ctx) { SSL_CTX_free(g_server_ssl_ctx); g_server_ssl_ctx = NULL; }
    if (g_client_ssl_ctx) { SSL_CTX_free(g_client_ssl_ctx); g_client_ssl_ctx = NULL; }
#endif

    /* Close all legacy PTY sessions */
    for (int i = 0; i < SHELL_MAX_SESSIONS; i++)
        session_close(&g_sessions[i]);

    core->path_unregister(core, "/shell/functions/exec");
    core->path_unregister(core, "/shell/functions/open");
    core->path_unregister(core, "/shell/functions/write");
    core->path_unregister(core, "/shell/functions/read");
    core->path_unregister(core, "/shell/functions/close");
    core->path_unregister(core, "/shell/functions/resize");
    core->path_unregister(core, "/shell/functions/open_remote");
    core->path_unregister(core, "/shell/functions/dialback_request");
    core->event_unregister(core, "/events/shell/exec");
    core->event_unregister(core, "/events/shell/session");

    core->log(core, PORTAL_LOG_INFO, "shell", "Unloaded");
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    const char *p = msg->path;
    if (strcmp(p, "/shell/functions/exec") == 0)               return handle_exec(core, msg, resp);
    if (strcmp(p, "/shell/functions/open") == 0)               return handle_open(core, msg, resp);
    if (strcmp(p, "/shell/functions/write") == 0)              return handle_write(core, msg, resp);
    if (strcmp(p, "/shell/functions/read") == 0)               return handle_read(core, msg, resp);
    if (strcmp(p, "/shell/functions/close") == 0)              return handle_close(core, msg, resp);
    if (strcmp(p, "/shell/functions/resize") == 0)             return handle_resize(core, msg, resp);
    if (strcmp(p, "/shell/functions/open_remote") == 0)        return handle_open_remote(core, msg, resp);
    if (strcmp(p, "/shell/functions/dialback_request") == 0)   return handle_dialback_request(core, msg, resp);

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
