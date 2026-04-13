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
#include <pty.h>
#include <time.h>
#include <termios.h>

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
} g_cfg;

static portal_core_t *g_core;
static shell_session_t g_sessions[SHELL_MAX_SESSIONS];
static int g_session_counter;

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

    /* Events */
    portal_labels_t labels = {0};
    core->event_register(core, "/events/shell/exec", "Command executed", &labels);
    core->event_register(core, "/events/shell/session", "PTY session opened/closed", &labels);

    /* Session cleanup timer */
    core->timer_add(core, 60.0, maintenance_tick, core);

    core->log(core, PORTAL_LOG_INFO, "shell",
              "v%s ready (PTY, timeout: %ds, shell: %s, max_sessions: %d, exec: %s)",
              info.version, g_cfg.timeout, g_cfg.shell, SHELL_MAX_SESSIONS,
              g_cfg.allow_exec ? "enabled" : "DISABLED");

    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    /* Close all sessions */
    for (int i = 0; i < SHELL_MAX_SESSIONS; i++)
        session_close(&g_sessions[i]);

    core->path_unregister(core, "/shell/functions/exec");
    core->path_unregister(core, "/shell/functions/open");
    core->path_unregister(core, "/shell/functions/write");
    core->path_unregister(core, "/shell/functions/read");
    core->path_unregister(core, "/shell/functions/close");
    core->path_unregister(core, "/shell/functions/resize");
    core->event_unregister(core, "/events/shell/exec");
    core->event_unregister(core, "/events/shell/session");

    core->log(core, PORTAL_LOG_INFO, "shell", "Unloaded");
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    const char *p = msg->path;
    if (strcmp(p, "/shell/functions/exec") == 0)   return handle_exec(core, msg, resp);
    if (strcmp(p, "/shell/functions/open") == 0)    return handle_open(core, msg, resp);
    if (strcmp(p, "/shell/functions/write") == 0)   return handle_write(core, msg, resp);
    if (strcmp(p, "/shell/functions/read") == 0)    return handle_read(core, msg, resp);
    if (strcmp(p, "/shell/functions/close") == 0)   return handle_close(core, msg, resp);
    if (strcmp(p, "/shell/functions/resize") == 0)  return handle_resize(core, msg, resp);

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
