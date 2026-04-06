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
 * mod_ssh — SSH Server for Portal CLI
 *
 * Provides SSH access to the Portal CLI. Any standard SSH client
 * (OpenSSH, PuTTY, etc.) can connect and get the interactive CLI.
 *
 * Authentication uses Portal's own user/password system.
 * After login, the user gets the same CLI as portal -r.
 *
 * Config:
 *   [mod_ssh]
 *   port = 2222
 *   host_key = /etc/portal/<instance>/certs/ssh_host_key
 *
 * Usage:
 *   ssh -p 2222 admin@host
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include "portal/portal.h"
#include "ev_config.h"
#include "ev.h"

#define SSH_DEFAULT_PORT    2222
#define SSH_MAX_CLIENTS     16
#define SSH_BUF_SIZE        4096

static portal_core_t *g_core = NULL;
static ssh_bind       g_sshbind = NULL;
static int            g_bind_fd = -1;
static int            g_port = SSH_DEFAULT_PORT;
static char           g_host_key[PORTAL_MAX_PATH_LEN] = "";
static volatile int   g_running = 1;

static portal_module_info_t info = {
    .name = "ssh", .version = "1.0.0",
    .description = "SSH server for remote CLI access",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

/* --- SSH client handler (runs in a thread) --- */

static int portal_ssh_auth(const char *user, const char *pass)
{
    /* Authenticate against Portal's auth system */
    portal_msg_t *msg = portal_msg_alloc();
    portal_resp_t *resp = portal_resp_alloc();
    if (!msg || !resp) return 0;

    portal_msg_set_path(msg, "/auth/login");
    portal_msg_set_method(msg, PORTAL_METHOD_CALL);
    portal_msg_add_header(msg, "username", user);
    portal_msg_add_header(msg, "password", pass);

    g_core->send(g_core, msg, resp);
    int ok = (resp->status == PORTAL_OK);

    portal_msg_free(msg);
    portal_resp_free(resp);
    return ok;
}

static void handle_ssh_client(ssh_session session)
{
    /* Key exchange */
    if (ssh_handle_key_exchange(session) != SSH_OK) {
        g_core->log(g_core, PORTAL_LOG_WARN, "ssh",
                    "Key exchange failed: %s", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }

    /* Authentication */
    ssh_message msg_ssh;
    int authenticated = 0;
    char username[64] = "";

    while ((msg_ssh = ssh_message_get(session)) != NULL) {
        if (ssh_message_type(msg_ssh) == SSH_REQUEST_AUTH &&
            ssh_message_subtype(msg_ssh) == SSH_AUTH_METHOD_PASSWORD) {
            const char *user = ssh_message_auth_user(msg_ssh);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
            const char *pass = ssh_message_auth_password(msg_ssh);
#pragma GCC diagnostic pop

            if (portal_ssh_auth(user, pass)) {
                ssh_message_auth_reply_success(msg_ssh, 0);
                snprintf(username, sizeof(username), "%s", user);
                authenticated = 1;
                ssh_message_free(msg_ssh);
                break;
            }
        }
        ssh_message_reply_default(msg_ssh);
        ssh_message_free(msg_ssh);
    }

    if (!authenticated) {
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }

    g_core->log(g_core, PORTAL_LOG_INFO, "ssh",
                "User '%s' authenticated via SSH", username);

    /* Wait for channel request */
    ssh_channel chan = NULL;
    while ((msg_ssh = ssh_message_get(session)) != NULL) {
        if (ssh_message_type(msg_ssh) == SSH_REQUEST_CHANNEL_OPEN &&
            ssh_message_subtype(msg_ssh) == SSH_CHANNEL_SESSION) {
            chan = ssh_message_channel_request_open_reply_accept(msg_ssh);
            ssh_message_free(msg_ssh);
            break;
        }
        ssh_message_reply_default(msg_ssh);
        ssh_message_free(msg_ssh);
    }

    if (!chan) {
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }

    /* Wait for shell or pty request */
    int got_shell = 0;
    while ((msg_ssh = ssh_message_get(session)) != NULL) {
        int type = ssh_message_type(msg_ssh);
        int subtype = ssh_message_subtype(msg_ssh);
        if (type == SSH_REQUEST_CHANNEL) {
            if (subtype == SSH_CHANNEL_REQUEST_SHELL ||
                subtype == SSH_CHANNEL_REQUEST_PTY) {
                ssh_message_channel_request_reply_success(msg_ssh);
                if (subtype == SSH_CHANNEL_REQUEST_SHELL)
                    got_shell = 1;
            } else {
                ssh_message_reply_default(msg_ssh);
            }
        } else {
            ssh_message_reply_default(msg_ssh);
        }
        ssh_message_free(msg_ssh);
        if (got_shell) break;
    }

    /* Send welcome banner */
    char banner[256];
    snprintf(banner, sizeof(banner),
        "\r\nPortal v" PORTAL_VERSION_STR " SSH CLI\r\n"
        "Logged in as %s\r\n\r\n", username);
    ssh_channel_write(chan, banner, (uint32_t)strlen(banner));

    /* Connect to local CLI socket and bridge */
    int cli_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cli_fd < 0) {
        ssh_channel_write(chan, "Cannot connect to CLI\r\n", 23);
        ssh_channel_close(chan);
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }

    /* Get socket path from config */
    const char *sock_path = g_core->config_get(g_core, "core", "socket_path");
    if (!sock_path) sock_path = "/var/run/portal.sock";

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);

    if (connect(cli_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        char err[128];
        snprintf(err, sizeof(err), "Cannot connect to CLI socket: %s\r\n",
                 strerror(errno));
        ssh_channel_write(chan, err, (uint32_t)strlen(err));
        close(cli_fd);
        ssh_channel_close(chan);
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }

    /* Auto-login on CLI */
    char login_cmd[128];
    snprintf(login_cmd, sizeof(login_cmd), "login %s portal\r\n", username);
    write(cli_fd, login_cmd, strlen(login_cmd));

    /* Bridge: SSH channel ↔ CLI socket */
    char buf[SSH_BUF_SIZE];
    fd_set rfds;
    int chan_fd = ssh_get_fd(session);

    while (g_running && ssh_channel_is_open(chan) && !ssh_channel_is_eof(chan)) {
        FD_ZERO(&rfds);
        FD_SET(cli_fd, &rfds);
        FD_SET(chan_fd, &rfds);
        int maxfd = cli_fd > chan_fd ? cli_fd : chan_fd;

        struct timeval tv = {1, 0};
        int sel = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) break;

        /* Data from CLI → SSH (translate \n to \r\n for terminal) */
        if (FD_ISSET(cli_fd, &rfds)) {
            char raw[SSH_BUF_SIZE];
            ssize_t n = read(cli_fd, raw, sizeof(raw) / 2);
            if (n <= 0) break;
            /* Convert \n to \r\n */
            size_t out = 0;
            for (ssize_t i = 0; i < n && out < sizeof(buf) - 2; i++) {
                if (raw[i] == '\n' && (i == 0 || raw[i-1] != '\r'))
                    buf[out++] = '\r';
                buf[out++] = raw[i];
            }
            ssh_channel_write(chan, buf, (uint32_t)out);
        }

        /* Data from SSH → CLI */
        if (ssh_channel_poll(chan, 0) > 0) {
            int n = ssh_channel_read_nonblocking(chan, buf, sizeof(buf), 0);
            if (n > 0) {
                write(cli_fd, buf, (size_t)n);
            } else if (n < 0) {
                break;
            }
        }
    }

    close(cli_fd);
    if (ssh_channel_is_open(chan))
        ssh_channel_close(chan);
    ssh_disconnect(session);
    ssh_free(session);

    g_core->log(g_core, PORTAL_LOG_INFO, "ssh",
                "User '%s' disconnected", username);
}

/* Thread wrapper */
static void *ssh_client_thread(void *arg)
{
    ssh_session session = (ssh_session)arg;
    handle_ssh_client(session);
    return NULL;
}

/* Accept new SSH connection */
static void on_ssh_accept(int fd, uint32_t events, void *userdata)
{
    (void)fd; (void)events; (void)userdata;

    ssh_session session = ssh_new();
    if (!session) return;

    if (ssh_bind_accept(g_sshbind, session) != SSH_OK) {
        g_core->log(g_core, PORTAL_LOG_WARN, "ssh",
                    "Accept failed: %s", ssh_get_error(g_sshbind));
        ssh_free(session);
        return;
    }

    /* Handle in a thread (SSH is blocking) */
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, ssh_client_thread, session);
    pthread_attr_destroy(&attr);
}

/* --- Module lifecycle --- */

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_running = 1;

    const char *v;
    if ((v = core->config_get(core, "ssh", "port")))
        g_port = atoi(v);
    if ((v = core->config_get(core, "ssh", "host_key")))
        snprintf(g_host_key, sizeof(g_host_key), "%s", v);

    /* Generate host key if not exists */
    if (g_host_key[0] == '\0') {
        const char *data_dir = core->config_get(core, "core", "data_dir");
        if (data_dir)
            snprintf(g_host_key, sizeof(g_host_key),
                     "%s/certs/ssh_host_key", data_dir);
        else
            snprintf(g_host_key, sizeof(g_host_key),
                     "/etc/portal/ssh_host_key");
    }

    /* Generate key if missing */
    if (access(g_host_key, F_OK) != 0) {
        char cmd[2048];
        snprintf(cmd, sizeof(cmd),
                 "ssh-keygen -t rsa -b 2048 -f %s -N '' -q 2>/dev/null",
                 g_host_key);
        system(cmd);
        core->log(core, PORTAL_LOG_INFO, "ssh",
                  "Generated SSH host key: %s", g_host_key);
    }

    /* Create SSH bind */
    g_sshbind = ssh_bind_new();
    if (!g_sshbind) {
        core->log(core, PORTAL_LOG_ERROR, "ssh", "ssh_bind_new() failed");
        return PORTAL_MODULE_FAIL;
    }

    ssh_bind_options_set(g_sshbind, SSH_BIND_OPTIONS_BINDPORT, &g_port);
    ssh_bind_options_set(g_sshbind, SSH_BIND_OPTIONS_RSAKEY, g_host_key);

    if (ssh_bind_listen(g_sshbind) < 0) {
        core->log(core, PORTAL_LOG_ERROR, "ssh",
                  "Cannot listen on port %d: %s",
                  g_port, ssh_get_error(g_sshbind));
        ssh_bind_free(g_sshbind);
        g_sshbind = NULL;
        return PORTAL_MODULE_FAIL;
    }

    /* Get the fd for event loop integration */
    g_bind_fd = ssh_bind_get_fd(g_sshbind);
    if (g_bind_fd >= 0)
        core->fd_add(core, g_bind_fd, EV_READ, on_ssh_accept, NULL);

    core->path_register(core, "/ssh/resources/status", "ssh");
    core->path_set_access(core, "/ssh/resources/status", PORTAL_ACCESS_READ);

    core->log(core, PORTAL_LOG_INFO, "ssh",
              "SSH server listening on port %d", g_port);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    g_running = 0;

    if (g_bind_fd >= 0) {
        core->fd_del(core, g_bind_fd);
        g_bind_fd = -1;
    }

    if (g_sshbind) {
        ssh_bind_free(g_sshbind);
        g_sshbind = NULL;
    }

    core->path_unregister(core, "/ssh/resources/status");
    core->log(core, PORTAL_LOG_INFO, "ssh", "SSH server stopped");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;

    if (strcmp(msg->path, "/ssh/resources/status") == 0) {
        char buf[256];
        int n = snprintf(buf, sizeof(buf),
            "SSH Server\nPort: %d\nHost key: %s\nStatus: listening\n",
            g_port, g_host_key);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
