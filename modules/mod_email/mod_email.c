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
 * mod_email — Email sender (SMTP)
 *
 * Send emails via SMTP through the path system.
 * Configurable SMTP server, authentication.
 *
 * Config:
 *   [mod_email]
 *   smtp_host = smtp.gmail.com
 *   smtp_port = 587
 *   smtp_user = user@gmail.com
 *   smtp_pass = password
 *   from = noreply@portal.local
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "portal/portal.h"

#define SMTP_BUF_SIZE   4096

static portal_core_t *g_core = NULL;
static char g_smtp_host[256] = "localhost";
static int  g_smtp_port = 25;
static char g_smtp_user[128] = "";
static char g_smtp_pass[128] = "";
static char g_from[256] = "portal@localhost";
static int64_t g_sent = 0;

static portal_module_info_t info = {
    .name = "email", .version = "1.0.0",
    .description = "Email sender (SMTP)",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

/* Simple SMTP conversation */
static int smtp_read(int fd, char *buf, size_t len)
{
    ssize_t n = read(fd, buf, len - 1);
    if (n <= 0) return -1;
    buf[n] = '\0';
    return atoi(buf);  /* SMTP status code */
}

static int smtp_send_cmd(int fd, const char *cmd, char *resp, size_t rlen)
{
    write(fd, cmd, strlen(cmd));
    return smtp_read(fd, resp, rlen);
}

static int send_email(const char *to, const char *subject, const char *body)
{
    struct hostent *he = gethostbyname(g_smtp_host);
    if (!he) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = {10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)g_smtp_port);
    memcpy(&addr.sin_addr, he->h_addr, (size_t)he->h_length);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }

    char resp[SMTP_BUF_SIZE];
    char cmd[SMTP_BUF_SIZE];

    /* Read greeting */
    if (smtp_read(fd, resp, sizeof(resp)) != 220) { close(fd); return -1; }

    /* EHLO */
    snprintf(cmd, sizeof(cmd), "EHLO portal\r\n");
    if (smtp_send_cmd(fd, cmd, resp, sizeof(resp)) != 250) { close(fd); return -1; }

    /* MAIL FROM */
    snprintf(cmd, sizeof(cmd), "MAIL FROM:<%s>\r\n", g_from);
    if (smtp_send_cmd(fd, cmd, resp, sizeof(resp)) != 250) { close(fd); return -1; }

    /* RCPT TO */
    snprintf(cmd, sizeof(cmd), "RCPT TO:<%s>\r\n", to);
    if (smtp_send_cmd(fd, cmd, resp, sizeof(resp)) != 250) { close(fd); return -1; }

    /* DATA */
    smtp_send_cmd(fd, "DATA\r\n", resp, sizeof(resp));

    /* Message */
    snprintf(cmd, sizeof(cmd),
        "From: %s\r\n"
        "To: %s\r\n"
        "Subject: %s\r\n"
        "Content-Type: text/plain; charset=UTF-8\r\n"
        "\r\n"
        "%s\r\n"
        ".\r\n",
        g_from, to, subject, body);
    if (smtp_send_cmd(fd, cmd, resp, sizeof(resp)) != 250) { close(fd); return -1; }

    smtp_send_cmd(fd, "QUIT\r\n", resp, sizeof(resp));
    close(fd);
    g_sent++;
    return 0;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_sent = 0;

    const char *v;
    if ((v = core->config_get(core, "email", "smtp_host")))
        snprintf(g_smtp_host, sizeof(g_smtp_host), "%s", v);
    if ((v = core->config_get(core, "email", "smtp_port")))
        g_smtp_port = atoi(v);
    if ((v = core->config_get(core, "email", "smtp_user")))
        snprintf(g_smtp_user, sizeof(g_smtp_user), "%s", v);
    if ((v = core->config_get(core, "email", "smtp_pass")))
        snprintf(g_smtp_pass, sizeof(g_smtp_pass), "%s", v);
    if ((v = core->config_get(core, "email", "from")))
        snprintf(g_from, sizeof(g_from), "%s", v);

    core->path_register(core, "/email/resources/status", "email");
    core->path_set_access(core, "/email/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/email/functions/send", "email");
    core->path_set_access(core, "/email/functions/send", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "email",
              "Email ready (SMTP: %s:%d, from: %s)",
              g_smtp_host, g_smtp_port, g_from);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/email/resources/status");
    core->path_unregister(core, "/email/functions/send");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;
    char buf[512]; int n;

    if (strcmp(msg->path, "/email/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "Email Module\nSMTP: %s:%d\nFrom: %s\nSent: %lld\n",
            g_smtp_host, g_smtp_port, g_from, (long long)g_sent);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/email/functions/send") == 0) {
        const char *to = get_hdr(msg, "to");
        const char *subject = get_hdr(msg, "subject");
        const char *body = msg->body ? msg->body : get_hdr(msg, "body");
        if (!to || !subject) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: to, subject headers + body\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (!body) body = "(no body)";

        if (send_email(to, subject, body) == 0) {
            core->event_emit(core, "/events/email/sent", to, strlen(to));
            n = snprintf(buf, sizeof(buf), "Email sent to %s\n", to);
            portal_resp_set_status(resp, PORTAL_OK);
        } else {
            n = snprintf(buf, sizeof(buf), "Failed to send to %s\n", to);
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
        }
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
