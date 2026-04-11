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
 * mod_ldap — LDAP/Active Directory authentication
 *
 * Authenticate users against an LDAP server.
 * Search directory, bind test, user lookup.
 * Uses simple TCP LDAP bind (no TLS in this version).
 *
 * Config:
 *   [mod_ldap]
 *   server = ldap://localhost:389
 *   base_dn = dc=example,dc=com
 *   bind_dn = cn=admin,dc=example,dc=com
 *   bind_pass = secret
 *   user_filter = (uid=%s)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "portal/portal.h"

#define LDAP_BUF_SIZE  4096

static portal_core_t *g_core = NULL;
static char g_server[256] = "localhost";
static int  g_port = 389;
static char g_base_dn[256] = "dc=example,dc=com";
static char g_bind_dn[256] = "";
static char g_bind_pass[256] = "";
static char g_user_filter[256] = "(uid=%s)";
static int64_t g_auths = 0;
static int64_t g_failures = 0;

static portal_module_info_t info = {
    .name = "ldap", .version = "1.0.0",
    .description = "LDAP/Active Directory authentication",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

/* BER/LDAP encoding helpers for simple bind */
static int ber_encode_length(unsigned char *buf, int len)
{
    if (len < 128) { buf[0] = (unsigned char)len; return 1; }
    if (len < 256) { buf[0] = 0x81; buf[1] = (unsigned char)len; return 2; }
    buf[0] = 0x82;
    buf[1] = (unsigned char)(len >> 8);
    buf[2] = (unsigned char)(len & 0xFF);
    return 3;
}

/* Build a simple LDAP bind request */
static int build_bind_request(unsigned char *buf, size_t buflen,
                               const char *dn, const char *pass, int msg_id)
{
    unsigned char inner[2048];
    int pos = 0;

    /* MessageID (INTEGER) */
    inner[pos++] = 0x02; /* INTEGER tag */
    inner[pos++] = 0x01; /* length 1 */
    inner[pos++] = (unsigned char)msg_id;

    /* BindRequest (APPLICATION 0) */
    unsigned char bind[1024];
    int bpos = 0;

    /* version INTEGER 3 */
    bind[bpos++] = 0x02; bind[bpos++] = 0x01; bind[bpos++] = 3;

    /* name OCTET STRING */
    int dnlen = (int)strlen(dn);
    bind[bpos++] = 0x04;
    bpos += ber_encode_length(bind + bpos, dnlen);
    memcpy(bind + bpos, dn, (size_t)dnlen); bpos += dnlen;

    /* authentication CHOICE: simple [0] */
    int passlen = (int)strlen(pass);
    bind[bpos++] = 0x80; /* context tag 0 */
    bpos += ber_encode_length(bind + bpos, passlen);
    memcpy(bind + bpos, pass, (size_t)passlen); bpos += passlen;

    /* Wrap in APPLICATION 0 */
    inner[pos++] = 0x60; /* APPLICATION CONSTRUCTED 0 */
    pos += ber_encode_length(inner + pos, bpos);
    memcpy(inner + pos, bind, (size_t)bpos); pos += bpos;

    /* Wrap in SEQUENCE */
    if ((size_t)pos + 4 > buflen) return -1;
    int fpos = 0;
    buf[fpos++] = 0x30; /* SEQUENCE */
    fpos += ber_encode_length(buf + fpos, pos);
    memcpy(buf + fpos, inner, (size_t)pos); fpos += pos;

    return fpos;
}

/* Parse LDAP bind response, return result code */
static int parse_bind_response(const unsigned char *buf, int len)
{
    if (len < 10 || buf[0] != 0x30) return -1;
    /* Skip sequence header and message ID, find BindResponse (0x61) */
    for (int i = 2; i < len - 5; i++) {
        if (buf[i] == 0x61) {
            /* Find the result code INTEGER after the tag */
            for (int j = i + 2; j < len - 2; j++) {
                if (buf[j] == 0x0A && buf[j+1] == 0x01) /* ENUMERATED len=1 */
                    return buf[j+2];
            }
        }
    }
    return -1;
}

static int ldap_simple_bind(const char *dn, const char *pass)
{
    struct hostent *he = gethostbyname(g_server);
    if (!he) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)g_port);
    memcpy(&addr.sin_addr, he->h_addr, (size_t)he->h_length);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }

    unsigned char req[2048];
    int reqlen = build_bind_request(req, sizeof(req), dn, pass, 1);
    if (reqlen < 0 || write(fd, req, (size_t)reqlen) < 0) { close(fd); return -1; }

    unsigned char resp[LDAP_BUF_SIZE];
    ssize_t rd = read(fd, resp, sizeof(resp));
    close(fd);

    if (rd <= 0) return -1;
    return parse_bind_response(resp, (int)rd);
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_auths = g_failures = 0;

    const char *v;
    if ((v = core->config_get(core, "ldap", "server"))) {
        /* Parse ldap://host:port */
        const char *p = v;
        if (strncmp(p, "ldap://", 7) == 0) p += 7;
        const char *colon = strchr(p, ':');
        if (colon) {
            size_t hlen = (size_t)(colon - p);
            if (hlen >= sizeof(g_server)) hlen = sizeof(g_server) - 1;
            memcpy(g_server, p, hlen); g_server[hlen] = '\0';
            g_port = atoi(colon + 1);
        } else {
            snprintf(g_server, sizeof(g_server), "%s", p);
        }
    }
    if ((v = core->config_get(core, "ldap", "base_dn")))
        snprintf(g_base_dn, sizeof(g_base_dn), "%s", v);
    if ((v = core->config_get(core, "ldap", "bind_dn")))
        snprintf(g_bind_dn, sizeof(g_bind_dn), "%s", v);
    if ((v = core->config_get(core, "ldap", "bind_pass")))
        snprintf(g_bind_pass, sizeof(g_bind_pass), "%s", v);
    if ((v = core->config_get(core, "ldap", "user_filter")))
        snprintf(g_user_filter, sizeof(g_user_filter), "%s", v);

    core->path_register(core, "/ldap/resources/status", "ldap");
    core->path_set_access(core, "/ldap/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/ldap/resources/status", "LDAP client: server, port, base DN");
    core->path_register(core, "/ldap/functions/auth", "ldap");
    core->path_set_access(core, "/ldap/functions/auth", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/ldap/functions/auth", "LDAP authentication. Headers: user, password");
    core->path_register(core, "/ldap/functions/test", "ldap");
    core->path_set_access(core, "/ldap/functions/test", PORTAL_ACCESS_RW);
    core->path_add_label(core, "/ldap/functions/test", "admin");

    core->log(core, PORTAL_LOG_INFO, "ldap",
              "LDAP auth ready (server: %s:%d, base: %s)",
              g_server, g_port, g_base_dn);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/ldap/resources/status");
    core->path_unregister(core, "/ldap/functions/auth");
    core->path_unregister(core, "/ldap/functions/test");
    core->log(core, PORTAL_LOG_INFO, "ldap", "LDAP auth unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[4096];
    int n;

    if (strcmp(msg->path, "/ldap/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "LDAP Authentication\n"
            "Server: %s:%d\n"
            "Base DN: %s\n"
            "Bind DN: %s\n"
            "User filter: %s\n"
            "Auth attempts: %lld\n"
            "Failures: %lld\n",
            g_server, g_port, g_base_dn,
            g_bind_dn[0] ? g_bind_dn : "(anonymous)",
            g_user_filter,
            (long long)g_auths, (long long)g_failures);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/ldap/functions/auth") == 0) {
        const char *user = get_hdr(msg, "user");
        const char *pass = get_hdr(msg, "pass");
        if (!user || !pass) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: user, pass headers\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        /* Build user DN from filter */
        char user_dn[512];
        char filter[256];
        snprintf(filter, sizeof(filter), g_user_filter, user);
        /* Simple DN construction: uid=user,base_dn */
        snprintf(user_dn, sizeof(user_dn), "uid=%s,%s", user, g_base_dn);

        g_auths++;
        int rc = ldap_simple_bind(user_dn, pass);
        if (rc == 0) {
            core->event_emit(core, "/events/ldap/auth", user, strlen(user));
            n = snprintf(buf, sizeof(buf), "Authenticated: %s\n", user);
            portal_resp_set_status(resp, PORTAL_OK);
            core->log(core, PORTAL_LOG_INFO, "ldap", "Auth OK: %s", user);
        } else {
            g_failures++;
            n = snprintf(buf, sizeof(buf),
                "Authentication failed for %s (LDAP result: %d)\n", user, rc);
            portal_resp_set_status(resp, PORTAL_UNAUTHORIZED);
            core->log(core, PORTAL_LOG_WARN, "ldap", "Auth FAILED: %s (rc=%d)",
                      user, rc);
        }
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/ldap/functions/test") == 0) {
        /* Test connectivity with bind DN */
        const char *dn = g_bind_dn[0] ? g_bind_dn : "";
        const char *pass = g_bind_pass[0] ? g_bind_pass : "";
        int rc = ldap_simple_bind(dn, pass);
        if (rc == 0) {
            n = snprintf(buf, sizeof(buf),
                "LDAP connection test: OK\nServer: %s:%d\nBind DN: %s\n",
                g_server, g_port, dn[0] ? dn : "(anonymous)");
            portal_resp_set_status(resp, PORTAL_OK);
        } else if (rc == -1) {
            n = snprintf(buf, sizeof(buf),
                "LDAP connection test: FAILED (cannot connect to %s:%d)\n",
                g_server, g_port);
            portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
        } else {
            n = snprintf(buf, sizeof(buf),
                "LDAP connection test: BIND FAILED (result: %d)\nServer: %s:%d\n",
                rc, g_server, g_port);
            portal_resp_set_status(resp, PORTAL_UNAUTHORIZED);
        }
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
