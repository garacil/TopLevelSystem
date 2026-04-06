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
 * mod_serial — RS232/serial port communication
 *
 * Open, configure, read, write serial ports via the path system.
 * Uses termios for POSIX serial configuration.
 * Supports baud rates from 1200 to 115200.
 *
 * Config:
 *   [mod_serial]
 *   max_ports = 16
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#include "portal/portal.h"

#define SERIAL_MAX_PORTS  16
#define SERIAL_BUF_SIZE   4096

typedef struct {
    char    device[128];
    int     fd;
    int     baud;
    int     active;
    int64_t bytes_rx;
    int64_t bytes_tx;
} serial_port_t;

static portal_core_t *g_core = NULL;
static serial_port_t  g_ports[SERIAL_MAX_PORTS];
static int            g_port_count = 0;
static int            g_max_ports = SERIAL_MAX_PORTS;

static portal_module_info_t info = {
    .name = "serial", .version = "1.0.0",
    .description = "RS232/serial port communication",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

static serial_port_t *find_port(const char *device)
{
    for (int i = 0; i < g_port_count; i++)
        if (g_ports[i].active && strcmp(g_ports[i].device, device) == 0)
            return &g_ports[i];
    return NULL;
}

/* Build lock resource path and owner string from message context */
static void lock_id(const char *device, char *resource, size_t rlen,
                    const portal_msg_t *msg, char *owner, size_t olen)
{
    snprintf(resource, rlen, "/serial/%s", device);
    const char *user = (msg->ctx && msg->ctx->auth.user) ? msg->ctx->auth.user : "?";
    snprintf(owner, olen, "%s", user);
}

/* Check/acquire lock for exclusive operations. Returns 0 if OK, -1 if blocked. */
static int check_lock(portal_core_t *core, const char *device,
                       const portal_msg_t *msg, portal_resp_t *resp)
{
    char resource[256], owner[128];
    lock_id(device, resource, sizeof(resource), msg, owner, sizeof(owner));

    if (core->resource_locked(core, resource)) {
        const char *cur = core->resource_owner(core, resource);
        if (!cur || strcmp(cur, owner) != 0) {
            portal_resp_set_status(resp, PORTAL_FORBIDDEN);
            char buf[256];
            int n = snprintf(buf, sizeof(buf), "Resource locked by: %s\n", cur ? cur : "?");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        /* Owner matches — refresh keepalive */
        core->resource_keepalive(core, resource, owner);
    } else {
        /* Auto-lock on first exclusive access */
        core->resource_lock(core, resource, owner);
    }
    return 0;
}

static speed_t baud_to_speed(int baud)
{
    switch (baud) {
    case 1200:   return B1200;
    case 2400:   return B2400;
    case 4800:   return B4800;
    case 9600:   return B9600;
    case 19200:  return B19200;
    case 38400:  return B38400;
    case 57600:  return B57600;
    case 115200: return B115200;
    default:     return B9600;
    }
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_ports, 0, sizeof(g_ports));
    g_port_count = 0;

    const char *v;
    if ((v = core->config_get(core, "serial", "max_ports")))
        g_max_ports = atoi(v);

    core->path_register(core, "/serial/resources/status", "serial");
    core->path_set_access(core, "/serial/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/serial/resources/ports", "serial");
    core->path_set_access(core, "/serial/resources/ports", PORTAL_ACCESS_READ);
    core->path_register(core, "/serial/functions/open", "serial");
    core->path_set_access(core, "/serial/functions/open", PORTAL_ACCESS_RW);
    core->path_register(core, "/serial/functions/close", "serial");
    core->path_set_access(core, "/serial/functions/close", PORTAL_ACCESS_RW);
    core->path_register(core, "/serial/functions/write", "serial");
    core->path_set_access(core, "/serial/functions/write", PORTAL_ACCESS_RW);
    core->path_register(core, "/serial/functions/read", "serial");
    core->path_set_access(core, "/serial/functions/read", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "serial",
              "Serial port module ready (max: %d ports)", g_max_ports);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    for (int i = 0; i < g_port_count; i++) {
        if (g_ports[i].active && g_ports[i].fd >= 0)
            close(g_ports[i].fd);
    }
    core->path_unregister(core, "/serial/resources/status");
    core->path_unregister(core, "/serial/resources/ports");
    core->path_unregister(core, "/serial/functions/open");
    core->path_unregister(core, "/serial/functions/close");
    core->path_unregister(core, "/serial/functions/write");
    core->path_unregister(core, "/serial/functions/read");
    core->log(core, PORTAL_LOG_INFO, "serial", "Serial module unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[SERIAL_BUF_SIZE];
    int n;

    if (strcmp(msg->path, "/serial/resources/status") == 0) {
        int active = 0;
        int64_t trx = 0, ttx = 0;
        for (int i = 0; i < g_port_count; i++) {
            if (!g_ports[i].active) continue;
            active++;
            trx += g_ports[i].bytes_rx;
            ttx += g_ports[i].bytes_tx;
        }
        n = snprintf(buf, sizeof(buf),
            "Serial Module\n"
            "Open ports: %d (max %d)\n"
            "Total RX: %lld bytes\n"
            "Total TX: %lld bytes\n",
            active, g_max_ports, (long long)trx, (long long)ttx);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/serial/resources/ports") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Serial Ports:\n");
        for (int i = 0; i < g_port_count; i++) {
            if (!g_ports[i].active) continue;
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "  %-20s baud: %d  rx: %lld  tx: %lld\n",
                g_ports[i].device, g_ports[i].baud,
                (long long)g_ports[i].bytes_rx,
                (long long)g_ports[i].bytes_tx);
        }
        if (g_port_count == 0)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/serial/functions/open") == 0) {
        const char *device = get_hdr(msg, "device");
        const char *baud_s = get_hdr(msg, "baud");
        if (!device) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: device header (e.g. /dev/ttyS0)\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (check_lock(core, device, msg, resp) < 0) return -1;
        if (find_port(device)) {
            portal_resp_set_status(resp, PORTAL_CONFLICT);
            n = snprintf(buf, sizeof(buf), "Port '%s' already open\n", device);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (g_port_count >= g_max_ports) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            n = snprintf(buf, sizeof(buf), "Max ports reached\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        int baud = baud_s ? atoi(baud_s) : 9600;
        int fd = open(device, O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (fd < 0) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            n = snprintf(buf, sizeof(buf), "Cannot open %s: %s\n",
                         device, strerror(errno));
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        /* Configure termios */
        struct termios tio;
        memset(&tio, 0, sizeof(tio));
        tio.c_cflag = (tcflag_t)(CS8 | CREAD | CLOCAL);
        tio.c_iflag = IGNPAR;
        speed_t spd = baud_to_speed(baud);
        cfsetispeed(&tio, spd);
        cfsetospeed(&tio, spd);
        tio.c_cc[VMIN] = 0;
        tio.c_cc[VTIME] = 10;  /* 1 second timeout */
        tcflush(fd, TCIFLUSH);
        tcsetattr(fd, TCSANOW, &tio);

        serial_port_t *port = &g_ports[g_port_count++];
        snprintf(port->device, sizeof(port->device), "%s", device);
        port->fd = fd;
        port->baud = baud;
        port->active = 1;
        port->bytes_rx = 0;
        port->bytes_tx = 0;

        core->event_emit(core, "/events/serial/open", device, strlen(device));
        portal_resp_set_status(resp, PORTAL_CREATED);
        n = snprintf(buf, sizeof(buf), "Opened %s at %d baud\n", device, baud);
        portal_resp_set_body(resp, buf, (size_t)n);
        core->log(core, PORTAL_LOG_INFO, "serial", "Opened %s at %d baud",
                  device, baud);
        return 0;
    }

    if (strcmp(msg->path, "/serial/functions/close") == 0) {
        const char *device = get_hdr(msg, "device");
        if (!device) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
        if (check_lock(core, device, msg, resp) < 0) return -1;
        serial_port_t *port = find_port(device);
        if (!port) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            return -1;
        }
        /* Release lock on close */
        char resource[256], owner[128];
        lock_id(device, resource, sizeof(resource), msg, owner, sizeof(owner));
        core->resource_unlock(core, resource, owner);
        close(port->fd);
        port->active = 0;
        core->event_emit(core, "/events/serial/close", device, strlen(device));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Closed %s\n", device);
        portal_resp_set_body(resp, buf, (size_t)n);
        core->log(core, PORTAL_LOG_INFO, "serial", "Closed %s", device);
        return 0;
    }

    if (strcmp(msg->path, "/serial/functions/write") == 0) {
        const char *device = get_hdr(msg, "device");
        const char *data = get_hdr(msg, "data");
        if (!data && msg->body) data = msg->body;
        if (!device || !data) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: device, data headers\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (check_lock(core, device, msg, resp) < 0) return -1;
        serial_port_t *port = find_port(device);
        if (!port) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            return -1;
        }
        ssize_t written = write(port->fd, data, strlen(data));
        if (written < 0) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            n = snprintf(buf, sizeof(buf), "Write error: %s\n", strerror(errno));
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        port->bytes_tx += written;
        core->event_emit(core, "/events/serial/write", device, strlen(device));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Wrote %zd bytes to %s\n", written, device);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/serial/functions/read") == 0) {
        const char *device = get_hdr(msg, "device");
        if (!device) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
        if (check_lock(core, device, msg, resp) < 0) return -1;
        serial_port_t *port = find_port(device);
        if (!port) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            return -1;
        }
        char rbuf[SERIAL_BUF_SIZE];
        ssize_t rd = read(port->fd, rbuf, sizeof(rbuf) - 1);
        if (rd < 0 && errno != EAGAIN) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            n = snprintf(buf, sizeof(buf), "Read error: %s\n", strerror(errno));
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (rd <= 0) {
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, "(no data)\n", 10);
            return 0;
        }
        port->bytes_rx += rd;
        rbuf[rd] = '\0';
        core->event_emit(core, "/events/serial/read", device, strlen(device));
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, rbuf, (size_t)rd);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
