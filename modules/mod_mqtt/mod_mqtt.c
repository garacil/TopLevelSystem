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
 * mod_mqtt — Lightweight MQTT Broker
 *
 * Accepts MQTT client connections and bridges topics
 * to Portal paths. MQTT publish → Portal event emit.
 * Portal events → MQTT subscribers.
 *
 * Config:
 *   [mod_mqtt]
 *   port = 1883
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "portal/portal.h"
#include "ev_config.h"
#include "ev.h"

#define MQTT_DEFAULT_PORT  1883
#define MQTT_MAX_CLIENTS   64
#define MQTT_BUF_SIZE      8192

/* MQTT packet types */
#define MQTT_CONNECT     1
#define MQTT_CONNACK     2
#define MQTT_PUBLISH     3
#define MQTT_SUBSCRIBE   8
#define MQTT_SUBACK      9
#define MQTT_PINGREQ    12
#define MQTT_PINGRESP   13
#define MQTT_DISCONNECT 14

typedef struct {
    int   fd;
    char  client_id[128];
    char  topics[16][256];
    int   topic_count;
    int   active;
} mqtt_client_t;

static portal_core_t *g_core = NULL;
static int            g_listen_fd = -1;
static int            g_port = MQTT_DEFAULT_PORT;
static mqtt_client_t  g_clients[MQTT_MAX_CLIENTS];
static int            g_client_count = 0;

static portal_module_info_t info = {
    .name = "mqtt", .version = "1.0.0",
    .description = "Lightweight MQTT broker",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static mqtt_client_t *find_mqtt_client(int fd)
{
    for (int i = 0; i < g_client_count; i++)
        if (g_clients[i].active && g_clients[i].fd == fd) return &g_clients[i];
    return NULL;
}

static void mqtt_send(int fd, const uint8_t *data, size_t len)
{
    write(fd, data, len);
}

static void mqtt_remove_client(int fd)
{
    mqtt_client_t *c = find_mqtt_client(fd);
    if (c) c->active = 0;
    g_core->fd_del(g_core, fd);
    close(fd);
}

/* Publish to all MQTT subscribers matching topic */
static void mqtt_publish_to_subs(const char *topic, const uint8_t *payload, size_t plen)
{
    for (int i = 0; i < g_client_count; i++) {
        if (!g_clients[i].active) continue;
        for (int t = 0; t < g_clients[i].topic_count; t++) {
            if (strcmp(g_clients[i].topics[t], topic) == 0 ||
                strcmp(g_clients[i].topics[t], "#") == 0) {
                /* Build PUBLISH packet */
                size_t tlen = strlen(topic);
                size_t total = 2 + tlen + plen;
                uint8_t header[4];
                size_t hlen = 0;
                header[hlen++] = 0x30;  /* PUBLISH, QoS 0 */
                if (total < 128) { header[hlen++] = (uint8_t)total; }
                else { header[hlen++] = (uint8_t)((total & 0x7F) | 0x80);
                       header[hlen++] = (uint8_t)(total >> 7); }
                write(g_clients[i].fd, header, hlen);
                uint8_t tl[2] = {(uint8_t)(tlen >> 8), (uint8_t)(tlen & 0xFF)};
                write(g_clients[i].fd, tl, 2);
                write(g_clients[i].fd, topic, tlen);
                if (plen > 0) write(g_clients[i].fd, payload, plen);
            }
        }
    }
}

static void on_mqtt_data(int fd, uint32_t events, void *userdata)
{
    (void)userdata;
    if (events & EV_ERROR) { mqtt_remove_client(fd); return; }

    uint8_t buf[MQTT_BUF_SIZE];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n <= 0) { mqtt_remove_client(fd); return; }

    uint8_t type = (buf[0] >> 4) & 0x0F;

    switch (type) {
    case MQTT_CONNECT: {
        /* Send CONNACK */
        uint8_t ack[] = {0x20, 0x02, 0x00, 0x00};
        mqtt_send(fd, ack, 4);
        mqtt_client_t *c = find_mqtt_client(fd);
        if (c)
            g_core->log(g_core, PORTAL_LOG_INFO, "mqtt", "Client connected (fd=%d)", fd);
        break;
    }
    case MQTT_SUBSCRIBE: {
        /* Parse topic from SUBSCRIBE packet */
        if (n < 7) break;
        uint16_t msg_id = ((uint16_t)buf[2] << 8) | buf[3];
        uint16_t tlen = ((uint16_t)buf[4] << 8) | buf[5];
        if (tlen > 0 && (size_t)(6 + tlen) <= (size_t)n) {
            char topic[256];
            size_t cplen = tlen < sizeof(topic) - 1 ? tlen : sizeof(topic) - 1;
            memcpy(topic, buf + 6, cplen);
            topic[cplen] = '\0';

            mqtt_client_t *c = find_mqtt_client(fd);
            if (c && c->topic_count < 16)
                snprintf(c->topics[c->topic_count++], 256, "%s", topic);

            g_core->log(g_core, PORTAL_LOG_DEBUG, "mqtt",
                        "Subscribe: %s (fd=%d)", topic, fd);
        }
        /* SUBACK */
        uint8_t suback[] = {0x90, 0x03, (uint8_t)(msg_id >> 8),
                             (uint8_t)(msg_id & 0xFF), 0x00};
        mqtt_send(fd, suback, 5);
        break;
    }
    case MQTT_PUBLISH: {
        /* Parse topic + payload */
        size_t rem_len = buf[1];
        size_t off = 2;
        if (rem_len > 127) { rem_len = ((buf[1] & 0x7F) | ((size_t)buf[2] << 7)); off = 3; }
        if (off + 2 > (size_t)n) break;
        uint16_t tlen = ((uint16_t)buf[off] << 8) | buf[off + 1];
        off += 2;
        char topic[256];
        size_t cplen = tlen < sizeof(topic) - 1 ? tlen : sizeof(topic) - 1;
        if (off + cplen > (size_t)n) break;
        memcpy(topic, buf + off, cplen);
        topic[cplen] = '\0';
        off += tlen;

        size_t plen = (size_t)n > off ? (size_t)n - off : 0;
        uint8_t *payload = plen > 0 ? buf + off : NULL;

        /* Forward to MQTT subscribers */
        mqtt_publish_to_subs(topic, payload, plen);

        /* Also emit as Portal event */
        if (payload && plen > 0)
            g_core->event_emit(g_core, topic, payload, plen);

        g_core->log(g_core, PORTAL_LOG_DEBUG, "mqtt",
                    "Publish: %s (%zu bytes)", topic, plen);
        break;
    }
    case MQTT_PINGREQ: {
        uint8_t pong[] = {0xD0, 0x00};
        mqtt_send(fd, pong, 2);
        break;
    }
    case MQTT_DISCONNECT:
        mqtt_remove_client(fd);
        break;
    }
}

static void on_mqtt_accept(int fd, uint32_t events, void *userdata)
{
    (void)events; (void)userdata;
    int client = accept(fd, NULL, NULL);
    if (client < 0) return;
    if (g_client_count >= MQTT_MAX_CLIENTS) { close(client); return; }

    mqtt_client_t *c = &g_clients[g_client_count++];
    memset(c, 0, sizeof(*c));
    c->fd = client; c->active = 1;
    g_core->fd_add(g_core, client, EV_READ, on_mqtt_data, NULL);
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_clients, 0, sizeof(g_clients));
    g_client_count = 0;

    const char *v = core->config_get(core, "mqtt", "port");
    if (v) g_port = atoi(v);

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) return PORTAL_MODULE_FAIL;
    int opt = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)g_port);
    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        core->log(core, PORTAL_LOG_ERROR, "mqtt", "bind(%d) failed", g_port);
        close(g_listen_fd); g_listen_fd = -1; return PORTAL_MODULE_FAIL;
    }
    listen(g_listen_fd, 16);
    core->fd_add(core, g_listen_fd, EV_READ, on_mqtt_accept, NULL);
    core->path_register(core, "/mqtt/resources/status", "mqtt");
    core->path_set_access(core, "/mqtt/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/mqtt/resources/status", "MQTT broker: port, connected clients, topics");
    core->path_register(core, "/mqtt/resources/clients", "mqtt");
    core->path_set_access(core, "/mqtt/resources/clients", PORTAL_ACCESS_READ);
    core->log(core, PORTAL_LOG_INFO, "mqtt", "MQTT broker on port %d", g_port);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    for (int i = 0; i < g_client_count; i++)
        if (g_clients[i].active) { core->fd_del(core, g_clients[i].fd); close(g_clients[i].fd); }
    if (g_listen_fd >= 0) { core->fd_del(core, g_listen_fd); close(g_listen_fd); }
    core->path_unregister(core, "/mqtt/resources/status");
    core->path_unregister(core, "/mqtt/resources/clients");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;
    char buf[4096]; int n;
    if (strcmp(msg->path, "/mqtt/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf), "MQTT Broker\nPort: %d\nClients: %d\n",
                     g_port, g_client_count);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }
    if (strcmp(msg->path, "/mqtt/resources/clients") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "MQTT Clients:\n");
        for (int i = 0; i < g_client_count; i++) {
            if (g_clients[i].active)
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "  fd=%d topics=%d\n", g_clients[i].fd, g_clients[i].topic_count);
        }
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
