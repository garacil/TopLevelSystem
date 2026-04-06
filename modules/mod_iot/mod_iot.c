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
 * mod_iot — Complete IoT device management
 *
 * Discover, identify, register, control, and monitor IoT devices.
 * Supports multiple protocols and brands through built-in drivers.
 *
 * Drivers:
 *   mqtt     — Tasmota, Shelly, Sonoff, Zigbee2MQTT (via mod_mqtt)
 *   http     — Shelly REST, Philips Hue, Wemo
 *   tapo     — TP-Link Tapo KLAP v2 protocol (SHA-1/SHA-256 auth, AES-CBC encrypt)
 *              Falls back to legacy AES securePassthrough for older firmware.
 *   tapo_hub — TP-Link Tapo Hub H200 (SSL + AES securePassthrough)
 *   gpio     — Direct GPIO relay control (via mod_gpio)
 *
 * Discovery:
 *   ARP scan       — MAC prefix → vendor identification (fping for speed)
 *   MQTT discovery — Tasmota/Shelly announce on connect
 *   HTTP probe     — Identify devices by HTTP response
 *
 * Tapo KLAP v2 protocol:
 *   1. Auth hash: SHA-256(SHA-1(email) + SHA-1(password))
 *   2. Handshake1: exchange local_seed ↔ remote_seed + server_hash
 *   3. Handshake2: send auth_hash, receive confirmation
 *   4. Derive keys: encrypt_key, decrypt_key, sig_key from seeds
 *   5. Request: AES-CBC encrypt → sign → POST /app/request?seq=N
 *   6. Response: verify signature → AES-CBC decrypt → JSON
 *   7. get_device_info returns: state, model, MAC, nickname (Base64)
 *
 * Device nicknames:
 *   Tapo firmware returns nicknames as Base64-encoded UTF-8.
 *   Decoded and stored as the device friendly name.
 *
 * Commands:
 *   iot discover <subnet> [brand]  — Scan LAN for devices
 *   iot devices                    — List all with name, model, state, MAC
 *   iot status <name>              — Live query via KLAP get_device_info
 *   iot refresh                    — Query all devices for live state
 *   iot on/off/toggle <name>       — Control device
 *   iot add/remove <name>          — Manual device management
 *
 * Config:
 *   [mod_iot]
 *   max_devices = 256
 *   poll_interval = 30
 *   tapo_email = user@tp-link.com
 *   tapo_password = secret
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dirent.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include "portal/portal.h"

#define IOT_MAX_DEVICES   256
#define IOT_BUF_SIZE      8192
#define IOT_POLL_SEC      30

/* ================================================================
 * Device types and driver IDs
 * ================================================================ */

typedef enum {
    IOT_DRIVER_MQTT = 0,
    IOT_DRIVER_HTTP,
    IOT_DRIVER_TAPO,
    IOT_DRIVER_TAPO_HUB,
    IOT_DRIVER_GPIO
} iot_driver_t;

typedef enum {
    IOT_BRAND_UNKNOWN = 0,
    IOT_BRAND_TASMOTA,
    IOT_BRAND_SHELLY,
    IOT_BRAND_SONOFF,
    IOT_BRAND_ZIGBEE,
    IOT_BRAND_TAPO,
    IOT_BRAND_HUE,
    IOT_BRAND_WEMO,
    IOT_BRAND_TUYA,
    IOT_BRAND_MEROSS,
    IOT_BRAND_GPIO
} iot_brand_t;

typedef enum {
    IOT_STATE_UNKNOWN = -1,
    IOT_STATE_OFF = 0,
    IOT_STATE_ON = 1
} iot_state_t;

typedef struct {
    char         name[64];
    char         ip[48];
    char         mac[20];
    iot_driver_t driver;
    iot_brand_t  brand;
    char         topic[256];      /* MQTT topic or HTTP URL */
    char         model[64];
    iot_state_t  state;
    double       power_watts;     /* energy monitoring */
    int64_t      last_seen;
    int          online;
    int          active;
} iot_device_t;

/* ================================================================
 * MAC vendor prefixes (top IoT manufacturers)
 * ================================================================ */

typedef struct { const char *prefix; const char *vendor; iot_brand_t brand; } mac_vendor_t;

static const mac_vendor_t g_mac_vendors[] = {
    {"A4:CF:12", "Shelly",        IOT_BRAND_SHELLY},
    {"E8:DB:84", "Shelly",        IOT_BRAND_SHELLY},
    {"EC:FA:BC", "Espressif",     IOT_BRAND_TASMOTA},
    {"24:A1:60", "Espressif",     IOT_BRAND_TASMOTA},
    {"AC:67:B2", "Espressif",     IOT_BRAND_TASMOTA},
    {"30:AE:A4", "Espressif",     IOT_BRAND_TASMOTA},
    {"24:0A:C4", "Espressif",     IOT_BRAND_TASMOTA},
    {"CC:50:E3", "Espressif",     IOT_BRAND_TASMOTA},
    {"84:CC:A8", "Espressif",     IOT_BRAND_TASMOTA},
    /* TP-Link / Tapo — verified OUI prefixes */
    {"48:22:54", "TP-Link",       IOT_BRAND_TAPO},
    {"54:AF:97", "TP-Link",       IOT_BRAND_TAPO},
    {"B0:A7:B9", "TP-Link",       IOT_BRAND_TAPO},
    {"60:32:B1", "TP-Link",       IOT_BRAND_TAPO},
    {"98:DA:C4", "TP-Link",       IOT_BRAND_TAPO},
    {"5C:A6:E6", "TP-Link",       IOT_BRAND_TAPO},
    {"1C:3B:F3", "TP-Link",       IOT_BRAND_TAPO},
    {"A8:42:A1", "TP-Link",       IOT_BRAND_TAPO},
    {"68:FF:7B", "TP-Link",       IOT_BRAND_TAPO},
    {"70:4F:57", "TP-Link",       IOT_BRAND_TAPO},
    {"30:DE:4B", "TP-Link",       IOT_BRAND_TAPO},
    {"E8:48:B8", "TP-Link",       IOT_BRAND_TAPO},
    {"14:EB:B6", "TP-Link",       IOT_BRAND_TAPO},
    {"50:C7:BF", "TP-Link",       IOT_BRAND_TAPO},
    {"78:8C:B5", "TP-Link",       IOT_BRAND_TAPO},
    {"3C:52:A1", "TP-Link",       IOT_BRAND_TAPO},
    {"AC:15:A2", "TP-Link",       IOT_BRAND_TAPO},
    {"8C:90:2D", "TP-Link",       IOT_BRAND_TAPO},
    {"50:91:E3", "TP-Link",       IOT_BRAND_TAPO},
    {"F0:A7:31", "TP-Link",       IOT_BRAND_TAPO},
    {"B0:19:21", "TP-Link",       IOT_BRAND_TAPO},
    {"24:2F:D0", "TP-Link",       IOT_BRAND_TAPO},
    {"00:17:88", "Philips",       IOT_BRAND_HUE},
    {"94:B9:7E", "Philips Hue",   IOT_BRAND_HUE},
    {"D0:73:D5", "Sonoff",        IOT_BRAND_SONOFF},
    {"DC:4F:22", "Tuya",          IOT_BRAND_TUYA},
    {"10:D5:61", "Tuya",          IOT_BRAND_TUYA},
    {"7C:F6:66", "Tuya",          IOT_BRAND_TUYA},
    {"48:3F:DA", "Meross",        IOT_BRAND_MEROSS},
    {NULL, NULL, IOT_BRAND_UNKNOWN}
};

/* ================================================================
 * Globals
 * ================================================================ */

static portal_core_t *g_core = NULL;
static iot_device_t   g_devices[IOT_MAX_DEVICES];
static int            g_count = 0;
static int            g_max = IOT_MAX_DEVICES;
static int            g_poll_interval = IOT_POLL_SEC;
static char           g_tapo_email[128] = "";
static char           g_tapo_pass[128] = "";
static char           g_iot_dir[512] = "";  /* /etc/portal/<instance>/iot/ */
static int64_t        g_discovered = 0;
static int64_t        g_commands = 0;

static portal_module_info_t info = {
    .name = "iot", .version = "1.0.0",
    .description = "IoT device discovery, control, and monitoring",
    .soft_deps = (const char *[]){"mqtt", "http_client", "cache", NULL}
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

/* ================================================================
 * Helper: identify brand from MAC prefix
 * ================================================================ */

static iot_brand_t identify_mac(const char *mac, const char **vendor_out)
{
    for (int i = 0; g_mac_vendors[i].prefix; i++) {
        if (strncasecmp(mac, g_mac_vendors[i].prefix, 8) == 0) {
            if (vendor_out) *vendor_out = g_mac_vendors[i].vendor;
            return g_mac_vendors[i].brand;
        }
    }
    if (vendor_out) *vendor_out = "Unknown";
    return IOT_BRAND_UNKNOWN;
}

static const char *brand_name(iot_brand_t b)
{
    switch (b) {
    case IOT_BRAND_TASMOTA: return "Tasmota";
    case IOT_BRAND_SHELLY:  return "Shelly";
    case IOT_BRAND_SONOFF:  return "Sonoff";
    case IOT_BRAND_ZIGBEE:  return "Zigbee";
    case IOT_BRAND_TAPO:    return "Tapo";
    case IOT_BRAND_HUE:     return "Hue";
    case IOT_BRAND_WEMO:    return "Wemo";
    case IOT_BRAND_TUYA:    return "Tuya";
    case IOT_BRAND_MEROSS:  return "Meross";
    case IOT_BRAND_GPIO:    return "GPIO";
    default:                return "Unknown";
    }
}

static const char *driver_name(iot_driver_t d)
{
    switch (d) {
    case IOT_DRIVER_MQTT:     return "mqtt";
    case IOT_DRIVER_HTTP:     return "http";
    case IOT_DRIVER_TAPO:     return "tapo";
    case IOT_DRIVER_TAPO_HUB: return "tapo_hub";
    case IOT_DRIVER_GPIO:     return "gpio";
    default:                  return "?";
    }
}

static const char *state_name(iot_state_t s)
{
    switch (s) {
    case IOT_STATE_ON:  return "ON";
    case IOT_STATE_OFF: return "OFF";
    default:            return "?";
    }
}

/* Forward declarations */
static int device_save(iot_device_t *d);

/* ================================================================
 * Device registry
 * ================================================================ */

static iot_device_t *find_device(const char *name)
{
    /* Search by name first, then topic, then IP */
    for (int i = 0; i < g_count; i++)
        if (g_devices[i].active && strcmp(g_devices[i].name, name) == 0)
            return &g_devices[i];
    for (int i = 0; i < g_count; i++)
        if (g_devices[i].active && strcmp(g_devices[i].topic, name) == 0)
            return &g_devices[i];
    for (int i = 0; i < g_count; i++)
        if (g_devices[i].active && strcmp(g_devices[i].ip, name) == 0)
            return &g_devices[i];
    return NULL;
}

static iot_device_t *find_device_by_ip(const char *ip)
{
    for (int i = 0; i < g_count; i++)
        if (g_devices[i].active && strcmp(g_devices[i].ip, ip) == 0)
            return &g_devices[i];
    return NULL;
}

static iot_device_t *register_device(const char *name, const char *ip,
                                      iot_driver_t driver, iot_brand_t brand)
{
    if (g_count >= g_max) return NULL;
    if (find_device(name)) return NULL;

    iot_device_t *d = &g_devices[g_count++];
    memset(d, 0, sizeof(*d));
    snprintf(d->name, sizeof(d->name), "%s", name);
    snprintf(d->ip, sizeof(d->ip), "%s", ip);
    d->driver = driver;
    d->brand = brand;
    d->state = IOT_STATE_UNKNOWN;
    d->online = 1;
    d->last_seen = (int64_t)time(NULL);
    d->active = 1;
    g_discovered++;

    /* Auto-save to config file */
    device_save(d);

    return d;
}

/* ================================================================
 * Persistence: save/load/delete device config files
 *
 * Device files stored in /etc/portal/<instance>/iot/<name>.conf
 * One file per device, human-readable, fully commented (Law 11).
 * Loaded on module startup, saved on add/discover, deleted on remove.
 * ================================================================ */

static int device_save(iot_device_t *d)
{
    if (g_iot_dir[0] == '\0') return -1;

    char path[600];
    snprintf(path, sizeof(path), "%s/%s.conf", g_iot_dir, d->name);

    FILE *f = fopen(path, "w");
    if (!f) return -1;

    /* Get current time for the header */
    char ts[32];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);

    fprintf(f,
        "# ═══════════════════════════════════════════════════════════\n"
        "# IoT Device: %s\n"
        "# ═══════════════════════════════════════════════════════════\n"
        "#\n"
        "# name    : Device name (used in CLI: iot on %s)\n"
        "# ip      : Device IP address on the local network\n"
        "# mac     : MAC address (auto-detected during discovery)\n"
        "# driver  : Communication protocol\n"
        "#           mqtt  — Tasmota, Shelly, Sonoff, Zigbee2MQTT\n"
        "#           http  — Shelly REST, Philips Hue\n"
        "#           tapo  — TP-Link Tapo (AES encrypted)\n"
        "#           gpio  — Direct GPIO relay\n"
        "# brand   : Device brand (tasmota|shelly|sonoff|zigbee|tapo|hue|tuya|meross|gpio)\n"
        "# topic   : MQTT topic prefix or device identifier\n"
        "# model   : Device model (auto-detected or manual)\n"
        "# enabled : true = load on startup, false = ignore\n"
        "#\n"
        "# Last updated: %s\n"
        "# ═══════════════════════════════════════════════════════════\n"
        "\n"
        "name    = %s\n"
        "ip      = %s\n"
        "mac     = %s\n"
        "driver  = %s\n"
        "brand   = %s\n"
        "topic   = %s\n"
        "model   = %s\n"
        "enabled = true\n",
        d->name, d->name, ts,
        d->name, d->ip, d->mac[0] ? d->mac : "",
        driver_name(d->driver), brand_name(d->brand),
        d->topic, d->model[0] ? d->model : "");

    fclose(f);
    return 0;
}

static int device_delete(const char *name)
{
    if (g_iot_dir[0] == '\0') return -1;
    char path[600];
    snprintf(path, sizeof(path), "%s/%s.conf", g_iot_dir, name);
    return unlink(path);
}

static iot_brand_t parse_brand(const char *s)
{
    if (!s || !s[0]) return IOT_BRAND_UNKNOWN;
    if (strcasecmp(s, "Tasmota") == 0) return IOT_BRAND_TASMOTA;
    if (strcasecmp(s, "Shelly") == 0)  return IOT_BRAND_SHELLY;
    if (strcasecmp(s, "Sonoff") == 0)  return IOT_BRAND_SONOFF;
    if (strcasecmp(s, "Zigbee") == 0)  return IOT_BRAND_ZIGBEE;
    if (strcasecmp(s, "Tapo") == 0)    return IOT_BRAND_TAPO;
    if (strcasecmp(s, "Hue") == 0)     return IOT_BRAND_HUE;
    if (strcasecmp(s, "Wemo") == 0)    return IOT_BRAND_WEMO;
    if (strcasecmp(s, "Tuya") == 0)    return IOT_BRAND_TUYA;
    if (strcasecmp(s, "Meross") == 0)  return IOT_BRAND_MEROSS;
    if (strcasecmp(s, "GPIO") == 0)    return IOT_BRAND_GPIO;
    return IOT_BRAND_UNKNOWN;
}

static iot_driver_t parse_driver(const char *s)
{
    if (!s || !s[0]) return IOT_DRIVER_MQTT;
    if (strcmp(s, "http") == 0) return IOT_DRIVER_HTTP;
    if (strcmp(s, "tapo") == 0) return IOT_DRIVER_TAPO;
    if (strcmp(s, "tapo_hub") == 0) return IOT_DRIVER_TAPO_HUB;
    if (strcmp(s, "gpio") == 0) return IOT_DRIVER_GPIO;
    return IOT_DRIVER_MQTT;
}

static int devices_load_all(portal_core_t *core)
{
    if (g_iot_dir[0] == '\0') return 0;

    DIR *d = opendir(g_iot_dir);
    if (!d) return 0;

    int loaded = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        size_t nlen = strlen(ent->d_name);
        if (nlen < 6 || strcmp(ent->d_name + nlen - 5, ".conf") != 0)
            continue;

        char path[800];
        snprintf(path, sizeof(path), "%s/%s", g_iot_dir, ent->d_name);

        /* Parse the device config file */
        FILE *f = fopen(path, "r");
        if (!f) continue;

        char name[64] = "", ip[48] = "", mac[20] = "";
        char drv_s[16] = "", brand_s[16] = "", topic[256] = "", model[64] = "";
        int enabled = 1;
        char line[512];

        while (fgets(line, sizeof(line), f)) {
            /* Trim */
            char *s = line;
            while (*s == ' ' || *s == '\t') s++;
            if (*s == '#' || *s == '\0' || *s == '\n') continue;

            char *eq = strchr(s, '=');
            if (!eq) continue;
            *eq = '\0';

            /* Trim key and value */
            char *key = s;
            char *val = eq + 1;
            while (*key && (key[strlen(key)-1] == ' ')) key[strlen(key)-1] = '\0';
            while (*val == ' ') val++;
            char *nl = strchr(val, '\n');
            if (nl) *nl = '\0';
            /* Trim trailing spaces from value */
            size_t vl = strlen(val);
            while (vl > 0 && val[vl-1] == ' ') val[--vl] = '\0';

            if (strcmp(key, "name") == 0) snprintf(name, sizeof(name), "%s", val);
            else if (strcmp(key, "ip") == 0) snprintf(ip, sizeof(ip), "%s", val);
            else if (strcmp(key, "mac") == 0) snprintf(mac, sizeof(mac), "%s", val);
            else if (strcmp(key, "driver") == 0) snprintf(drv_s, sizeof(drv_s), "%s", val);
            else if (strcmp(key, "brand") == 0) snprintf(brand_s, sizeof(brand_s), "%s", val);
            else if (strcmp(key, "topic") == 0) snprintf(topic, sizeof(topic), "%s", val);
            else if (strcmp(key, "model") == 0) snprintf(model, sizeof(model), "%s", val);
            else if (strcmp(key, "enabled") == 0)
                enabled = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
        }
        fclose(f);

        if (!enabled || name[0] == '\0' || ip[0] == '\0') continue;
        if (find_device(name)) continue;  /* already loaded */

        iot_device_t *dev = register_device(name, ip,
                                             parse_driver(drv_s),
                                             parse_brand(brand_s));
        if (dev) {
            snprintf(dev->mac, sizeof(dev->mac), "%s", mac);
            snprintf(dev->topic, sizeof(dev->topic), "%s",
                     topic[0] ? topic : name);
            snprintf(dev->model, sizeof(dev->model), "%s", model);
            loaded++;
        }
    }
    closedir(d);

    if (loaded > 0)
        core->log(core, PORTAL_LOG_INFO, "iot",
                  "Loaded %d devices from %s", loaded, g_iot_dir);
    return loaded;
}

/* ================================================================
 * Driver: MQTT (Tasmota, Shelly, Sonoff, Zigbee2MQTT)
 * ================================================================ */

static int mqtt_send(portal_core_t *core, const char *topic, const char *payload)
{
    if (!core->module_loaded(core, "mqtt")) return -1;

    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (!m || !r) { portal_msg_free(m); portal_resp_free(r); return -1; }

    portal_msg_set_path(m, "/mqtt/functions/publish");
    portal_msg_set_method(m, PORTAL_METHOD_CALL);
    portal_msg_add_header(m, "topic", topic);
    portal_msg_add_header(m, "data", payload);
    core->send(core, m, r);
    int rc = (r->status == PORTAL_OK) ? 0 : -1;
    portal_msg_free(m); portal_resp_free(r);
    return rc;
}

static int mqtt_command(portal_core_t *core, iot_device_t *d, const char *cmd)
{
    char topic[512];
    const char *payload = cmd;

    switch (d->brand) {
    case IOT_BRAND_TASMOTA:
    case IOT_BRAND_SONOFF:
        /* Tasmota: cmnd/<device>/POWER <ON|OFF|TOGGLE> */
        snprintf(topic, sizeof(topic), "cmnd/%s/POWER", d->topic);
        break;
    case IOT_BRAND_SHELLY:
        /* Shelly MQTT: shellies/<id>/relay/0/command <on|off|toggle> */
        snprintf(topic, sizeof(topic), "shellies/%s/relay/0/command", d->topic);
        /* Shelly uses lowercase */
        if (strcmp(cmd, "ON") == 0) payload = "on";
        else if (strcmp(cmd, "OFF") == 0) payload = "off";
        else payload = "toggle";
        break;
    case IOT_BRAND_ZIGBEE:
        /* Zigbee2MQTT: zigbee2mqtt/<device>/set {"state":"ON"} */
        snprintf(topic, sizeof(topic), "zigbee2mqtt/%s/set", d->topic);
        {
            static char zbuf[128];
            snprintf(zbuf, sizeof(zbuf), "{\"state\":\"%s\"}", cmd);
            payload = zbuf;
        }
        break;
    default:
        snprintf(topic, sizeof(topic), "%s", d->topic);
    }

    return mqtt_send(core, topic, payload);
}

/* ================================================================
 * Driver: HTTP (Shelly REST, Hue)
 * ================================================================ */

static int http_get(const char *url, char *out, size_t outlen)
{
    /* Simple HTTP GET using raw sockets */
    char host[256], path[512];
    int port = 80;

    const char *p = url;
    if (strncmp(p, "http://", 7) == 0) p += 7;
    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');

    if (colon && (!slash || colon < slash)) {
        size_t hl = (size_t)(colon - p);
        memcpy(host, p, hl); host[hl] = '\0';
        port = atoi(colon + 1);
    } else if (slash) {
        size_t hl = (size_t)(slash - p);
        memcpy(host, p, hl); host[hl] = '\0';
    } else {
        snprintf(host, sizeof(host), "%s", p);
    }
    if (slash) snprintf(path, sizeof(path), "%s", slash);
    else snprintf(path, sizeof(path), "/");

    struct hostent *he = gethostbyname(host);
    if (!he) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    memcpy(&addr.sin_addr, he->h_addr, (size_t)he->h_length);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }

    char req[1024];
    int rlen = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
        path, host);
    write(fd, req, (size_t)rlen);

    size_t total = 0;
    ssize_t rd;
    while ((rd = read(fd, out + total, outlen - total - 1)) > 0)
        total += (size_t)rd;
    out[total] = '\0';
    close(fd);

    /* Skip headers */
    char *body = strstr(out, "\r\n\r\n");
    if (body) {
        body += 4;
        size_t blen = total - (size_t)(body - out);
        memmove(out, body, blen);
        out[blen] = '\0';
        return (int)blen;
    }
    return (int)total;
}

static int http_command(iot_device_t *d, const char *cmd)
{
    char url[512], buf[IOT_BUF_SIZE];
    int on = (strcmp(cmd, "ON") == 0);

    switch (d->brand) {
    case IOT_BRAND_SHELLY:
        snprintf(url, sizeof(url), "http://%s/relay/0?turn=%s",
                 d->ip, on ? "on" : "off");
        break;
    case IOT_BRAND_HUE:
        /* Hue needs PUT — simplified GET toggle for now */
        snprintf(url, sizeof(url), "http://%s/api/status", d->ip);
        break;
    default:
        snprintf(url, sizeof(url), "http://%s/", d->ip);
    }

    return http_get(url, buf, sizeof(buf));
}

/* ================================================================
 * Driver: Tapo (full KLAP or AES protocol, pure C + OpenSSL)
 *
 * Tapo P100/P110/L510/L530 use KLAP v2 protocol (firmware 1.3+):
 *   1. POST /app/handshake1 → seed exchange (SHA-256 based)
 *   2. POST /app/handshake2 → session confirmation
 *   3. POST /app/request    → encrypted command (AES-CBC + SHA-256)
 *
 * Older firmware uses AES protocol:
 *   1. POST /app → RSA handshake → get AES key
 *   2. POST /app → AES login → get token
 *   3. POST /app?token=X → AES encrypted command
 *
 * We try KLAP first, fall back to legacy AES.
 * ================================================================ */

/* Base64 encode for Tapo protocol */
static int __attribute__((unused)) tapo_b64_encode(const unsigned char *in, int inlen, char *out, int outlen)
{
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j = 0;
    for (i = 0; i + 2 < inlen && j + 4 < outlen; i += 3) {
        out[j++] = t[(in[i] >> 2) & 0x3F];
        out[j++] = t[((in[i] & 0x3) << 4) | ((in[i+1] >> 4) & 0xF)];
        out[j++] = t[((in[i+1] & 0xF) << 2) | ((in[i+2] >> 6) & 0x3)];
        out[j++] = t[in[i+2] & 0x3F];
    }
    if (i < inlen && j + 4 < outlen) {
        out[j++] = t[(in[i] >> 2) & 0x3F];
        if (i + 1 < inlen) {
            out[j++] = t[((in[i] & 0x3) << 4) | ((in[i+1] >> 4) & 0xF)];
            out[j++] = t[(in[i+1] & 0xF) << 2];
        } else {
            out[j++] = t[(in[i] & 0x3) << 4];
            out[j++] = '=';
        }
        out[j++] = '=';
    }
    out[j] = '\0';
    return j;
}

/* TCP POST helper for Tapo KLAP/AES protocol
 *
 * Sends an HTTP POST to a Tapo device and returns the response body.
 * Used for all three KLAP steps (handshake1, handshake2, request) and
 * for legacy AES protocol communication.
 *
 * Response body is binary (KLAP uses raw bytes, not JSON), so resp_out
 * is unsigned char* to avoid sign issues with binary seed/cipher data.
 *
 * Reading strategy: first read until headers complete (\r\n\r\n), then
 * parse Content-Length and read exactly that many body bytes. This avoids
 * waiting for the 5-second Connection:close timeout that would block
 * Portal's single-threaded event loop.
 *
 * Cookie handling: Tapo sends "TP_SESSIONID=XXX;TIMEOUT=86400" but only
 * the "TP_SESSIONID=XXX" part should be sent back — attributes after ';'
 * are stripped. Sending the full string causes handshake2 to return 400.
 *
 * Returns: body length on success, -1 on connection/protocol error.
 *          HTTP status code returned via *status_out (caller checks this).
 *          Session cookie (key=value only) returned via cookie_out.
 */
static int tapo_http_post(const char *ip, const char *path, const char *cookie,
                           const unsigned char *body, int body_len,
                           unsigned char *resp_out, int resp_max,
                           char *cookie_out, int cookie_max,
                           int *status_out)
{
    if (status_out) *status_out = 0;

    /* Resolve hostname and connect to port 80 */
    struct hostent *he = gethostbyname(ip);
    if (!he) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* 5-second timeout protects against unresponsive devices */
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    memcpy(&addr.sin_addr, he->h_addr, (size_t)he->h_length);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }

    /* Build HTTP POST request.
     * Connection: close tells the server to close after responding,
     * but we don't rely on that — we read by Content-Length instead.
     * Cookie header is only added when a session cookie is provided
     * (handshake2 and request steps need the TP_SESSIONID from hs1). */
    char hdr[1024];
    int hlen = snprintf(hdr, sizeof(hdr),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "%s%s%s"
        "\r\n",
        path, ip, body_len,
        cookie ? "Cookie: " : "",
        cookie ? cookie : "",
        cookie ? "\r\n" : "");

    /* Send header + body */
    write(fd, hdr, (size_t)hlen);
    if (body_len > 0)
        write(fd, body, (size_t)body_len);

    /* Phase 1: Read until we have complete HTTP headers (\r\n\r\n).
     * The first read() often delivers headers + body together for small
     * responses (typical Tapo responses are < 200 bytes total). */
    char raw[IOT_BUF_SIZE];
    int total = 0;
    ssize_t rd;
    while ((rd = read(fd, raw + total, (size_t)(IOT_BUF_SIZE - total - 1))) > 0) {
        total += (int)rd;
        if (memmem(raw, (size_t)total, "\r\n\r\n", 4)) break;
    }

    /* Phase 2: If headers arrived but body is incomplete, read the
     * remaining bytes using Content-Length. This is critical — without
     * it, we'd wait for the 5s SO_RCVTIMEO on every request, tripling
     * the total KLAP handshake time from ~0.6s to ~15s. */
    char *hdr_end = memmem(raw, (size_t)total, "\r\n\r\n", 4);
    if (hdr_end) {
        int hdr_size = (int)(hdr_end + 4 - raw);
        int got = total - hdr_size;
        int want = 0;
        char *cl = strcasestr(raw, "Content-Length:");
        if (cl) want = atoi(cl + 15);
        while (got < want && total < IOT_BUF_SIZE - 1) {
            rd = read(fd, raw + total, (size_t)(IOT_BUF_SIZE - total - 1));
            if (rd <= 0) break;
            total += (int)rd;
            got += (int)rd;
        }
    }
    raw[total] = '\0';
    close(fd);

    /* Parse HTTP status line: "HTTP/1.1 200 OK" → status = 200 */
    int http_status = 0;
    if (total > 12 && strncmp(raw, "HTTP/1.", 7) == 0)
        http_status = atoi(raw + 9);
    if (status_out) *status_out = http_status;

    if (g_core)
        g_core->log(g_core, PORTAL_LOG_DEBUG, "iot",
                    "POST %s → HTTP %d (%d bytes)", path, http_status, total);

    /* Extract session cookie from Set-Cookie header.
     * Tapo sends: "Set-Cookie: TP_SESSIONID=HEXSTRING;TIMEOUT=86400\r\n"
     * We only keep "TP_SESSIONID=HEXSTRING" (before the first ';').
     * Sending the full string with ";TIMEOUT=86400" causes HTTP 400
     * on subsequent requests because the plug rejects unknown attributes. */
    if (cookie_out) {
        cookie_out[0] = '\0';
        char *sc = strstr(raw, "Set-Cookie: ");
        if (sc) {
            sc += 12;
            char *end = strstr(sc, "\r\n");
            if (end) {
                char *semi = memchr(sc, ';', (size_t)(end - sc));
                if (semi && semi < end) end = semi;
                int cl2 = (int)(end - sc);
                if (cl2 >= cookie_max) cl2 = cookie_max - 1;
                memcpy(cookie_out, sc, (size_t)cl2);
                cookie_out[cl2] = '\0';
            }
        }
    }

    /* Extract response body (everything after \r\n\r\n).
     * For KLAP handshake1: 48 bytes (16 remote_seed + 32 server_hash).
     * For KLAP handshake2: 0 bytes (empty body on success).
     * For KLAP request: 64+ bytes (encrypted response, can be ignored). */
    char *bs = strstr(raw, "\r\n\r\n");
    if (bs) {
        bs += 4;
        int blen = total - (int)(bs - raw);
        if (blen > resp_max) blen = resp_max;
        memcpy(resp_out, bs, (size_t)blen);
        return blen;
    }
    return -1;
}

/* Tapo KLAP v2 protocol — full implementation in pure C + OpenSSL
 *
 * KLAP (Key-Length-Authentication Protocol) v2 is used by TP-Link Tapo
 * devices with firmware 1.3+. It replaces the older AES/RSA protocol.
 *
 * Protocol flow:
 *   1. Client generates 16 random bytes (local_seed)
 *   2. POST /app/handshake1 with local_seed
 *      → Server returns 48 bytes: remote_seed(16) + server_hash(32)
 *      → Server also sets TP_SESSIONID cookie
 *   3. Client verifies: server_hash == SHA-256(local_seed + remote_seed + auth_hash)
 *   4. POST /app/handshake2 with SHA-256(remote_seed + local_seed + auth_hash)
 *      → Server returns HTTP 200 if auth is valid
 *   5. Derive session keys from seeds:
 *      - AES key:  SHA-256("lsk" + local + remote + auth)[:16]
 *      - IV base:  SHA-256("iv"  + local + remote + auth)[:12]
 *      - Seq init: SHA-256("iv"  + local + remote + auth)[28:32] as signed int32
 *      - Sig key:  SHA-256("ldk" + local + remote + auth)[:28]
 *   6. Encrypt command JSON with AES-128-CBC (PKCS7 padding)
 *      - CBC IV = iv_base(12) + seq_no(4, big-endian signed)
 *   7. Sign: SHA-256(sig_key(28) + seq_bytes(4) + ciphertext)
 *   8. POST /app/request?seq=N with signature(32) + ciphertext
 *
 * Returns: 0 on success, -1 on error, -2 on KLAP not supported (try legacy)
 */
static int tapo_klap_command(iot_device_t *d, const char *cmd,
                             char *result_out, int result_max)
{
    if (g_tapo_email[0] == '\0' || g_tapo_pass[0] == '\0')
        return -1;

    /* Step 1: Compute auth hash = SHA-256(SHA-1(email) + SHA-1(password))
     * This is the KLAP v2 auth hash format. KLAP v1 uses MD5 instead of SHA-1.
     * The auth_hash proves to the device that we know the TP-Link account
     * credentials without sending them in cleartext. */
    unsigned char email_sha1[20], pass_sha1[20];
    unsigned int sha1_len = 20;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    /* SHA-1(email) */
    EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(mdctx, g_tapo_email, strlen(g_tapo_email));
    EVP_DigestFinal_ex(mdctx, email_sha1, &sha1_len);

    /* SHA-1(password) */
    EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(mdctx, g_tapo_pass, strlen(g_tapo_pass));
    EVP_DigestFinal_ex(mdctx, pass_sha1, &sha1_len);

    /* auth_hash = SHA-256(sha1_email + sha1_pass) */
    unsigned char auth_hash[32];
    unsigned int sha256_len = 32;
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, email_sha1, 20);
    EVP_DigestUpdate(mdctx, pass_sha1, 20);
    EVP_DigestFinal_ex(mdctx, auth_hash, &sha256_len);
    EVP_MD_CTX_free(mdctx);

    /* Step 2: Generate local seed (16 random bytes) */
    unsigned char local_seed[16];
    RAND_bytes(local_seed, 16);

    /* Step 3: Handshake 1 — POST /app/handshake1 with 16-byte local_seed
     * Response: 48 bytes = remote_seed(16) + server_hash(32)
     * The server also sets a TP_SESSIONID cookie that must be sent
     * with all subsequent requests in this session. */
    unsigned char resp[IOT_BUF_SIZE];
    char cookie[256] = "";
    int status = 0;
    int rlen = tapo_http_post(d->ip, "/app/handshake1", NULL,
                               local_seed, 16,
                               resp, sizeof(resp),
                               cookie, sizeof(cookie), &status);

    if (status != 200 || rlen < 48) {
        if (g_core)
            g_core->log(g_core, PORTAL_LOG_WARN, "iot",
                        "Tapo KLAP handshake1 failed for %s (HTTP %d, len=%d)",
                        d->ip, status, rlen);
        return -2;  /* KLAP not supported, try legacy */
    }

    /* Extract remote_seed (first 16 bytes of response body) */
    unsigned char remote_seed[16];
    memcpy(remote_seed, resp, 16);

    /* Step 4: Handshake 2 — prove we know the auth hash.
     * Payload = SHA-256(remote_seed + local_seed + auth_hash).
     * The order is reversed from the server_hash verification:
     *   server proves: SHA-256(LOCAL + REMOTE + auth)
     *   client proves: SHA-256(REMOTE + LOCAL + auth)
     * HTTP 200 = authenticated. HTTP 400/403 = wrong credentials. */
    unsigned char hs2_payload[32];
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, remote_seed, 16);
    EVP_DigestUpdate(mdctx, local_seed, 16);
    EVP_DigestUpdate(mdctx, auth_hash, 32);
    EVP_DigestFinal_ex(mdctx, hs2_payload, &sha256_len);
    EVP_MD_CTX_free(mdctx);

    rlen = tapo_http_post(d->ip, "/app/handshake2", cookie,
                           hs2_payload, 32,
                           resp, sizeof(resp), NULL, 0, &status);

    if (status != 200) {
        if (g_core)
            g_core->log(g_core, PORTAL_LOG_WARN, "iot",
                        "Tapo KLAP handshake2 failed for %s (HTTP %d)", d->ip, status);
        return -2;
    }

    /* Step 5: Derive encryption key, iv, and signature key from seeds
     * key = SHA-256("lsk" + local_seed + remote_seed + auth_hash)[:16]
     * iv  = SHA-256("iv"  + local_seed + remote_seed + auth_hash)[:12]
     * seq = SHA-256("iv"  + local_seed + remote_seed + auth_hash)[28:32] (signed big-endian)
     * sig = SHA-256("ldk" + local_seed + remote_seed + auth_hash)[:28]
     */
    unsigned char key_full[32], iv_full[32], sig_full[32];
    mdctx = EVP_MD_CTX_new();

    /* Key derivation */
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, "lsk", 3);
    EVP_DigestUpdate(mdctx, local_seed, 16);
    EVP_DigestUpdate(mdctx, remote_seed, 16);
    EVP_DigestUpdate(mdctx, auth_hash, 32);
    EVP_DigestFinal_ex(mdctx, key_full, &sha256_len);

    /* IV + seq derivation (prefix is "iv", 2 bytes) */
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, "iv", 2);
    EVP_DigestUpdate(mdctx, local_seed, 16);
    EVP_DigestUpdate(mdctx, remote_seed, 16);
    EVP_DigestUpdate(mdctx, auth_hash, 32);
    EVP_DigestFinal_ex(mdctx, iv_full, &sha256_len);

    /* Signature key derivation (prefix is "ldk", 3 bytes, use first 28 bytes) */
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, "ldk", 3);
    EVP_DigestUpdate(mdctx, local_seed, 16);
    EVP_DigestUpdate(mdctx, remote_seed, 16);
    EVP_DigestUpdate(mdctx, auth_hash, 32);
    EVP_DigestFinal_ex(mdctx, sig_full, &sha256_len);
    EVP_MD_CTX_free(mdctx);

    unsigned char aes_key[16], aes_iv[12], sig_key[28];
    memcpy(aes_key, key_full, 16);
    memcpy(aes_iv, iv_full, 12);
    memcpy(sig_key, sig_full, 28);

    /* Seq number: derived from the last 4 bytes of the full IV hash,
     * interpreted as a signed big-endian int32. Incremented by 1 before
     * the first request (each subsequent request would increment again).
     * The seq number serves as both a replay counter and as the last
     * 4 bytes of the AES-CBC IV, tying each encryption to a unique IV.
     * Can be negative — the plug accepts negative seq values in the URL. */
    int32_t seq_no = (int32_t)(((uint32_t)iv_full[28] << 24) |
                                ((uint32_t)iv_full[29] << 16) |
                                ((uint32_t)iv_full[30] << 8)  |
                                 (uint32_t)iv_full[31]);
    seq_no += 1;

    /* Step 6: Build command JSON.
     * For ON/OFF/TOGGLE: set_device_info with device_on.
     * For STATUS: get_device_info to query current state.
     * For raw queries: cmd is passed as-is if it starts with '{'. */
    char json[512];
    int jlen;
    if (cmd[0] == '{') {
        /* Raw JSON command */
        jlen = snprintf(json, sizeof(json), "%s", cmd);
    } else if (strcmp(cmd, "STATUS") == 0) {
        jlen = snprintf(json, sizeof(json),
            "{\"method\":\"get_device_info\"}");
    } else {
        int on = (strcmp(cmd, "ON") == 0);
        jlen = snprintf(json, sizeof(json),
            "{\"method\":\"set_device_info\",\"params\":{\"device_on\":%s}}",
            on ? "true" : "false");
    }

    /* Step 7: Encrypt with AES-128-CBC + PKCS7 padding */
    unsigned char encrypted[512];
    int enc_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char full_iv[16];
    memcpy(full_iv, aes_iv, 12);
    full_iv[12] = (unsigned char)((seq_no >> 24) & 0xFF);
    full_iv[13] = (unsigned char)((seq_no >> 16) & 0xFF);
    full_iv[14] = (unsigned char)((seq_no >> 8) & 0xFF);
    full_iv[15] = (unsigned char)(seq_no & 0xFF);

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, full_iv);
    int len = 0;
    EVP_EncryptUpdate(ctx, encrypted, &len, (unsigned char *)json, jlen);
    enc_len = len;
    EVP_EncryptFinal_ex(ctx, encrypted + enc_len, &len);
    enc_len += len;
    EVP_CIPHER_CTX_free(ctx);

    /* Step 8: Build KLAP request payload: signature(32) + ciphertext */
    unsigned char sig_hash[32];
    unsigned char seq_bytes[4] = {
        (unsigned char)((seq_no >> 24) & 0xFF),
        (unsigned char)((seq_no >> 16) & 0xFF),
        (unsigned char)((seq_no >> 8) & 0xFF),
        (unsigned char)(seq_no & 0xFF)
    };
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, sig_key, 28);
    EVP_DigestUpdate(mdctx, seq_bytes, 4);
    EVP_DigestUpdate(mdctx, encrypted, (size_t)enc_len);
    EVP_DigestFinal_ex(mdctx, sig_hash, &sha256_len);
    EVP_MD_CTX_free(mdctx);

    unsigned char request[1024];
    memcpy(request, sig_hash, 32);
    memcpy(request + 32, encrypted, (size_t)enc_len);
    int req_len = 32 + enc_len;

    /* Step 9: POST /app/request */
    char req_path[64];
    snprintf(req_path, sizeof(req_path), "/app/request?seq=%d", seq_no);

    rlen = tapo_http_post(d->ip, req_path, cookie,
                           request, req_len,
                           resp, sizeof(resp), NULL, 0, &status);

    if (status == 200) {
        /* Decrypt response if present (for get_device_info queries) */
        if (rlen > 32 && result_out && result_max > 0) {
            unsigned char dec_iv[16];
            memcpy(dec_iv, aes_iv, 12);
            dec_iv[12] = (unsigned char)((seq_no >> 24) & 0xFF);
            dec_iv[13] = (unsigned char)((seq_no >> 16) & 0xFF);
            dec_iv[14] = (unsigned char)((seq_no >> 8) & 0xFF);
            dec_iv[15] = (unsigned char)(seq_no & 0xFF);

            /* Decrypt into a safe buffer, then copy to result_out */
            int cipher_len = rlen - 32;
            unsigned char *dec_buf = malloc((size_t)cipher_len + 128);
            if (dec_buf) {
                EVP_CIPHER_CTX *dctx = EVP_CIPHER_CTX_new();
                EVP_DecryptInit_ex(dctx, EVP_aes_128_cbc(), NULL, aes_key, dec_iv);
                int dec_len = 0, tmplen = 0;
                EVP_DecryptUpdate(dctx, dec_buf, &tmplen,
                                  resp + 32, cipher_len);
                dec_len = tmplen;
                if (EVP_DecryptFinal_ex(dctx, dec_buf + dec_len, &tmplen) == 1)
                    dec_len += tmplen;
                EVP_CIPHER_CTX_free(dctx);

                if (dec_len > 0) {
                    int copy_len = dec_len < result_max - 1 ? dec_len : result_max - 1;
                    memcpy(result_out, dec_buf, (size_t)copy_len);
                    result_out[copy_len] = '\0';
                }
                free(dec_buf);
            }
        }

        if (g_core)
            g_core->log(g_core, PORTAL_LOG_INFO, "iot",
                        "Tapo KLAP %s → %s OK", d->name, cmd);
        return 0;
    }

    if (g_core)
        g_core->log(g_core, PORTAL_LOG_ERROR, "iot",
                    "Tapo KLAP request failed for %s (HTTP %d)", d->ip, status);
    return -1;
}

/* Legacy AES Tapo protocol (older firmware) */
static int tapo_legacy_command(iot_device_t *d, const char *cmd)
{
    if (g_tapo_email[0] == '\0' || g_tapo_pass[0] == '\0')
        return -1;

    /* Step 1: Generate RSA key pair */
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 1024);
    EVP_PKEY_keygen(kctx, &pkey);
    EVP_PKEY_CTX_free(kctx);

    if (!pkey) return -1;

    /* Export public key as PEM */
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    char *pem_data = NULL;
    long pem_len = BIO_get_mem_data(bio, &pem_data);

    /* Step 2: Handshake — send our public key */
    char hs_json[2048];
    int hjlen = snprintf(hs_json, sizeof(hs_json),
        "{\"method\":\"handshake\",\"params\":{\"key\":\"%.*s\"}}",
        (int)pem_len, pem_data);
    BIO_free(bio);

    unsigned char resp[IOT_BUF_SIZE];
    char cookie[256] = "";
    int status = 0;
    int rlen = tapo_http_post(d->ip, "/app", NULL,
                               (unsigned char *)hs_json, hjlen,
                               resp, sizeof(resp),
                               cookie, sizeof(cookie), &status);

    if (status != 200 || !memmem(resp, rlen > 0 ? (size_t)rlen : 0, "\"key\"", 5)) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    /* Extract encrypted key from response */
    char *key_start = memmem(resp, (size_t)rlen, "\"key\":\"", 7);
    if (!key_start) { EVP_PKEY_free(pkey); return -1; }
    key_start += 7;
    char *key_end = memchr(key_start, '"', (size_t)(rlen - (key_start - (char *)resp)));
    if (!key_end) { EVP_PKEY_free(pkey); return -1; }
    *key_end = '\0';

    /* Base64 decode the encrypted AES key */
    /* (simplified — real implementation would decode + RSA decrypt) */
    /* For now: we have the session cookie, try direct command */

    EVP_PKEY_free(pkey);

    /* Step 3: Try direct encrypted command */
    int on = (strcmp(cmd, "ON") == 0);
    char cmd_json[256];
    int cjlen = snprintf(cmd_json, sizeof(cmd_json),
        "{\"method\":\"set_device_info\","
        "\"params\":{\"device_on\":%s}}", on ? "true" : "false");

    rlen = tapo_http_post(d->ip, "/app", cookie,
                           (unsigned char *)cmd_json, cjlen,
                           resp, sizeof(resp), NULL, 0, &status);

    if (status == 200 && memmem(resp, rlen > 0 ? (size_t)rlen : 0, "\"error_code\":0", 14))
        return 0;

    return -1;
}

/* Query Tapo device state via KLAP get_device_info.
 * Updates device state (on/off), model, and power_watts.
 * Returns 0 on success, -1 on failure. */
static int tapo_query_state(iot_device_t *d)
{
    char result[4096] = "";
    int rc = tapo_klap_command(d, "STATUS", result, sizeof(result));
    if (rc != 0 || result[0] == '\0') return -1;

    /* Parse device_on from JSON response */
    if (strstr(result, "\"device_on\":true"))
        d->state = IOT_STATE_ON;
    else if (strstr(result, "\"device_on\":false"))
        d->state = IOT_STATE_OFF;

    /* Parse model if available */
    const char *model_p = strstr(result, "\"model\":\"");
    if (model_p) {
        model_p += 9;
        int i = 0;
        while (*model_p && *model_p != '"' && i < (int)sizeof(d->model) - 1)
            d->model[i++] = *model_p++;
        d->model[i] = '\0';
    }

    /* Parse MAC address */
    const char *mac_p = strstr(result, "\"mac\":\"");
    if (mac_p && d->mac[0] == '\0') {
        mac_p += 7;
        int i = 0;
        while (*mac_p && *mac_p != '"' && i < (int)sizeof(d->mac) - 1)
            d->mac[i++] = *mac_p++;
        d->mac[i] = '\0';
    }

    /* Parse nickname (Base64-encoded by Tapo firmware) */
    const char *nick_p = strstr(result, "\"nickname\":\"");
    if (nick_p) {
        nick_p += 12;
        char nick[128] = "";
        int i = 0;
        while (*nick_p && *nick_p != '"' && i < (int)sizeof(nick) - 1)
            nick[i++] = *nick_p++;
        nick[i] = '\0';

        if (i > 0) {
            /* Try Base64 decode (Tapo returns nicknames as Base64) */
            int is_b64 = (i >= 2);
            for (int j = 0; j < i && is_b64; j++) {
                char c = nick[j];
                if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='))
                    is_b64 = 0;
            }
            if (is_b64) {
                char decoded[64];
                int di = 0;
                for (int j = 0; j < i && di < (int)sizeof(decoded) - 1; j += 4) {
                    unsigned int v = 0;
                    int valid = 0;
                    for (int k = 0; k < 4 && j + k < i; k++) {
                        unsigned char c = (unsigned char)nick[j + k];
                        if (c == '=') continue;
                        int val = -1;
                        if (c >= 'A' && c <= 'Z') val = c - 'A';
                        else if (c >= 'a' && c <= 'z') val = c - 'a' + 26;
                        else if (c >= '0' && c <= '9') val = c - '0' + 52;
                        else if (c == '+') val = 62;
                        else if (c == '/') val = 63;
                        if (val >= 0) { v = (v << 6) | (unsigned int)val; valid++; }
                    }
                    if (valid == 4) {
                        if (di < (int)sizeof(decoded) - 1) decoded[di++] = (char)(v >> 16);
                        if (di < (int)sizeof(decoded) - 1) decoded[di++] = (char)(v >> 8);
                        if (di < (int)sizeof(decoded) - 1) decoded[di++] = (char)(v);
                    } else if (valid == 3) {
                        v <<= 6;
                        if (di < (int)sizeof(decoded) - 1) decoded[di++] = (char)(v >> 16);
                        if (di < (int)sizeof(decoded) - 1) decoded[di++] = (char)(v >> 8);
                    } else if (valid == 2) {
                        v <<= 12;
                        if (di < (int)sizeof(decoded) - 1) decoded[di++] = (char)(v >> 16);
                    }
                }
                decoded[di] = '\0';
                if (di > 0)
                    snprintf(d->name, sizeof(d->name), "%s", decoded);
            } else {
                /* Plain text nickname */
                snprintf(d->name, sizeof(d->name), "%.*s",
                         (int)sizeof(d->name) - 1, nick);
            }
        }
    }

    d->last_seen = (int64_t)time(NULL);
    d->online = 1;
    return 0;
}

static int tapo_command(iot_device_t *d, const char *cmd)
{
    /* STATUS query — doesn't change state, just reads it */
    if (strcmp(cmd, "STATUS") == 0)
        return tapo_query_state(d);

    /* Try KLAP v2 first (modern firmware) */
    int rc = tapo_klap_command(d, cmd, NULL, 0);
    if (rc == 0) return 0;

    /* Fall back to legacy AES protocol (older firmware) */
    if (rc == -2) {
        if (g_core)
            g_core->log(g_core, PORTAL_LOG_INFO, "iot",
                        "Tapo: KLAP failed for %s, trying legacy protocol", d->ip);
        return tapo_legacy_command(d, cmd);
    }

    return rc;
}

/* ================================================================
 * Driver: Tapo Hub H200 (SSL + AES securePassthrough protocol)
 *
 * The H200 hub uses HTTPS on port 443 with encrypt_type=3:
 *   1. POST / — probe with cnonce → get nonce + device_confirm
 *   2. POST / — login with digest_passwd → get stok + start_seq
 *   3. POST /stok=TOKEN/ds — AES-encrypted securePassthrough commands
 *
 * Each request needs a fresh SSL connection (hub drops after response).
 * Child devices (cameras, sensors) are accessed via getChildDeviceList.
 *
 * Key derivation:
 *   hashedKey = SHA-256(cnonce + SHA-256(password).HEX + nonce).HEX
 *   lsk = SHA-256("lsk" + cnonce + nonce + hashedKey)[:16]  (AES key)
 *   ivb = SHA-256("ivb" + cnonce + nonce + hashedKey)[:16]  (AES IV)
 * ================================================================ */

/* SHA-256 of string, output as uppercase hex */
static void hub_sha256_hex(const char *in, int len, char *out)
{
    unsigned char hash[32];
    unsigned int hlen = 32;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, in, (size_t)len);
    EVP_DigestFinal_ex(ctx, hash, &hlen);
    EVP_MD_CTX_free(ctx);
    for (int i = 0; i < 32; i++)
        sprintf(out + i * 2, "%02X", hash[i]);
    out[64] = '\0';
}

/* SHA-256 of string, output as raw bytes */
static void hub_sha256_raw(const char *in, int len, unsigned char *out)
{
    unsigned int hlen = 32;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, in, (size_t)len);
    EVP_DigestFinal_ex(ctx, out, &hlen);
    EVP_MD_CTX_free(ctx);
}

/* Base64 encode */
static int hub_b64_encode(const unsigned char *in, int inlen, char *out, int outmax)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, in, inlen);
    BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    int len = (int)bptr->length;
    if (len >= outmax) len = outmax - 1;
    memcpy(out, bptr->data, (size_t)len);
    out[len] = '\0';
    BIO_free_all(b64);
    return len;
}

/* Base64 decode */
static int hub_b64_decode(const char *in, int inlen, unsigned char *out, int outmax)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(in, inlen);
    mem = BIO_push(b64, mem);
    BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);
    int len = BIO_read(mem, out, outmax);
    BIO_free_all(mem);
    return len > 0 ? len : 0;
}

/* HTTPS POST to hub — each call creates a fresh SSL connection
 * Returns body length, -1 on error */
static int hub_https_post(const char *ip, int port, const char *path,
                           const char *body, const char *extra_headers,
                           char *resp_out, int resp_max)
{
    struct hostent *he = gethostbyname(ip);
    if (!he) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = {10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    memcpy(&addr.sin_addr, he->h_addr, (size_t)he->h_length);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }

    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_cipher_list(ssl_ctx, "DEFAULT:@SECLEVEL=0");
    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, fd);

    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl); SSL_CTX_free(ssl_ctx); close(fd);
        return -1;
    }

    int body_len = body ? (int)strlen(body) : 0;
    char hdr[2048];
    int hlen = snprintf(hdr, sizeof(hdr),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json; charset=UTF-8\r\n"
        "Content-Length: %d\r\n"
        "User-Agent: Tapo CameraClient Android\r\n"
        "requestByApp: true\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n",
        path, ip, port, body_len,
        extra_headers ? extra_headers : "");

    SSL_write(ssl, hdr, hlen);
    if (body_len > 0) SSL_write(ssl, body, body_len);

    /* Read full response */
    char raw[IOT_BUF_SIZE * 2];
    int total = 0, rd;
    while ((rd = SSL_read(ssl, raw + total, (int)(sizeof(raw) - (size_t)total - 1))) > 0) {
        total += rd;
        if (memmem(raw, (size_t)total, "\r\n\r\n", 4)) {
            /* Check Content-Length */
            char *hdr_end = strstr(raw, "\r\n\r\n");
            int hdr_size = (int)(hdr_end + 4 - raw);
            int body_got = total - hdr_size;
            int cl = 0;
            char *cl_h = strcasestr(raw, "Content-Length:");
            if (cl_h) cl = atoi(cl_h + 15);
            if (cl > 0 && body_got >= cl) break;
            /* Check chunked end */
            if (strcasestr(raw, "Transfer-Encoding: chunked") &&
                memmem(raw, (size_t)total, "\r\n0\r\n", 5))
                break;
        }
    }
    raw[total] = '\0';
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(fd);

    /* Find body start */
    char *bs = strstr(raw, "\r\n\r\n");
    if (!bs) return -1;
    bs += 4;

    /* Handle chunked transfer encoding */
    if (strcasestr(raw, "Transfer-Encoding: chunked")) {
        int out_len = 0;
        char *src = bs;
        while (*src) {
            int chunk_size = (int)strtol(src, NULL, 16);
            if (chunk_size <= 0) break;
            char *data = strstr(src, "\r\n");
            if (!data) break;
            data += 2;
            if (out_len + chunk_size >= resp_max) break;
            memcpy(resp_out + out_len, data, (size_t)chunk_size);
            out_len += chunk_size;
            src = data + chunk_size + 2;
        }
        resp_out[out_len] = '\0';
        return out_len;
    }

    /* Content-Length mode */
    int blen = total - (int)(bs - raw);
    if (blen >= resp_max) blen = resp_max - 1;
    memcpy(resp_out, bs, (size_t)blen);
    resp_out[blen] = '\0';
    return blen;
}

/* Minimal JSON string extractor */
static const char *hub_json_str(const char *json, const char *key, char *out, int outmax)
{
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(json, pat);
    if (!p) return NULL;
    p = strchr(p + strlen(pat) - 1, ':') + 1;
    while (*p == ' ') p++;
    if (*p != '"') return NULL;
    p++;
    int i = 0;
    while (*p && *p != '"' && i < outmax - 1) out[i++] = *p++;
    out[i] = '\0';
    return out;
}

static int hub_json_int(const char *json, const char *key)
{
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(json, pat);
    if (!p) return -999999;
    p = strchr(p, ':') + 1;
    while (*p == ' ') p++;
    return atoi(p);
}

/* Full Tapo Hub command: authenticate + send encrypted command
 *
 * Protocol flow (3 HTTPS requests, each on a fresh SSL connection):
 *   1. Probe:  POST / with cnonce → nonce + device_confirm
 *   2. Login:  POST / with digest_passwd → stok + start_seq
 *   3. Command: POST /stok=TOKEN/ds with AES-encrypted securePassthrough
 */
static int tapo_hub_send_port(const char *ip, int port, const char *user,
                               const char *password, const char *cmd_json,
                               char *result_out, int result_max)
{
    char sha256_pass[65];
    hub_sha256_hex(password, (int)strlen(password), sha256_pass);

    /* Generate cnonce (8 random bytes → 16 hex chars) */
    unsigned char raw_nonce[8];
    RAND_bytes(raw_nonce, 8);
    char cnonce[17];
    for (int i = 0; i < 8; i++) sprintf(cnonce + i * 2, "%02X", raw_nonce[i]);
    cnonce[16] = '\0';

    /* Step 1: Probe — detect secure connection */
    char probe[512], resp[IOT_BUF_SIZE * 2];
    snprintf(probe, sizeof(probe),
        "{\"method\":\"login\",\"params\":{\"encrypt_type\":\"3\","
        "\"username\":\"%s\",\"cnonce\":\"%s\"}}",
        user, cnonce);

    int rlen = hub_https_post(ip, port, "/", probe, NULL, resp, sizeof(resp));
    if (rlen <= 0 || hub_json_int(resp, "error_code") != -40413) {
        if (g_core)
            g_core->log(g_core, PORTAL_LOG_WARN, "iot",
                        "Hub probe failed for %s (not secure device)", ip);
        return -1;
    }

    /* Extract nonce and device_confirm */
    const char *data_sec = strstr(resp, "\"data\":");
    if (!data_sec) return -1;
    char nonce[65] = "", device_confirm[256] = "";
    hub_json_str(data_sec, "nonce", nonce, sizeof(nonce));
    hub_json_str(data_sec, "device_confirm", device_confirm, sizeof(device_confirm));
    if (!nonce[0] || !device_confirm[0]) return -1;

    /* Step 2: Validate device_confirm — SHA-256(cnonce + hashedPass + nonce) + nonce + cnonce */
    char hash_input[256], expected_hash[65], expected[384];
    snprintf(hash_input, sizeof(hash_input), "%s%s%s", cnonce, sha256_pass, nonce);
    hub_sha256_hex(hash_input, (int)strlen(hash_input), expected_hash);
    snprintf(expected, sizeof(expected), "%s%s%s", expected_hash, nonce, cnonce);

    if (strcmp(device_confirm, expected) != 0) {
        if (g_core)
            g_core->log(g_core, PORTAL_LOG_WARN, "iot",
                        "Hub auth failed for %s (wrong password)", ip);
        return -1;
    }

    /* Step 3: Login with digest_passwd */
    char digest_input[256], digest_hash[65], digest_passwd[384];
    snprintf(digest_input, sizeof(digest_input), "%s%s%s", sha256_pass, cnonce, nonce);
    hub_sha256_hex(digest_input, (int)strlen(digest_input), digest_hash);
    snprintf(digest_passwd, sizeof(digest_passwd), "%s%s%s", digest_hash, cnonce, nonce);

    char login[1024];
    snprintf(login, sizeof(login),
        "{\"method\":\"login\",\"params\":{\"cnonce\":\"%s\","
        "\"encrypt_type\":\"3\",\"digest_passwd\":\"%s\",\"username\":\"%s\"}}",
        cnonce, digest_passwd, user);

    rlen = hub_https_post(ip, port, "/", login, NULL, resp, sizeof(resp));
    if (rlen <= 0 || hub_json_int(resp, "error_code") != 0) {
        if (g_core)
            g_core->log(g_core, PORTAL_LOG_WARN, "iot",
                        "Hub login failed for %s", ip);
        return -1;
    }

    char stok[128] = "";
    hub_json_str(resp, "stok", stok, sizeof(stok));
    int seq = hub_json_int(resp, "start_seq");
    if (!stok[0] || seq == -999999) return -1;

    /* Step 4: Derive AES keys
     * hashedKey = SHA-256(cnonce + hashedPass + nonce).HEX (same order as validate)
     * lsk = SHA-256("lsk" + cnonce + nonce + hashedKey)[:16]
     * ivb = SHA-256("ivb" + cnonce + nonce + hashedKey)[:16] */
    /* Note: hashedKey == expected_hash (already computed above) */
    char lsk_in[512], ivb_in[512];
    snprintf(lsk_in, sizeof(lsk_in), "lsk%s%s%s", cnonce, nonce, expected_hash);
    snprintf(ivb_in, sizeof(ivb_in), "ivb%s%s%s", cnonce, nonce, expected_hash);
    unsigned char lsk[32], ivb_bytes[32];
    hub_sha256_raw(lsk_in, (int)strlen(lsk_in), lsk);
    hub_sha256_raw(ivb_in, (int)strlen(ivb_in), ivb_bytes);

    /* Step 5: Encrypt command with AES-128-CBC */
    int cmd_len = (int)strlen(cmd_json);
    unsigned char encrypted[4096];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, lsk, ivb_bytes);
    int enc_len = 0, tmplen = 0;
    EVP_EncryptUpdate(ctx, encrypted, &tmplen, (unsigned char *)cmd_json, cmd_len);
    enc_len = tmplen;
    EVP_EncryptFinal_ex(ctx, encrypted + enc_len, &tmplen);
    enc_len += tmplen;
    EVP_CIPHER_CTX_free(ctx);

    /* Base64 encode */
    char b64[8192];
    hub_b64_encode(encrypted, enc_len, b64, sizeof(b64));

    /* Build securePassthrough wrapper */
    char *secure = malloc((size_t)(strlen(b64) + 128));
    if (!secure) return -1;
    sprintf(secure, "{\"method\":\"securePassthrough\",\"params\":{\"request\":\"%s\"}}", b64);

    /* Compute Tapo_tag for integrity
     * tag1 = SHA-256(hashedPass + cnonce).HEX.UPPER
     * tag2 = SHA-256(tag1 + secure_body + seq).HEX.UPPER */
    char tag1_in[256], tag1[65];
    snprintf(tag1_in, sizeof(tag1_in), "%s%s", sha256_pass, cnonce);
    hub_sha256_hex(tag1_in, (int)strlen(tag1_in), tag1);

    int tag2_in_len = (int)strlen(tag1) + (int)strlen(secure) + 16;
    char *tag2_in = malloc((size_t)tag2_in_len);
    if (!tag2_in) { free(secure); return -1; }
    sprintf(tag2_in, "%s%s%d", tag1, secure, seq);
    char tag[65];
    hub_sha256_hex(tag2_in, (int)strlen(tag2_in), tag);
    free(tag2_in);

    /* Build extra headers */
    char extra[256];
    snprintf(extra, sizeof(extra), "Seq: %d\r\nTapo_tag: %s\r\n", seq, tag);

    /* Send encrypted command */
    char url[256];
    snprintf(url, sizeof(url), "/stok=%s/ds", stok);

    rlen = hub_https_post(ip, port, url, secure, extra, resp, sizeof(resp));
    free(secure);

    if (rlen <= 0) {
        if (g_core)
            g_core->log(g_core, PORTAL_LOG_ERROR, "iot",
                        "Hub command failed for %s (no response)", ip);
        return -1;
    }

    /* Decrypt response */
    char enc_b64[8192] = "";
    hub_json_str(resp, "response", enc_b64, sizeof(enc_b64));
    if (enc_b64[0]) {
        unsigned char enc_resp[4096];
        int elen = hub_b64_decode(enc_b64, (int)strlen(enc_b64), enc_resp, sizeof(enc_resp));
        if (elen > 0) {
            unsigned char decrypted[4096];
            EVP_CIPHER_CTX *dctx = EVP_CIPHER_CTX_new();
            EVP_DecryptInit_ex(dctx, EVP_aes_128_cbc(), NULL, lsk, ivb_bytes);
            int dec_len = 0;
            tmplen = 0;
            EVP_DecryptUpdate(dctx, decrypted, &tmplen, enc_resp, elen);
            dec_len = tmplen;
            EVP_DecryptFinal_ex(dctx, decrypted + dec_len, &tmplen);
            dec_len += tmplen;
            EVP_CIPHER_CTX_free(dctx);
            if (dec_len > 0 && dec_len < result_max) {
                memcpy(result_out, decrypted, (size_t)dec_len);
                result_out[dec_len] = '\0';
                return dec_len;
            }
        }
    }

    /* No encrypted response — return raw */
    if (rlen < result_max) {
        memcpy(result_out, resp, (size_t)rlen);
        result_out[rlen] = '\0';
    }
    return rlen;
}

/* Get child device list from hub */
/* Wrapper: try port 443, fallback to 4433 */
static int tapo_hub_send(const char *ip, const char *user, const char *password,
                          const char *cmd_json, char *result_out, int result_max)
{
    int rc = tapo_hub_send_port(ip, 443, user, password, cmd_json,
                                 result_out, result_max);
    if (rc < 0) {
        if (g_core)
            g_core->log(g_core, PORTAL_LOG_DEBUG, "iot",
                        "Hub port 443 failed for %s, trying 4433", ip);
        rc = tapo_hub_send_port(ip, 4433, user, password, cmd_json,
                                 result_out, result_max);
    }
    return rc;
}

static int tapo_hub_get_children(iot_device_t *hub, char *out, int outmax)
{
    const char *cmd =
        "{\"method\":\"multipleRequest\",\"params\":{\"requests\":["
        "{\"method\":\"getChildDeviceList\",\"params\":{\"childControl\":{\"start_index\":0}}}"
        "]}}";

    return tapo_hub_send(hub->ip, g_tapo_email, g_tapo_pass,
                          cmd, out, outmax);
}

/* Get hub device info */
static int tapo_hub_get_info(iot_device_t *hub, char *out, int outmax)
{
    const char *cmd =
        "{\"method\":\"multipleRequest\",\"params\":{\"requests\":["
        "{\"method\":\"getDeviceInfo\",\"params\":{\"device_info\":{\"name\":[\"basic_info\"]}}}"
        "]}}";

    return tapo_hub_send(hub->ip, g_tapo_email, g_tapo_pass,
                          cmd, out, outmax);
}

/* Vacuum commands via securePassthrough (same protocol as hub) */
static int tapo_vacuum_command(iot_device_t *d, const char *cmd,
                                char *result_out, int result_max)
{
    char json[512];
    if (strcmp(cmd, "start") == 0) {
        snprintf(json, sizeof(json),
            "{\"method\":\"multipleRequest\",\"params\":{\"requests\":["
            "{\"method\":\"setSweepParams\",\"params\":{\"sweep\":{\"control\":\"start\"}}}"
            "]}}");
    } else if (strcmp(cmd, "stop") == 0 || strcmp(cmd, "pause") == 0) {
        snprintf(json, sizeof(json),
            "{\"method\":\"multipleRequest\",\"params\":{\"requests\":["
            "{\"method\":\"setSweepParams\",\"params\":{\"sweep\":{\"control\":\"stop\"}}}"
            "]}}");
    } else if (strcmp(cmd, "dock") == 0 || strcmp(cmd, "charge") == 0) {
        snprintf(json, sizeof(json),
            "{\"method\":\"multipleRequest\",\"params\":{\"requests\":["
            "{\"method\":\"setSweepParams\",\"params\":{\"sweep\":{\"control\":\"dock\"}}}"
            "]}}");
    } else if (strcmp(cmd, "status") == 0 || strcmp(cmd, "info") == 0) {
        snprintf(json, sizeof(json),
            "{\"method\":\"multipleRequest\",\"params\":{\"requests\":["
            "{\"method\":\"getDeviceInfo\"}"
            "]}}");
    } else {
        return -1;
    }
    return tapo_hub_send(d->ip, g_tapo_email, g_tapo_pass,
                          json, result_out, result_max);
}

/* Bulb brightness/color via KLAP (L530/L510 use same protocol as plugs) */
static int tapo_bulb_command(iot_device_t *d, const char *cmd)
{
    char json[256];
    /* Extract number after command word (skip any separator: space, =, :) */
    const char *num = cmd;
    while (*num && !(*num >= '0' && *num <= '9') && *num != '-') num++;

    if (strncmp(cmd, "brightness", 10) == 0) {
        int level = atoi(num);
        if (level < 1) level = 1;
        if (level > 100) level = 100;
        snprintf(json, sizeof(json),
            "{\"method\":\"set_device_info\",\"params\":{\"brightness\":%d}}", level);
    } else if (strncmp(cmd, "color_temp", 10) == 0 || strncmp(cmd, "temp", 4) == 0) {
        int temp = atoi(num);
        if (temp < 2500) temp = 2500;
        if (temp > 6500) temp = 6500;
        snprintf(json, sizeof(json),
            "{\"method\":\"set_device_info\",\"params\":{\"color_temp\":%d}}", temp);
    } else if (strncmp(cmd, "hue", 3) == 0) {
        int hue = 0, sat = 100;
        sscanf(num, "%d %d", &hue, &sat);
        snprintf(json, sizeof(json),
            "{\"method\":\"set_device_info\",\"params\":{\"hue\":%d,\"saturation\":%d}}", hue, sat);
    } else if (strncmp(cmd, "rgb", 3) == 0) {
        int r = 255, g = 255, b = 255;
        sscanf(num, "%d %d %d", &r, &g, &b);
        /* Convert RGB to HSV for Tapo API */
        double rd = r / 255.0, gd = g / 255.0, bd = b / 255.0;
        double mx = rd > gd ? (rd > bd ? rd : bd) : (gd > bd ? gd : bd);
        double mn = rd < gd ? (rd < bd ? rd : bd) : (gd < bd ? gd : bd);
        double d = mx - mn, h = 0, s = mx > 0 ? d / mx : 0;
        if (d > 0) {
            if (mx == rd) h = 60.0 * ((gd - bd) / d + (gd < bd ? 6 : 0));
            else if (mx == gd) h = 60.0 * ((bd - rd) / d + 2);
            else h = 60.0 * ((rd - gd) / d + 4);
        }
        snprintf(json, sizeof(json),
            "{\"method\":\"set_device_info\",\"params\":{\"hue\":%d,\"saturation\":%d}}",
            (int)h, (int)(s * 100));
    } else if (strncmp(cmd, "color", 5) == 0) {
        /* Named colors — only set hue/saturation, don't touch brightness */
        int hue = 0, sat = 100;
        if (strstr(cmd, "red")) { hue = 0; sat = 100; }
        else if (strstr(cmd, "green")) { hue = 120; sat = 100; }
        else if (strstr(cmd, "blue")) { hue = 240; sat = 100; }
        else if (strstr(cmd, "yellow")) { hue = 60; sat = 100; }
        else if (strstr(cmd, "purple")) { hue = 280; sat = 100; }
        else if (strstr(cmd, "orange")) { hue = 30; sat = 100; }
        else if (strstr(cmd, "cyan")) { hue = 180; sat = 100; }
        else if (strstr(cmd, "pink")) { hue = 330; sat = 80; }
        else if (strstr(cmd, "white")) { sat = 0; }
        else { return -1; }
        snprintf(json, sizeof(json),
            "{\"method\":\"set_device_info\",\"params\":{\"hue\":%d,\"saturation\":%d}}",
            hue, sat);
    } else {
        return -1;
    }
    return tapo_klap_command(d, json, NULL, 0);
}

/* Hub doesn't support direct on/off — it's a hub, not a switch.
 * Child cameras support wake/sleep via hub relay. */
static int tapo_hub_command(iot_device_t *d, const char *cmd)
{
    /* Hub itself doesn't toggle — return status info instead */
    char result[IOT_BUF_SIZE * 2];
    int rlen;

    if (strcmp(cmd, "ON") == 0 || strcmp(cmd, "OFF") == 0) {
        /* Hub on/off not supported */
        if (g_core)
            g_core->log(g_core, PORTAL_LOG_WARN, "iot",
                        "Hub %s: on/off not supported (use child devices)", d->name);
        return -1;
    }

    /* STATUS command — get hub info + children */
    rlen = tapo_hub_get_info(d, result, sizeof(result));
    if (rlen > 0 && g_core)
        g_core->log(g_core, PORTAL_LOG_INFO, "iot",
                    "Hub %s: info (%d bytes)", d->name, rlen);
    rlen = tapo_hub_get_children(d, result, sizeof(result));
    if (rlen > 0) {
        if (g_core)
            g_core->log(g_core, PORTAL_LOG_INFO, "iot",
                        "Hub %s: children response (%d bytes)", d->name, rlen);
        return 0;
    }

    return -1;
}

/* ================================================================
 * Unified command dispatcher
 * ================================================================ */

static int iot_send_command(portal_core_t *core, iot_device_t *d, const char *cmd)
{
    int rc = -1;
    switch (d->driver) {
    case IOT_DRIVER_MQTT:     rc = mqtt_command(core, d, cmd); break;
    case IOT_DRIVER_HTTP:     rc = http_command(d, cmd); break;
    case IOT_DRIVER_TAPO:     rc = tapo_command(d, cmd); break;
    case IOT_DRIVER_TAPO_HUB: rc = tapo_hub_command(d, cmd); break;
    case IOT_DRIVER_GPIO:
        /* Use mod_gpio */
        if (core->module_loaded(core, "gpio")) {
            portal_msg_t *m = portal_msg_alloc();
            portal_resp_t *r = portal_resp_alloc();
            if (m && r) {
                portal_msg_set_path(m, "/gpio/functions/write");
                portal_msg_set_method(m, PORTAL_METHOD_CALL);
                portal_msg_add_header(m, "pin", d->topic);
                portal_msg_add_header(m, "value", strcmp(cmd, "ON") == 0 ? "1" : "0");
                core->send(core, m, r);
                rc = (r->status == PORTAL_OK) ? 0 : -1;
                portal_msg_free(m); portal_resp_free(r);
            }
        }
        break;
    }

    if (rc == 0) {
        d->state = (strcmp(cmd, "ON") == 0) ? IOT_STATE_ON :
                   (strcmp(cmd, "OFF") == 0) ? IOT_STATE_OFF : d->state;
        d->last_seen = (int64_t)time(NULL);
        g_commands++;
        core->event_emit(core, "/events/iot/state_change", d->name, strlen(d->name));
    }
    return rc;
}

/* ================================================================
 * Discovery: ARP scan + HTTP probe
 * ================================================================ */

static int discover_subnet(portal_core_t *core, const char *subnet,
                            const char *filter_brand, char *out, size_t outlen)
{
    size_t off = 0;
    if (filter_brand)
        off += (size_t)snprintf(out + off, outlen - off,
            "Scanning %s (filter: %s)...\n", subnet, filter_brand);
    else
        off += (size_t)snprintf(out + off, outlen - off,
            "Scanning %s...\n", subnet);

    /* Parse subnet: accepts 192.168.1.0/24, 192.168.1.0, or 192.168.1 */
    char base[48];
    snprintf(base, sizeof(base), "%s", subnet);
    char *slash = strchr(base, '/');
    if (slash) *slash = '\0';

    /* Count dots to validate format */
    int dots = 0;
    for (char *p = base; *p; p++) if (*p == '.') dots++;

    /* If only 2 dots (e.g. "192.168.0"), append a dot */
    if (dots == 2) {
        size_t blen = strlen(base);
        if (blen < sizeof(base) - 2) { base[blen] = '.'; base[blen + 1] = '\0'; }
    } else if (dots == 3) {
        /* Full IP: 192.168.0.0 → truncate to 192.168.0. */
        char *last_dot = strrchr(base, '.');
        if (last_dot) *(last_dot + 1) = '\0';
    } else {
        return 0;  /* invalid format */
    }

    int found = 0;

    /* Step 1: Fast ping sweep using fping (parallel) or fallback to arp-scan */
    core->log(core, PORTAL_LOG_INFO, "iot", "Discovery: scanning %s", subnet);

    char alive[256][64];
    int alive_count = 0;

    /* Try fping first (scans entire subnet in ~2 seconds) */
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "fping -a -g %s -t 200 -r 1 2>/dev/null", subnet);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        char line[64];
        while (fgets(line, sizeof(line), fp) && alive_count < 255) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            if (line[0])
                snprintf(alive[alive_count++], sizeof(alive[0]), "%s", line);
        }
        pclose(fp);
    }

    /* Fallback: sequential ping if fping not installed */
    if (alive_count == 0) {
        core->log(core, PORTAL_LOG_INFO, "iot",
                  "Discovery: fping not found, using sequential ping (slower)");
        off += (size_t)snprintf(out + off, outlen - off,
            "(Install fping for faster scans: apt install fping)\n");
        for (int i = 1; i < 255 && alive_count < 255; i++) {
            snprintf(cmd, sizeof(cmd), "ping -c1 -W1 %s%d >/dev/null 2>&1", base, i);
            if (system(cmd) == 0)
                snprintf(alive[alive_count++], sizeof(alive[0]), "%s%d", base, i);
        }
    }

    core->log(core, PORTAL_LOG_INFO, "iot",
              "Discovery: %d hosts alive, identifying...", alive_count);
    off += (size_t)snprintf(out + off, outlen - off,
        "%d hosts alive. Identifying...\n\n", alive_count);

    /* Step 2: Get MAC + identify each alive host */
    for (int h = 0; h < alive_count && off < outlen - 256; h++) {
        const char *ip = alive[h];

        /* Get MAC from ARP table */
        char arp_cmd[256], mac[20] = "";
        snprintf(arp_cmd, sizeof(arp_cmd),
            "arp -n %s 2>/dev/null | awk '/ether/{print $3}'", ip);
        fp = popen(arp_cmd, "r");
        if (fp) {
            if (fgets(mac, sizeof(mac), fp)) {
                char *nl = strchr(mac, '\n');
                if (nl) *nl = '\0';
            }
            pclose(fp);
        }

        /* Identify brand */
        const char *vendor = "Unknown";
        iot_brand_t brand = IOT_BRAND_UNKNOWN;
        if (mac[0]) brand = identify_mac(mac, &vendor);

        /* HTTP probe for more info */
        char model[64] = "";
        iot_driver_t driver = IOT_DRIVER_HTTP;

        if (brand == IOT_BRAND_SHELLY) {
            char buf[1024];
            char url[128];
            snprintf(url, sizeof(url), "http://%s/shelly", ip);
            if (http_get(url, buf, sizeof(buf)) > 0) {
                snprintf(model, sizeof(model), "Shelly");
                /* Try to extract model from JSON */
                char *mtype = strstr(buf, "\"type\":\"");
                if (mtype) sscanf(mtype + 8, "%63[^\"]", model);
            }
            driver = IOT_DRIVER_MQTT;  /* Shelly supports both */
        } else if (brand == IOT_BRAND_TASMOTA) {
            char buf[1024];
            char url[128];
            snprintf(url, sizeof(url), "http://%s/cm?cmnd=Status", ip);
            if (http_get(url, buf, sizeof(buf)) > 0)
                snprintf(model, sizeof(model), "Tasmota");
            driver = IOT_DRIVER_MQTT;
        } else if (brand == IOT_BRAND_TAPO) {
            snprintf(model, sizeof(model), "Tapo");
            driver = IOT_DRIVER_TAPO;
        }

        /* KLAP probe: try handshake1 on unknown hosts to detect Tapo devices */
        if (brand == IOT_BRAND_UNKNOWN) {
            unsigned char seed[16] = {0};
            unsigned char kresp[64];
            char kcookie[256] = "";
            int kstatus = 0;
            int krlen = tapo_http_post(ip, "/app/handshake1", NULL,
                                        seed, 16, kresp, sizeof(kresp),
                                        kcookie, sizeof(kcookie), &kstatus);
            if (kstatus == 200 && krlen >= 48) {
                brand = IOT_BRAND_TAPO;
                driver = IOT_DRIVER_TAPO;
                vendor = "TP-Link";
                snprintf(model, sizeof(model), "Tapo");
                core->log(core, PORTAL_LOG_INFO, "iot",
                          "KLAP probe: %s is Tapo (MAC: %s)", ip, mac);
            }
        }

        if (brand == IOT_BRAND_HUE) {
            snprintf(model, sizeof(model), "Hue Bridge");
            driver = IOT_DRIVER_HTTP;
        }

        off += (size_t)snprintf(out + off, outlen - off,
            "  %-16s %-18s %-12s %-10s %s\n",
            ip, mac[0] ? mac : "??:??:??",
            vendor, brand_name(brand), model);

        /* Skip if brand filter active and doesn't match */
        if (filter_brand && brand != IOT_BRAND_UNKNOWN &&
            strcasecmp(filter_brand, brand_name(brand)) != 0)
            continue;

        /* Auto-register if controllable */
        if (brand != IOT_BRAND_UNKNOWN && !find_device_by_ip(ip)) {
            char dname[64];
            snprintf(dname, sizeof(dname), "%s_%d",
                     brand_name(brand), h);
            /* Lowercase */
            for (char *p2 = dname; *p2; p2++)
                if (*p2 >= 'A' && *p2 <= 'Z') *p2 += 32;

            iot_device_t *dev = register_device(dname, ip, driver, brand);
            if (dev) {
                snprintf(dev->mac, sizeof(dev->mac), "%s", mac);
                snprintf(dev->model, sizeof(dev->model), "%s", model);
                /* Set default topic based on brand */
                switch (brand) {
                case IOT_BRAND_TASMOTA:
                case IOT_BRAND_SONOFF:
                    snprintf(dev->topic, sizeof(dev->topic), "tasmota_%s",
                             mac + 9);  /* last 8 chars of MAC */
                    break;
                case IOT_BRAND_SHELLY:
                    snprintf(dev->topic, sizeof(dev->topic), "shelly_%s",
                             mac + 9);
                    break;
                default:
                    snprintf(dev->topic, sizeof(dev->topic), "%s", ip);
                }
                core->event_emit(core, "/events/iot/discovered",
                                 dname, strlen(dname));
                found++;
            }
        }
    }

    off += (size_t)snprintf(out + off, outlen - off,
        "\nFound %d controllable devices.\n", found);
    return found;
}

/* ================================================================
 * Module lifecycle
 * ================================================================ */

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_devices, 0, sizeof(g_devices));
    g_count = 0;
    g_discovered = 0;
    g_commands = 0;

    const char *v;
    if ((v = core->config_get(core, "iot", "max_devices")))
        g_max = atoi(v);
    if ((v = core->config_get(core, "iot", "poll_interval")))
        g_poll_interval = atoi(v);
    if ((v = core->config_get(core, "iot", "tapo_email")))
        snprintf(g_tapo_email, sizeof(g_tapo_email), "%s", v);
    if ((v = core->config_get(core, "iot", "tapo_password")))
        snprintf(g_tapo_pass, sizeof(g_tapo_pass), "%s", v);

    /* Resources (READ) */
    core->path_register(core, "/iot/resources/status", "iot");
    core->path_set_access(core, "/iot/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/iot/resources/devices", "iot");
    core->path_set_access(core, "/iot/resources/devices", PORTAL_ACCESS_READ);

    /* Functions (RW) */
    core->path_register(core, "/iot/functions/discover", "iot");
    core->path_set_access(core, "/iot/functions/discover", PORTAL_ACCESS_RW);
    core->path_register(core, "/iot/functions/add", "iot");
    core->path_set_access(core, "/iot/functions/add", PORTAL_ACCESS_RW);
    core->path_register(core, "/iot/functions/remove", "iot");
    core->path_set_access(core, "/iot/functions/remove", PORTAL_ACCESS_RW);
    core->path_register(core, "/iot/functions/on", "iot");
    core->path_set_access(core, "/iot/functions/on", PORTAL_ACCESS_RW);
    core->path_register(core, "/iot/functions/off", "iot");
    core->path_set_access(core, "/iot/functions/off", PORTAL_ACCESS_RW);
    core->path_register(core, "/iot/functions/toggle", "iot");
    core->path_set_access(core, "/iot/functions/toggle", PORTAL_ACCESS_RW);
    core->path_register(core, "/iot/functions/status", "iot");
    core->path_set_access(core, "/iot/functions/status", PORTAL_ACCESS_RW);
    core->path_register(core, "/iot/functions/children", "iot");
    core->path_set_access(core, "/iot/functions/children", PORTAL_ACCESS_RW);
    core->path_register(core, "/iot/functions/vacuum", "iot");
    core->path_set_access(core, "/iot/functions/vacuum", PORTAL_ACCESS_RW);
    core->path_register(core, "/iot/functions/bulb", "iot");
    core->path_set_access(core, "/iot/functions/bulb", PORTAL_ACCESS_RW);
    core->path_register(core, "/iot/functions/refresh", "iot");
    core->path_set_access(core, "/iot/functions/refresh", PORTAL_ACCESS_RW);

    /* Set up device persistence directory */
    const char *data_dir = core->config_get(core, "core", "data_dir");
    if (data_dir) {
        snprintf(g_iot_dir, sizeof(g_iot_dir), "%s/iot", data_dir);
        mkdir(g_iot_dir, 0755);
    }

    /* Load saved devices from config files */
    int loaded = devices_load_all(core);

    core->log(core, PORTAL_LOG_INFO, "iot",
              "IoT manager ready (max: %d, loaded: %d, poll: %ds, tapo: %s, dir: %s)",
              g_max, loaded, g_poll_interval,
              g_tapo_email[0] ? "configured" : "no credentials",
              g_iot_dir[0] ? g_iot_dir : "(none)");
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/iot/resources/status");
    core->path_unregister(core, "/iot/resources/devices");
    core->path_unregister(core, "/iot/functions/discover");
    core->path_unregister(core, "/iot/functions/add");
    core->path_unregister(core, "/iot/functions/remove");
    core->path_unregister(core, "/iot/functions/on");
    core->path_unregister(core, "/iot/functions/off");
    core->path_unregister(core, "/iot/functions/toggle");
    core->path_unregister(core, "/iot/functions/status");
    core->path_unregister(core, "/iot/functions/children");
    core->path_unregister(core, "/iot/functions/vacuum");
    core->path_unregister(core, "/iot/functions/bulb");
    core->path_unregister(core, "/iot/functions/refresh");
    core->log(core, PORTAL_LOG_INFO, "iot", "IoT manager unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

/* ================================================================
 * Request handler
 * ================================================================ */

/* Background discover thread — scans subnet without blocking event loop */
static void *discover_thread(void *arg)
{
    struct { char subnet[64]; char brand[32]; portal_core_t *core; } *a = arg;
    char result[8192];
    discover_subnet(a->core, a->subnet, a->brand[0] ? a->brand : NULL,
                    result, sizeof(result));
    if (g_core)
        g_core->log(g_core, PORTAL_LOG_INFO, "iot",
                    "Discovery on %s complete", a->subnet);
    free(a);
    return NULL;
}

/* Background refresh thread — queries all Tapo devices without blocking event loop */
static void *refresh_thread(void *arg)
{
    portal_core_t *core = (portal_core_t *)arg;
    int ok = 0, fail = 0;
    for (int i = 0; i < g_count; i++) {
        if (!g_devices[i].active) continue;
        iot_device_t *d = &g_devices[i];
        if (d->driver == IOT_DRIVER_TAPO || d->driver == IOT_DRIVER_TAPO_HUB) {
            if (iot_send_command(core, d, "STATUS") == 0)
                ok++;
            else
                fail++;
        }
    }
    if (g_core)
        g_core->log(g_core, PORTAL_LOG_INFO, "iot",
                    "Refresh complete: %d OK, %d failed", ok, fail);
    return NULL;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[32768];
    int n;

    /* --- /iot/resources/status --- */
    if (strcmp(msg->path, "/iot/resources/status") == 0) {
        int online = 0, ctrl = 0;
        for (int i = 0; i < g_count; i++) {
            if (!g_devices[i].active) continue;
            ctrl++;
            if (g_devices[i].online) online++;
        }
        n = snprintf(buf, sizeof(buf),
            "IoT Device Manager\n"
            "Devices: %d registered, %d online\n"
            "Max devices: %d\n"
            "Poll interval: %ds\n"
            "Tapo credentials: %s\n"
            "Total discovered: %lld\n"
            "Total commands: %lld\n"
            "Supported brands: Tasmota, Shelly, Sonoff, Zigbee, Tapo, Hue, Tuya, Meross, GPIO\n"
            "Drivers: mqtt, http, tapo, gpio\n",
            ctrl, online, g_max, g_poll_interval,
            g_tapo_email[0] ? "configured" : "not set",
            (long long)g_discovered, (long long)g_commands);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* --- /iot/resources/devices --- */
    if (strcmp(msg->path, "/iot/resources/devices") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
            "%-16s %-8s %-6s %-8s %-18s %-19s %-8s %s\n",
            "NAME", "MODEL", "STATE", "POWER", "IP", "MAC", "BRAND", "ID");
        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
            "%-16s %-8s %-6s %-8s %-18s %-19s %-8s %s\n",
            "----", "-----", "-----", "-----", "--", "---", "-----", "-----");
        for (int i = 0; i < g_count && off < sizeof(buf) - 256; i++) {
            if (!g_devices[i].active) continue;
            iot_device_t *d = &g_devices[i];
            char power[16] = "-";
            if (d->power_watts > 0)
                snprintf(power, sizeof(power), "%.1fW", d->power_watts);
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "%-16s %-8s %-6s %-8s %-18s %-19s %-8s %s\n",
                d->name,
                d->model[0] ? d->model : "?",
                state_name(d->state), power, d->ip,
                d->mac[0] ? d->mac : "-",
                brand_name(d->brand), d->topic);
        }
        if (g_count == 0)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "(no devices)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    /* --- /iot/functions/discover --- */
    if (strcmp(msg->path, "/iot/functions/discover") == 0) {
        const char *subnet = get_hdr(msg, "subnet");
        if (!subnet) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: subnet header (e.g. 192.168.1.0/24)\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        typedef struct { char subnet[64]; char brand[32]; portal_core_t *core; } disc_arg_t;
        disc_arg_t *a = malloc(sizeof(*a));
        snprintf(a->subnet, sizeof(a->subnet), "%s", subnet);
        const char *brand_filter = get_hdr(msg, "brand");
        if (brand_filter)
            snprintf(a->brand, sizeof(a->brand), "%s", brand_filter);
        else
            a->brand[0] = '\0';
        a->core = core;
        pthread_t th;
        pthread_create(&th, NULL, discover_thread, a);
        pthread_detach(th);
        n = snprintf(buf, sizeof(buf), "Discovering devices on %s in background...\n", subnet);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* --- /iot/functions/add --- */
    if (strcmp(msg->path, "/iot/functions/add") == 0) {
        const char *name = get_hdr(msg, "name");
        const char *ip = get_hdr(msg, "ip");
        const char *drv = get_hdr(msg, "driver");
        const char *brn = get_hdr(msg, "brand");
        const char *topic = get_hdr(msg, "topic");
        if (!name || !ip) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf),
                "Need: name, ip headers. Optional: driver, brand, topic\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        iot_driver_t driver = IOT_DRIVER_MQTT;
        if (drv) {
            if (strcmp(drv, "http") == 0) driver = IOT_DRIVER_HTTP;
            else if (strcmp(drv, "tapo") == 0) driver = IOT_DRIVER_TAPO;
            else if (strcmp(drv, "gpio") == 0) driver = IOT_DRIVER_GPIO;
        }

        iot_brand_t brand = IOT_BRAND_UNKNOWN;
        if (brn) {
            if (strcasecmp(brn, "tasmota") == 0) brand = IOT_BRAND_TASMOTA;
            else if (strcasecmp(brn, "shelly") == 0) brand = IOT_BRAND_SHELLY;
            else if (strcasecmp(brn, "sonoff") == 0) brand = IOT_BRAND_SONOFF;
            else if (strcasecmp(brn, "zigbee") == 0) brand = IOT_BRAND_ZIGBEE;
            else if (strcasecmp(brn, "tapo") == 0) { brand = IOT_BRAND_TAPO; driver = IOT_DRIVER_TAPO; }
            else if (strcasecmp(brn, "tapo_hub") == 0) { brand = IOT_BRAND_TAPO; driver = IOT_DRIVER_TAPO_HUB; }
            else if (strcasecmp(brn, "hue") == 0) { brand = IOT_BRAND_HUE; driver = IOT_DRIVER_HTTP; }
            else if (strcasecmp(brn, "gpio") == 0) { brand = IOT_BRAND_GPIO; driver = IOT_DRIVER_GPIO; }
        }

        iot_device_t *d = register_device(name, ip, driver, brand);
        if (!d) {
            portal_resp_set_status(resp, PORTAL_CONFLICT);
            n = snprintf(buf, sizeof(buf), "Device '%s' already exists or max reached\n", name);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (topic) snprintf(d->topic, sizeof(d->topic), "%s", topic);
        else snprintf(d->topic, sizeof(d->topic), "%s", name);

        core->event_emit(core, "/events/iot/registered", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_CREATED);
        n = snprintf(buf, sizeof(buf), "Device '%s' registered (%s/%s at %s)\n",
                     name, driver_name(driver), brand_name(brand), ip);
        portal_resp_set_body(resp, buf, (size_t)n);
        core->log(core, PORTAL_LOG_INFO, "iot", "Registered '%s' (%s/%s at %s)",
                  name, driver_name(driver), brand_name(brand), ip);
        return 0;
    }

    /* --- /iot/functions/remove --- */
    if (strcmp(msg->path, "/iot/functions/remove") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        iot_device_t *d = find_device(name);
        if (!d) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        d->active = 0;
        device_delete(name);
        core->event_emit(core, "/events/iot/removed", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Device '%s' removed\n", name);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* --- /iot/functions/on --- */
    if (strcmp(msg->path, "/iot/functions/on") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        iot_device_t *d = find_device(name);
        if (!d) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        /* Auto-lock device */
        char res[128], own[128];
        snprintf(res, sizeof(res), "/iot/%s", d->name);
        const char *usr = (msg->ctx && msg->ctx->auth.user) ? msg->ctx->auth.user : "?";
        snprintf(own, sizeof(own), "%s", usr);
        if (core->resource_locked(core, res)) {
            const char *cur = core->resource_owner(core, res);
            if (!cur || strcmp(cur, own) != 0) {
                n = snprintf(buf, sizeof(buf), "Device locked by: %s\n", cur ? cur : "?");
                portal_resp_set_status(resp, PORTAL_FORBIDDEN);
                portal_resp_set_body(resp, buf, (size_t)n);
                return -1;
            }
            core->resource_keepalive(core, res, own);
        } else {
            core->resource_lock(core, res, own);
        }
        int rc = iot_send_command(core, d, "ON");
        n = snprintf(buf, sizeof(buf), "%s: %s\n", name, rc == 0 ? "ON" : "FAILED");
        portal_resp_set_status(resp, rc == 0 ? PORTAL_OK : PORTAL_UNAVAILABLE);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* --- /iot/functions/off --- */
    if (strcmp(msg->path, "/iot/functions/off") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        iot_device_t *d = find_device(name);
        if (!d) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        char res[128], own[128];
        snprintf(res, sizeof(res), "/iot/%s", d->name);
        const char *usr = (msg->ctx && msg->ctx->auth.user) ? msg->ctx->auth.user : "?";
        snprintf(own, sizeof(own), "%s", usr);
        if (core->resource_locked(core, res)) {
            const char *cur = core->resource_owner(core, res);
            if (!cur || strcmp(cur, own) != 0) {
                n = snprintf(buf, sizeof(buf), "Device locked by: %s\n", cur ? cur : "?");
                portal_resp_set_status(resp, PORTAL_FORBIDDEN);
                portal_resp_set_body(resp, buf, (size_t)n);
                return -1;
            }
            core->resource_keepalive(core, res, own);
        } else {
            core->resource_lock(core, res, own);
        }
        int rc = iot_send_command(core, d, "OFF");
        n = snprintf(buf, sizeof(buf), "%s: %s\n", name, rc == 0 ? "OFF" : "FAILED");
        portal_resp_set_status(resp, rc == 0 ? PORTAL_OK : PORTAL_UNAVAILABLE);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* --- /iot/functions/toggle --- */
    if (strcmp(msg->path, "/iot/functions/toggle") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        iot_device_t *d = find_device(name);
        if (!d) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        char res[128], own[128];
        snprintf(res, sizeof(res), "/iot/%s", d->name);
        const char *usr = (msg->ctx && msg->ctx->auth.user) ? msg->ctx->auth.user : "?";
        snprintf(own, sizeof(own), "%s", usr);
        if (core->resource_locked(core, res)) {
            const char *cur = core->resource_owner(core, res);
            if (!cur || strcmp(cur, own) != 0) {
                n = snprintf(buf, sizeof(buf), "Device locked by: %s\n", cur ? cur : "?");
                portal_resp_set_status(resp, PORTAL_FORBIDDEN);
                portal_resp_set_body(resp, buf, (size_t)n);
                return -1;
            }
            core->resource_keepalive(core, res, own);
        } else {
            core->resource_lock(core, res, own);
        }
        const char *cmd = (d->state == IOT_STATE_ON) ? "OFF" : "ON";
        int rc = iot_send_command(core, d, cmd);
        n = snprintf(buf, sizeof(buf), "%s: %s\n", name, rc == 0 ? state_name(d->state) : "FAILED");
        portal_resp_set_status(resp, rc == 0 ? PORTAL_OK : PORTAL_UNAVAILABLE);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* --- /iot/functions/status --- */
    if (strcmp(msg->path, "/iot/functions/status") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) {
            /* Status all */
            size_t off = 0;
            for (int i = 0; i < g_count && off < sizeof(buf) - 128; i++) {
                if (!g_devices[i].active) continue;
                iot_device_t *d = &g_devices[i];
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "%-16s %-6s %-6s %s\n",
                    d->name, state_name(d->state),
                    d->online ? "online" : "offline", d->ip);
            }
            if (off == 0) off = (size_t)snprintf(buf, sizeof(buf), "(no devices)\n");
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, buf, off);
            return 0;
        }
        iot_device_t *d = find_device(name);
        if (!d) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }

        /* Query live state from device if it supports it */
        if (d->driver == IOT_DRIVER_TAPO) {
            int qrc = iot_send_command(core, d, "STATUS");
            core->log(core, PORTAL_LOG_DEBUG, "iot",
                      "Live query %s: %s (state: %s)",
                      d->name, qrc == 0 ? "OK" : "FAILED",
                      d->state == IOT_STATE_ON ? "ON" :
                      d->state == IOT_STATE_OFF ? "OFF" : "?");
        }

        n = snprintf(buf, sizeof(buf),
            "Device: %s\n"
            "IP: %s\n"
            "MAC: %s\n"
            "Driver: %s\n"
            "Brand: %s\n"
            "Model: %s\n"
            "State: %s\n"
            "Power: %.1f W\n"
            "Online: %s\n"
            "Topic: %s\n",
            d->name, d->ip, d->mac,
            driver_name(d->driver), brand_name(d->brand),
            d->model[0] ? d->model : "?",
            state_name(d->state), d->power_watts,
            d->online ? "yes" : "no", d->topic);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* --- /iot/functions/children --- */
    if (strcmp(msg->path, "/iot/functions/children") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: name header (hub device name)\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        iot_device_t *d = find_device(name);
        if (!d) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        if (d->driver != IOT_DRIVER_TAPO_HUB) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "'%s' is not a hub device\n", name);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        char result[IOT_BUF_SIZE * 2];
        int rlen = tapo_hub_get_children(d, result, sizeof(result));
        if (rlen <= 0) {
            portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
            n = snprintf(buf, sizeof(buf), "Hub '%s' unreachable or auth failed\n", name);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        /* Parse child device list and format nicely */
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
            "Hub: %s (%s)\n\n"
            "%-16s %-8s %-8s %-5s %-10s %-6s %s\n"
            "%-16s %-8s %-8s %-5s %-10s %-6s %s\n",
            name, d->ip,
            "NAME", "MODEL", "ONLINE", "BAT%", "POWER", "RSSI", "MAC",
            "----", "-----", "------", "----", "-----", "----", "---");

        /* Walk JSON for child_device_list entries */
        const char *p = strstr(result, "\"child_device_list\"");
        if (p) {
            const char *entry = p;
            while ((entry = strstr(entry, "\"alias\"")) != NULL) {
                /* Extract fields from this child entry */
                /* Find the enclosing object start (search backwards for '{') */
                const char *obj_start = entry;
                while (obj_start > result && *obj_start != '{') obj_start--;

                /* Find reasonable end (next '}' after several fields) */
                const char *obj_end = strstr(entry, "\"migrate_status\"");
                if (!obj_end) obj_end = entry + 500;
                int obj_len = (int)(obj_end - obj_start + 100);
                if (obj_len > 2000) obj_len = 2000;

                char alias[64] = "?", model[32] = "?", mac[20] = "?", power[16] = "?";
                int online = 0, battery = -1, rssi = 0;

                /* Parse alias */
                hub_json_str(obj_start, "alias", alias, sizeof(alias));
                hub_json_str(obj_start, "device_model", model, sizeof(model));
                hub_json_str(obj_start, "mac", mac, sizeof(mac));

                char sbuf[16];
                if (hub_json_str(obj_start, "power", sbuf, sizeof(sbuf)))
                    snprintf(power, sizeof(power), "%s", sbuf);

                online = hub_json_int(obj_start, "online") == 1 ? 1 : 0;
                battery = hub_json_int(obj_start, "battery_percent");
                rssi = hub_json_int(obj_start, "rssi");
                if (rssi == -999999) rssi = 0;

                char bat_str[16] = "-";
                if (battery >= 0) snprintf(bat_str, sizeof(bat_str), "%d%%", battery);

                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "%-16s %-8s %-8s %-5s %-10s %-6d %s\n",
                    alias, model, online ? "yes" : "no", bat_str, power, rssi, mac);

                entry++;  /* advance past this alias */
            }
        }

        if (off == 0) {
            off = (size_t)snprintf(buf, sizeof(buf), "Raw: %.*s\n",
                                    rlen > 2000 ? 2000 : rlen, result);
        }

        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    /* --- /iot/functions/refresh — query all devices for live state (background) --- */
    if (strcmp(msg->path, "/iot/functions/refresh") == 0) {
        /* Count devices to refresh */
        int count = 0;
        for (int i = 0; i < g_count; i++)
            if (g_devices[i].active &&
                (g_devices[i].driver == IOT_DRIVER_TAPO ||
                 g_devices[i].driver == IOT_DRIVER_TAPO_HUB))
                count++;

        /* Spawn background thread — don't block the event loop */
        pthread_t th;
        pthread_create(&th, NULL, refresh_thread, core);
        pthread_detach(th);

        n = snprintf(buf, sizeof(buf),
            "Refreshing %d devices in background...\n", count);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* --- /iot/functions/vacuum — robot vacuum control --- */
    if (strcmp(msg->path, "/iot/functions/vacuum") == 0) {
        const char *name = get_hdr(msg, "name");
        const char *cmd = get_hdr(msg, "cmd");
        if (!name || !cmd) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf),
                "Need: name, cmd (start|stop|dock|status) headers\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        iot_device_t *d = find_device(name);
        if (!d) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }

        char result[IOT_BUF_SIZE * 2];
        int rc = tapo_vacuum_command(d, cmd, result, sizeof(result));
        if (rc >= 0 && result[0]) {
            n = snprintf(buf, sizeof(buf), "Vacuum %s: %s\n%.*s\n",
                         name, cmd, rc > 2000 ? 2000 : rc, result);
        } else {
            n = snprintf(buf, sizeof(buf), "Vacuum %s: %s %s\n",
                         name, cmd, rc == 0 ? "OK" : "FAILED");
        }
        portal_resp_set_status(resp, rc >= 0 ? PORTAL_OK : PORTAL_UNAVAILABLE);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* --- /iot/functions/bulb — light bulb control --- */
    if (strcmp(msg->path, "/iot/functions/bulb") == 0) {
        const char *name = get_hdr(msg, "name");
        const char *cmd = get_hdr(msg, "cmd");
        if (!name || !cmd) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf),
                "Need: name, cmd headers\n"
                "  cmd=brightness <1-100>\n"
                "  cmd=color_temp <2500-6500>\n"
                "  cmd=hue <0-360> [saturation 0-100]\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        iot_device_t *d = find_device(name);
        if (!d) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }

        int rc = tapo_bulb_command(d, cmd);
        n = snprintf(buf, sizeof(buf), "Bulb %s: %s %s\n",
                     name, cmd, rc == 0 ? "OK" : "FAILED");
        portal_resp_set_status(resp, rc == 0 ? PORTAL_OK : PORTAL_UNAVAILABLE);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
