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
 * mod_gpio — GPIO pin control for IoT/embedded
 *
 * Control GPIO pins via sysfs (/sys/class/gpio) or
 * configurable backend. Export, set direction, read/write values.
 * Designed for Raspberry Pi, BeagleBone, and similar SBCs.
 *
 * Config:
 *   [mod_gpio]
 *   sysfs_path = /sys/class/gpio
 *   max_pins = 64
 *   simulate = false
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "portal/portal.h"

#define GPIO_MAX_PINS    64
#define GPIO_SYSFS       "/sys/class/gpio"

typedef struct {
    int   pin;
    char  direction[8];  /* "in" or "out" */
    int   value;
    int   exported;
    int   simulated;     /* if sysfs not available */
} gpio_pin_t;

static portal_core_t *g_core = NULL;
static gpio_pin_t     g_pins[GPIO_MAX_PINS];
static int            g_pin_count = 0;
static int            g_max_pins = GPIO_MAX_PINS;
static char           g_sysfs[256] = GPIO_SYSFS;
static int            g_simulate = 0;
static int64_t        g_reads = 0;
static int64_t        g_writes = 0;

static portal_module_info_t info = {
    .name = "gpio", .version = "1.0.0",
    .description = "GPIO pin control for IoT/embedded",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

static gpio_pin_t *find_pin(int pin)
{
    for (int i = 0; i < g_pin_count; i++)
        if (g_pins[i].exported && g_pins[i].pin == pin)
            return &g_pins[i];
    return NULL;
}

static int sysfs_write(const char *path, const char *val)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t w = write(fd, val, strlen(val));
    close(fd);
    return w > 0 ? 0 : -1;
}

static int sysfs_read(const char *path, char *val, size_t len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, val, len - 1);
    close(fd);
    if (r <= 0) return -1;
    val[r] = '\0';
    /* Strip newline */
    if (r > 0 && val[r - 1] == '\n') val[r - 1] = '\0';
    return 0;
}

/* Check/acquire lock for exclusive pin operations */
static int check_pin_lock(portal_core_t *core, int pin,
                           const portal_msg_t *msg, portal_resp_t *resp)
{
    char resource[64], owner[128];
    snprintf(resource, sizeof(resource), "/gpio/%d", pin);
    const char *user = (msg->ctx && msg->ctx->auth.user) ? msg->ctx->auth.user : "?";
    snprintf(owner, sizeof(owner), "%s", user);

    if (core->resource_locked(core, resource)) {
        const char *cur = core->resource_owner(core, resource);
        if (!cur || strcmp(cur, owner) != 0) {
            portal_resp_set_status(resp, PORTAL_FORBIDDEN);
            char buf[256];
            int n = snprintf(buf, sizeof(buf), "GPIO%d locked by: %s\n", pin, cur ? cur : "?");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        core->resource_keepalive(core, resource, owner);
    } else {
        core->resource_lock(core, resource, owner);
    }
    return 0;
}

static int gpio_export(int pin)
{
    if (g_simulate) return 0;
    char path[512];
    snprintf(path, sizeof(path), "%s/export", g_sysfs);
    char val[16];
    snprintf(val, sizeof(val), "%d", pin);
    return sysfs_write(path, val);
}

static int gpio_unexport(int pin)
{
    if (g_simulate) return 0;
    char path[512];
    snprintf(path, sizeof(path), "%s/unexport", g_sysfs);
    char val[16];
    snprintf(val, sizeof(val), "%d", pin);
    return sysfs_write(path, val);
}

static int gpio_set_direction(int pin, const char *dir)
{
    if (g_simulate) return 0;
    char path[512];
    snprintf(path, sizeof(path), "%s/gpio%d/direction", g_sysfs, pin);
    return sysfs_write(path, dir);
}

static int gpio_write_value(int pin, int val)
{
    if (g_simulate) return 0;
    char path[512];
    snprintf(path, sizeof(path), "%s/gpio%d/value", g_sysfs, pin);
    return sysfs_write(path, val ? "1" : "0");
}

static int gpio_read_value(int pin)
{
    if (g_simulate) {
        gpio_pin_t *p = find_pin(pin);
        return p ? p->value : 0;
    }
    char path[512], val[16];
    snprintf(path, sizeof(path), "%s/gpio%d/value", g_sysfs, pin);
    if (sysfs_read(path, val, sizeof(val)) < 0) return -1;
    return atoi(val);
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_pins, 0, sizeof(g_pins));
    g_pin_count = 0;
    g_reads = g_writes = 0;

    const char *v;
    if ((v = core->config_get(core, "gpio", "sysfs_path")))
        snprintf(g_sysfs, sizeof(g_sysfs), "%s", v);
    if ((v = core->config_get(core, "gpio", "max_pins")))
        g_max_pins = atoi(v);
    if ((v = core->config_get(core, "gpio", "simulate")))
        g_simulate = (strcmp(v, "true") == 0 || strcmp(v, "1") == 0);

    /* Auto-detect: if sysfs not available, enable simulation */
    if (access(g_sysfs, F_OK) != 0) {
        g_simulate = 1;
        core->log(core, PORTAL_LOG_WARN, "gpio",
                  "GPIO sysfs not found, simulation mode enabled");
    }

    core->path_register(core, "/gpio/resources/status", "gpio");
    core->path_set_access(core, "/gpio/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/gpio/resources/status", "GPIO module: max pins, sysfs path, simulate mode");
    core->path_register(core, "/gpio/resources/pins", "gpio");
    core->path_set_access(core, "/gpio/resources/pins", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/gpio/resources/pins", "List exported GPIO pins with direction and value");
    core->path_register(core, "/gpio/functions/export", "gpio");
    core->path_set_access(core, "/gpio/functions/export", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/gpio/functions/export", "Export a GPIO pin. Header: pin (number)");
    core->path_register(core, "/gpio/functions/unexport", "gpio");
    core->path_set_access(core, "/gpio/functions/unexport", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/gpio/functions/unexport", "Unexport a GPIO pin. Header: pin");
    core->path_register(core, "/gpio/functions/direction", "gpio");
    core->path_set_access(core, "/gpio/functions/direction", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/gpio/functions/direction", "Set pin direction. Headers: pin, direction (in/out)");
    core->path_register(core, "/gpio/functions/read", "gpio");
    core->path_set_access(core, "/gpio/functions/read", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/gpio/functions/read", "Read pin value. Header: pin");
    core->path_register(core, "/gpio/functions/write", "gpio");
    core->path_set_access(core, "/gpio/functions/write", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/gpio/functions/write", "Write to pin. Headers: pin, value (0/1)");

    core->log(core, PORTAL_LOG_INFO, "gpio",
              "GPIO ready (sysfs: %s, simulate: %s, max: %d pins)",
              g_sysfs, g_simulate ? "yes" : "no", g_max_pins);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    /* Unexport all pins */
    for (int i = 0; i < g_pin_count; i++) {
        if (g_pins[i].exported)
            gpio_unexport(g_pins[i].pin);
    }

    core->path_unregister(core, "/gpio/resources/status");
    core->path_unregister(core, "/gpio/resources/pins");
    core->path_unregister(core, "/gpio/functions/export");
    core->path_unregister(core, "/gpio/functions/unexport");
    core->path_unregister(core, "/gpio/functions/direction");
    core->path_unregister(core, "/gpio/functions/read");
    core->path_unregister(core, "/gpio/functions/write");
    core->log(core, PORTAL_LOG_INFO, "gpio", "GPIO unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[8192];
    int n;

    if (strcmp(msg->path, "/gpio/resources/status") == 0) {
        int exported = 0;
        for (int i = 0; i < g_pin_count; i++)
            if (g_pins[i].exported) exported++;
        n = snprintf(buf, sizeof(buf),
            "GPIO Module\n"
            "Mode: %s\n"
            "Sysfs: %s\n"
            "Exported pins: %d (max %d)\n"
            "Reads: %lld\n"
            "Writes: %lld\n",
            g_simulate ? "simulation" : "hardware",
            g_sysfs, exported, g_max_pins,
            (long long)g_reads, (long long)g_writes);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/gpio/resources/pins") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "GPIO Pins:\n");
        for (int i = 0; i < g_pin_count; i++) {
            if (!g_pins[i].exported) continue;
            int val = gpio_read_value(g_pins[i].pin);
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "  GPIO%-4d dir: %-4s value: %d\n",
                g_pins[i].pin, g_pins[i].direction,
                val >= 0 ? val : g_pins[i].value);
        }
        if (g_pin_count == 0)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/gpio/functions/export") == 0) {
        const char *pin_s = get_hdr(msg, "pin");
        const char *dir = get_hdr(msg, "direction");
        if (!pin_s) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: pin header (optional: direction=in|out)\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        int pin = atoi(pin_s);
        if (check_pin_lock(core, pin, msg, resp) < 0) return -1;
        if (find_pin(pin)) {
            portal_resp_set_status(resp, PORTAL_CONFLICT);
            n = snprintf(buf, sizeof(buf), "GPIO%d already exported\n", pin);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (g_pin_count >= g_max_pins) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            return -1;
        }

        if (gpio_export(pin) < 0 && !g_simulate) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            n = snprintf(buf, sizeof(buf), "Failed to export GPIO%d: %s\n",
                         pin, strerror(errno));
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        if (!dir) dir = "in";
        if (!g_simulate) {
            usleep(100000);  /* sysfs needs time to create nodes */
            gpio_set_direction(pin, dir);
        }

        gpio_pin_t *p = &g_pins[g_pin_count++];
        p->pin = pin;
        snprintf(p->direction, sizeof(p->direction), "%s", dir);
        p->value = 0;
        p->exported = 1;
        p->simulated = g_simulate;

        core->event_emit(core, "/events/gpio/export", pin_s, strlen(pin_s));
        portal_resp_set_status(resp, PORTAL_CREATED);
        n = snprintf(buf, sizeof(buf), "GPIO%d exported (dir: %s, mode: %s)\n",
                     pin, dir, g_simulate ? "simulated" : "hardware");
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/gpio/functions/unexport") == 0) {
        const char *pin_s = get_hdr(msg, "pin");
        if (!pin_s) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        int pin = atoi(pin_s);
        if (check_pin_lock(core, pin, msg, resp) < 0) return -1;
        gpio_pin_t *p = find_pin(pin);
        if (!p) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        /* Release lock on unexport */
        char res[64], own[128];
        snprintf(res, sizeof(res), "/gpio/%d", pin);
        const char *u = (msg->ctx && msg->ctx->auth.user) ? msg->ctx->auth.user : "?";
        snprintf(own, sizeof(own), "%s", u);
        core->resource_unlock(core, res, own);
        gpio_unexport(pin);
        p->exported = 0;
        core->event_emit(core, "/events/gpio/unexport", pin_s, strlen(pin_s));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "GPIO%d unexported\n", pin);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/gpio/functions/direction") == 0) {
        const char *pin_s = get_hdr(msg, "pin");
        const char *dir = get_hdr(msg, "direction");
        if (!pin_s || !dir) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: pin, direction (in|out) headers\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        int pin = atoi(pin_s);
        if (check_pin_lock(core, pin, msg, resp) < 0) return -1;
        gpio_pin_t *p = find_pin(pin);
        if (!p) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        gpio_set_direction(pin, dir);
        snprintf(p->direction, sizeof(p->direction), "%s", dir);
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "GPIO%d direction set to %s\n", pin, dir);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/gpio/functions/read") == 0) {
        const char *pin_s = get_hdr(msg, "pin");
        if (!pin_s) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        int pin = atoi(pin_s);
        gpio_pin_t *p = find_pin(pin);
        if (!p) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        int val = gpio_read_value(pin);
        if (val < 0) val = p->value;
        g_reads++;
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "%d\n", val);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/gpio/functions/write") == 0) {
        const char *pin_s = get_hdr(msg, "pin");
        const char *val_s = get_hdr(msg, "value");
        if (!pin_s || !val_s) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: pin, value (0|1) headers\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        int pin = atoi(pin_s);
        int val = atoi(val_s);
        if (check_pin_lock(core, pin, msg, resp) < 0) return -1;
        gpio_pin_t *p = find_pin(pin);
        if (!p) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        if (strcmp(p->direction, "out") != 0) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "GPIO%d is input, cannot write\n", pin);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        gpio_write_value(pin, val);
        p->value = val ? 1 : 0;
        g_writes++;
        core->event_emit(core, "/events/gpio/write", pin_s, strlen(pin_s));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "GPIO%d = %d\n", pin, p->value);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
