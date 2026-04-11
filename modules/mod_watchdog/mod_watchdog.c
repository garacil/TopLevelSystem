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
 * mod_watchdog — Hardware watchdog keepalive for Portal
 *
 * Opens /dev/watchdog and writes a keepalive byte at a configurable interval.
 * If Portal dies, the hardware timer expires and the system reboots —
 * exactly what you want on unattended embedded/appliance devices.
 *
 * Resources (READ):
 *   /watchdog/resources/status   — Current state, ticks, last kick time
 *
 * Functions (RW):
 *   /watchdog/functions/enable   — Open /dev/watchdog and start kicking
 *   /watchdog/functions/disable  — Stop kicking (writes 'V' magic close)
 *
 * Events:
 *   /events/watchdog/started     — Watchdog opened and ticking
 *   /events/watchdog/stopped     — Watchdog closed (magic close)
 *   /events/watchdog/failed      — Failed to open or write to device
 *
 * Config (mod_watchdog.conf):
 *   device    = /dev/watchdog     Device path
 *   interval  = 15                Kick interval in seconds
 *   auto_start = false            Open device on module load
 *
 * Law 14: /dev/watchdog is exclusively locked via resource_lock().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/watchdog.h>
#include "portal/portal.h"

/* --- State --- */
static portal_core_t *g_core    = NULL;
static int            g_fd      = -1;       /* /dev/watchdog fd */
static int            g_active  = 0;        /* 1 = ticking */
static uint64_t       g_ticks   = 0;        /* total kicks */
static time_t         g_last    = 0;        /* last kick timestamp */
static time_t         g_started = 0;        /* when watchdog was opened */
static char           g_device[128] = "/dev/watchdog";
static double         g_interval = 15.0;    /* seconds between kicks */
static int            g_hw_timeout = 0;     /* hardware timeout (from ioctl) */

/* --- Module info --- */
static portal_module_info_t info = {
    .name        = "watchdog",
    .version     = "1.0.0",
    .description = "Hardware watchdog keepalive",
    .soft_deps   = NULL
};

portal_module_info_t *portal_module_info(void) { return &info; }

/* --- Keepalive timer callback --- */
static void watchdog_kick(void *userdata)
{
    (void)userdata;
    if (g_fd < 0 || !g_active) return;

    /* Write a byte to pet the watchdog */
    ssize_t r = write(g_fd, "1", 1);
    if (r < 0) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "watchdog",
                    "Write to %s failed: %s", g_device, strerror(errno));
        g_core->event_emit(g_core, "/events/watchdog/failed",
                           "write failed", 12);
        return;
    }
    g_ticks++;
    g_last = time(NULL);
}

/* --- Open the watchdog device --- */
static int watchdog_open(void)
{
    if (g_fd >= 0) return 0;  /* already open */

    /* Law 14: exclusive resource lock */
    if (g_core->resource_lock(g_core, g_device, "watchdog") != 0) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "watchdog",
                    "Cannot lock %s — already owned by another module", g_device);
        return -1;
    }

    g_fd = open(g_device, O_WRONLY);
    if (g_fd < 0) {
        g_core->log(g_core, PORTAL_LOG_ERROR, "watchdog",
                    "Cannot open %s: %s", g_device, strerror(errno));
        g_core->resource_unlock(g_core, g_device, "watchdog");
        g_core->event_emit(g_core, "/events/watchdog/failed",
                           "open failed", 11);
        return -1;
    }

    /* Query hardware timeout if supported */
    struct watchdog_info wi;
    memset(&wi, 0, sizeof(wi));
    if (ioctl(g_fd, WDIOC_GETSUPPORT, &wi) == 0) {
        g_core->log(g_core, PORTAL_LOG_INFO, "watchdog",
                    "Hardware: %s (firmware %d, options 0x%x)",
                    wi.identity, wi.firmware_version, wi.options);
    }

    int timeout = 0;
    if (ioctl(g_fd, WDIOC_GETTIMEOUT, &timeout) == 0) {
        g_hw_timeout = timeout;
        g_core->log(g_core, PORTAL_LOG_INFO, "watchdog",
                    "Hardware timeout: %d seconds", timeout);
    }

    g_active  = 1;
    g_started = time(NULL);
    g_ticks   = 0;

    /* First kick immediately */
    watchdog_kick(NULL);

    g_core->log(g_core, PORTAL_LOG_INFO, "watchdog",
                "Opened %s — kicking every %.0fs", g_device, g_interval);
    g_core->event_emit(g_core, "/events/watchdog/started", g_device,
                       strlen(g_device));
    return 0;
}

/* --- Close the watchdog device (magic close) --- */
static int watchdog_close(void)
{
    if (g_fd < 0) return 0;

    g_active = 0;

    /* Write 'V' = magic close character — tells the driver to
     * disarm the watchdog instead of triggering a reboot */
    ssize_t r = write(g_fd, "V", 1);
    if (r < 0) {
        g_core->log(g_core, PORTAL_LOG_WARN, "watchdog",
                    "Magic close write failed: %s", strerror(errno));
    }

    close(g_fd);
    g_fd = -1;

    g_core->resource_unlock(g_core, g_device, "watchdog");

    g_core->log(g_core, PORTAL_LOG_INFO, "watchdog",
                "Closed %s (magic close, %llu ticks)", g_device,
                (unsigned long long)g_ticks);
    g_core->event_emit(g_core, "/events/watchdog/stopped", g_device,
                       strlen(g_device));
    return 0;
}

/* --- Module load --- */
int portal_module_load(portal_core_t *core)
{
    g_core = core;

    /* Read config */
    const char *val;

    val = core->config_get(core, "watchdog", "device");
    if (val && val[0]) {
        snprintf(g_device, sizeof(g_device), "%s", val);
    }

    val = core->config_get(core, "watchdog", "interval");
    if (val) {
        double v = atof(val);
        if (v >= 1.0 && v <= 300.0) g_interval = v;
    }

    /* Register paths */
    core->path_register(core, "/watchdog/resources/status", "watchdog");
    core->path_set_access(core, "/watchdog/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/watchdog/resources/status",
        "Watchdog state: active, ticks, device, hardware timeout");

    core->path_register(core, "/watchdog/functions/enable", "watchdog");
    core->path_set_access(core, "/watchdog/functions/enable", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/watchdog/functions/enable",
        "Open /dev/watchdog and start keepalive timer");
    core->path_add_label(core, "/watchdog/functions/enable", "admin");

    core->path_register(core, "/watchdog/functions/disable", "watchdog");
    core->path_set_access(core, "/watchdog/functions/disable", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/watchdog/functions/disable",
        "Stop keepalive and close device (magic close, no reboot)");
    core->path_add_label(core, "/watchdog/functions/disable", "admin");

    /* Register events */
    core->event_register(core, "/events/watchdog/started",
        "Watchdog device opened and ticking", NULL);
    core->event_register(core, "/events/watchdog/stopped",
        "Watchdog device closed (magic close)", NULL);
    core->event_register(core, "/events/watchdog/failed",
        "Watchdog write or open failure", NULL);

    /* Register keepalive timer */
    core->timer_add(core, g_interval, watchdog_kick, NULL);

    /* Auto-start if configured */
    val = core->config_get(core, "watchdog", "auto_start");
    if (val && (strcmp(val, "true") == 0 || strcmp(val, "1") == 0)) {
        if (watchdog_open() != 0) {
            core->log(core, PORTAL_LOG_WARN, "watchdog",
                      "Auto-start failed — use 'set /watchdog/functions/enable' to retry");
        }
    }

    core->log(core, PORTAL_LOG_INFO, "watchdog",
              "Module loaded (device=%s, interval=%.0fs, auto_start=%s)",
              g_device, g_interval,
              (val && (strcmp(val, "true") == 0 || strcmp(val, "1") == 0)) ? "true" : "false");
    return PORTAL_MODULE_OK;
}

/* --- Module unload --- */
int portal_module_unload(portal_core_t *core)
{
    /* Close device cleanly (magic close — won't reboot) */
    watchdog_close();

    core->path_unregister(core, "/watchdog/resources/status");
    core->path_unregister(core, "/watchdog/functions/enable");
    core->path_unregister(core, "/watchdog/functions/disable");

    core->event_unregister(core, "/events/watchdog/started");
    core->event_unregister(core, "/events/watchdog/stopped");
    core->event_unregister(core, "/events/watchdog/failed");

    g_core = NULL;
    core->log(core, PORTAL_LOG_INFO, "watchdog", "Module unloaded");
    return PORTAL_MODULE_OK;
}

/* --- Message handler --- */
int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;

    /* GET /watchdog/resources/status */
    if (strcmp(msg->path, "/watchdog/resources/status") == 0) {
        char buf[512];
        int n;

        if (g_active) {
            time_t uptime = time(NULL) - g_started;
            int days  = (int)(uptime / 86400);
            int hours = (int)((uptime % 86400) / 3600);
            int mins  = (int)((uptime % 3600) / 60);
            int secs  = (int)(uptime % 60);
            n = snprintf(buf, sizeof(buf),
                "active     = true\n"
                "device     = %s\n"
                "hw_timeout = %d\n"
                "interval   = %.0f\n"
                "ticks      = %llu\n"
                "last_kick  = %lld\n"
                "uptime     = %dd %dh %dm %ds\n",
                g_device, g_hw_timeout, g_interval,
                (unsigned long long)g_ticks,
                (long long)g_last,
                days, hours, mins, secs);
        } else {
            n = snprintf(buf, sizeof(buf),
                "active     = false\n"
                "device     = %s\n"
                "interval   = %.0f\n",
                g_device, g_interval);
        }
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* SET /watchdog/functions/enable */
    if (strcmp(msg->path, "/watchdog/functions/enable") == 0) {
        if (g_active) {
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, "already active\n", 15);
            return 0;
        }
        if (watchdog_open() == 0) {
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, "ok\n", 3);
        } else {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            char buf[256];
            int n = snprintf(buf, sizeof(buf),
                "failed to open %s: %s\n", g_device, strerror(errno));
            portal_resp_set_body(resp, buf, (size_t)n);
        }
        return 0;
    }

    /* SET /watchdog/functions/disable */
    if (strcmp(msg->path, "/watchdog/functions/disable") == 0) {
        if (!g_active) {
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, "not active\n", 11);
            return 0;
        }
        watchdog_close();
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, "ok\n", 3);
        return 0;
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
