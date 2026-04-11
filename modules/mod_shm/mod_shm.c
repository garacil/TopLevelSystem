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
 * mod_shm — Shared Memory Tables
 *
 * Named shared memory regions accessible via paths.
 * Multiple processes/modules can read/write the same data.
 * Zero-copy access for maximum performance.
 *
 * Config:
 *   [mod_shm]
 *   max_regions = 64
 *   max_region_size = 1048576
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "portal/portal.h"

#define SHM_MAX_REGIONS   64
#define SHM_MAX_SIZE      (1024 * 1024)  /* 1MB default */
#define SHM_PREFIX        "/portal_"

typedef struct {
    char    name[64];
    char    shm_name[128];  /* /portal_<instance>_<name> */
    void   *ptr;
    size_t  size;
    size_t  used;
    int     fd;
    int     active;
} shm_region_t;

static portal_core_t *g_core = NULL;
static shm_region_t   g_regions[SHM_MAX_REGIONS];
static int             g_count = 0;
static size_t          g_max_size = SHM_MAX_SIZE;

static portal_module_info_t info = {
    .name = "shm", .version = "1.0.0",
    .description = "Shared memory regions",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0)
            return msg->headers[i].value;
    return NULL;
}

static shm_region_t *find_region(const char *name)
{
    for (int i = 0; i < g_count; i++)
        if (g_regions[i].active && strcmp(g_regions[i].name, name) == 0)
            return &g_regions[i];
    return NULL;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_regions, 0, sizeof(g_regions));
    g_count = 0;

    const char *v = core->config_get(core, "shm", "max_region_size");
    if (v) g_max_size = (size_t)atoi(v);

    core->path_register(core, "/shm/resources/status", "shm");
    core->path_set_access(core, "/shm/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/shm/resources/status", "Shared memory: max region size, region count");
    core->path_register(core, "/shm/resources/regions", "shm");
    core->path_set_access(core, "/shm/resources/regions", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/shm/resources/regions", "List shared memory regions");
    core->path_register(core, "/shm/functions/create", "shm");
    core->path_set_access(core, "/shm/functions/create", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/shm/functions/create", "Create SHM region. Headers: name, size");
    core->path_register(core, "/shm/functions/write", "shm");
    core->path_set_access(core, "/shm/functions/write", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/shm/functions/write", "Write to SHM region. Header: name. Body: data");
    core->path_register(core, "/shm/functions/read", "shm");
    core->path_set_access(core, "/shm/functions/read", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/shm/functions/read", "Read from SHM region. Header: name");
    core->path_register(core, "/shm/functions/destroy", "shm");
    core->path_set_access(core, "/shm/functions/destroy", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/shm/functions/destroy", "Destroy SHM region. Header: name");

    core->log(core, PORTAL_LOG_INFO, "shm",
              "Shared memory ready (max region: %zuKB)", g_max_size / 1024);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    for (int i = 0; i < g_count; i++) {
        if (g_regions[i].active) {
            if (g_regions[i].ptr)
                munmap(g_regions[i].ptr, g_regions[i].size);
            if (g_regions[i].fd >= 0)
                close(g_regions[i].fd);
            shm_unlink(g_regions[i].shm_name);
        }
    }
    core->path_unregister(core, "/shm/resources/status");
    core->path_unregister(core, "/shm/resources/regions");
    core->path_unregister(core, "/shm/functions/create");
    core->path_unregister(core, "/shm/functions/write");
    core->path_unregister(core, "/shm/functions/read");
    core->path_unregister(core, "/shm/functions/destroy");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;
    char buf[4096];
    int n;

    if (strcmp(msg->path, "/shm/resources/status") == 0) {
        size_t total = 0;
        int active = 0;
        for (int i = 0; i < g_count; i++)
            if (g_regions[i].active) { active++; total += g_regions[i].size; }
        n = snprintf(buf, sizeof(buf),
            "Shared Memory\nRegions: %d\nTotal: %zuKB\nMax per region: %zuKB\n",
            active, total / 1024, g_max_size / 1024);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/shm/resources/regions") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Regions:\n");
        for (int i = 0; i < g_count; i++) {
            if (g_regions[i].active)
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "  %-20s %zuKB (used: %zu bytes)\n",
                    g_regions[i].name, g_regions[i].size / 1024,
                    g_regions[i].used);
        }
        if (g_count == 0) off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/shm/functions/create") == 0) {
        const char *name = get_hdr(msg, "name");
        const char *size_s = get_hdr(msg, "size");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        size_t sz = size_s ? (size_t)atoi(size_s) : 4096;
        if (sz > g_max_size) sz = g_max_size;
        if (g_count >= SHM_MAX_REGIONS || find_region(name)) {
            portal_resp_set_status(resp, PORTAL_CONFLICT);
            return -1;
        }

        shm_region_t *r = &g_regions[g_count];
        snprintf(r->name, sizeof(r->name), "%s", name);
        snprintf(r->shm_name, sizeof(r->shm_name), "%s%s", SHM_PREFIX, name);

        r->fd = shm_open(r->shm_name, O_CREAT | O_RDWR, 0666);
        if (r->fd < 0) { portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR); return -1; }
        ftruncate(r->fd, (off_t)sz);
        r->ptr = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, r->fd, 0);
        if (r->ptr == MAP_FAILED) {
            close(r->fd); shm_unlink(r->shm_name);
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR); return -1;
        }
        r->size = sz; r->used = 0; r->active = 1;
        g_count++;
        core->event_emit(core, "/events/shm/create", name, strlen(name));

        n = snprintf(buf, sizeof(buf), "Created '%s' (%zuKB)\n", name, sz / 1024);
        portal_resp_set_status(resp, PORTAL_CREATED);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/shm/functions/write") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name || !msg->body) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        shm_region_t *r = find_region(name);
        if (!r) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        size_t wlen = msg->body_len < r->size ? msg->body_len : r->size;
        memcpy(r->ptr, msg->body, wlen);
        r->used = wlen;
        n = snprintf(buf, sizeof(buf), "Wrote %zu bytes to '%s'\n", wlen, name);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/shm/functions/read") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        shm_region_t *r = find_region(name);
        if (!r) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, r->ptr, r->used);
        return 0;
    }

    if (strcmp(msg->path, "/shm/functions/destroy") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        shm_region_t *r = find_region(name);
        if (!r) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        munmap(r->ptr, r->size); close(r->fd);
        shm_unlink(r->shm_name);
        r->active = 0;
        n = snprintf(buf, sizeof(buf), "Destroyed '%s'\n", name);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
