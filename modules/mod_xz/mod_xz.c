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
 * mod_xz — XZ/LZMA compression
 *
 * Compress and decompress data using XZ (LZMA2) via liblzma.
 * Also supports compressing/decompressing files.
 *
 * Config:
 *   [mod_xz]
 *   level = 6
 *   max_size = 10485760
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lzma.h>
#include "portal/portal.h"

#define XZ_MAX_SIZE  (10 * 1024 * 1024)
#define XZ_DEFAULT_LEVEL  6

static portal_core_t *g_core = NULL;
static int g_level = XZ_DEFAULT_LEVEL;
static size_t g_max_size = XZ_MAX_SIZE;
static int64_t g_compressed = 0;
static int64_t g_decompressed = 0;
static int64_t g_bytes_in = 0;
static int64_t g_bytes_out = 0;

static portal_module_info_t info = {
    .name = "xz", .version = "1.0.0",
    .description = "XZ/LZMA compression",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

static int xz_compress(const void *in, size_t inlen,
                        void **out, size_t *outlen)
{
    size_t bound = lzma_stream_buffer_bound(inlen);
    *out = malloc(bound);
    if (!*out) return -1;

    lzma_ret ret = lzma_easy_buffer_encode(
        (uint32_t)g_level, LZMA_CHECK_CRC64,
        NULL, (const uint8_t *)in, inlen,
        (uint8_t *)*out, outlen, bound);

    if (ret != LZMA_OK) { free(*out); *out = NULL; return -1; }
    return 0;
}

static int xz_decompress(const void *in, size_t inlen,
                           void **out, size_t *outlen)
{
    /* Allocate output buffer (start with 4x input, grow if needed) */
    size_t alloc = inlen * 4;
    if (alloc < 4096) alloc = 4096;
    if (alloc > g_max_size) alloc = g_max_size;

    *out = malloc(alloc);
    if (!*out) return -1;

    uint64_t memlimit = 128 * 1024 * 1024;  /* 128 MB */
    size_t in_pos = 0;
    *outlen = 0;

    lzma_ret ret = lzma_stream_buffer_decode(
        &memlimit, 0, NULL,
        (const uint8_t *)in, &in_pos, inlen,
        (uint8_t *)*out, outlen, alloc);

    if (ret != LZMA_OK) { free(*out); *out = NULL; return -1; }
    return 0;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_compressed = g_decompressed = 0;
    g_bytes_in = g_bytes_out = 0;

    const char *v;
    if ((v = core->config_get(core, "xz", "level")))
        g_level = atoi(v);
    if (g_level < 0) g_level = 0;
    if (g_level > 9) g_level = 9;
    if ((v = core->config_get(core, "xz", "max_size")))
        g_max_size = (size_t)atol(v);

    core->path_register(core, "/xz/resources/status", "xz");
    core->path_set_access(core, "/xz/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/xz/functions/compress", "xz");
    core->path_set_access(core, "/xz/functions/compress", PORTAL_ACCESS_RW);
    core->path_register(core, "/xz/functions/decompress", "xz");
    core->path_set_access(core, "/xz/functions/decompress", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "xz",
              "XZ compression ready (level: %d, max: %zu bytes)",
              g_level, g_max_size);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/xz/resources/status");
    core->path_unregister(core, "/xz/functions/compress");
    core->path_unregister(core, "/xz/functions/decompress");
    core->log(core, PORTAL_LOG_INFO, "xz", "XZ compression unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[4096];
    int n;

    if (strcmp(msg->path, "/xz/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "XZ/LZMA Compression\n"
            "Level: %d\n"
            "Max size: %zu bytes\n"
            "Compressed: %lld operations\n"
            "Decompressed: %lld operations\n"
            "Bytes in: %lld\n"
            "Bytes out: %lld\n",
            g_level, g_max_size,
            (long long)g_compressed, (long long)g_decompressed,
            (long long)g_bytes_in, (long long)g_bytes_out);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/xz/functions/compress") == 0) {
        const void *data = msg->body;
        size_t dlen = msg->body_len;
        if (!data || dlen == 0) {
            const char *d = get_hdr(msg, "data");
            if (d) { data = d; dlen = strlen(d); }
        }
        if (!data || dlen == 0) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: body or data header\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (dlen > g_max_size) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Data too large\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        void *out = NULL;
        size_t outlen = 0;
        if (xz_compress(data, dlen, &out, &outlen) < 0) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            n = snprintf(buf, sizeof(buf), "Compression failed\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        g_compressed++;
        g_bytes_in += (int64_t)dlen;
        g_bytes_out += (int64_t)outlen;
        core->event_emit(core, "/events/xz/compress", "data", 4);
        core->log(core, PORTAL_LOG_DEBUG, "xz",
                  "Compressed %zu → %zu bytes (%.1f%%)",
                  dlen, outlen, 100.0 - (double)outlen / (double)dlen * 100.0);

        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, out, outlen);
        free(out);
        return 0;
    }

    if (strcmp(msg->path, "/xz/functions/decompress") == 0) {
        const void *data = msg->body;
        size_t dlen = msg->body_len;
        if (!data || dlen == 0) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: XZ compressed data in body\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        void *out = NULL;
        size_t outlen = 0;
        if (xz_decompress(data, dlen, &out, &outlen) < 0) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Decompression failed (invalid XZ data)\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        g_decompressed++;
        g_bytes_in += (int64_t)dlen;
        g_bytes_out += (int64_t)outlen;
        core->event_emit(core, "/events/xz/decompress", "data", 4);

        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, out, outlen);
        free(out);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
