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
 * mod_gzip — Gzip compression
 *
 * Compress and decompress data using gzip (deflate) via zlib.
 *
 * Config:
 *   [mod_gzip]
 *   level = 6
 *   max_size = 10485760
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include "portal/portal.h"

#define GZIP_MAX_SIZE  (10 * 1024 * 1024)
#define GZIP_DEFAULT_LEVEL  6

static portal_core_t *g_core = NULL;
static int g_level = GZIP_DEFAULT_LEVEL;
static size_t g_max_size = GZIP_MAX_SIZE;
static int64_t g_compressed = 0;
static int64_t g_decompressed = 0;
static int64_t g_bytes_in = 0;
static int64_t g_bytes_out = 0;

static portal_module_info_t info = {
    .name = "gzip", .version = "1.0.0",
    .description = "Gzip compression (zlib)",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

static int gz_compress(const void *in, size_t inlen,
                        void **out, size_t *outlen)
{
    /* gzip adds ~18 bytes header/trailer, plus deflate overhead */
    size_t bound = inlen + 128;
    if (bound < 256) bound = 256;
    *out = malloc(bound);
    if (!*out) return -1;

    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    /* windowBits = 15 + 16 enables gzip format */
    int rc = deflateInit2(&strm, g_level, Z_DEFLATED,
                          15 + 16, 8, Z_DEFAULT_STRATEGY);
    if (rc != Z_OK) {
        free(*out); *out = NULL;
        return -2;  /* init failed */
    }

    strm.next_in = (Bytef *)in;
    strm.avail_in = (uInt)inlen;
    strm.next_out = (Bytef *)*out;
    strm.avail_out = (uInt)bound;

    rc = deflate(&strm, Z_FINISH);
    deflateEnd(&strm);

    if (rc != Z_STREAM_END) {
        free(*out); *out = NULL;
        return -3;  /* deflate failed */
    }

    *outlen = strm.total_out;
    return 0;
}

static int gz_decompress(const void *in, size_t inlen,
                           void **out, size_t *outlen)
{
    size_t alloc = inlen * 4;
    if (alloc < 4096) alloc = 4096;
    if (alloc > g_max_size) alloc = g_max_size;

    *out = malloc(alloc);
    if (!*out) return -1;

    /* Use inflateInit2 for gzip format (windowBits = 15+16) */
    z_stream strm = {0};
    if (inflateInit2(&strm, 15 + 16) != Z_OK) {
        free(*out); *out = NULL;
        return -1;
    }

    strm.next_in = (Bytef *)in;
    strm.avail_in = (uInt)inlen;
    strm.next_out = (Bytef *)*out;
    strm.avail_out = (uInt)alloc;

    int ret = inflate(&strm, Z_FINISH);
    *outlen = strm.total_out;
    inflateEnd(&strm);

    if (ret != Z_STREAM_END) {
        /* Try with larger buffer */
        if (ret == Z_BUF_ERROR && alloc < g_max_size) {
            free(*out);
            alloc = g_max_size;
            *out = malloc(alloc);
            if (!*out) return -1;

            z_stream s2 = {0};
            inflateInit2(&s2, 15 + 16);
            s2.next_in = (Bytef *)in;
            s2.avail_in = (uInt)inlen;
            s2.next_out = (Bytef *)*out;
            s2.avail_out = (uInt)alloc;
            ret = inflate(&s2, Z_FINISH);
            *outlen = s2.total_out;
            inflateEnd(&s2);
            if (ret != Z_STREAM_END) { free(*out); *out = NULL; return -1; }
            return 0;
        }
        free(*out); *out = NULL;
        return -1;
    }
    return 0;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_compressed = g_decompressed = 0;
    g_bytes_in = g_bytes_out = 0;

    const char *v;
    if ((v = core->config_get(core, "gzip", "level")))
        g_level = atoi(v);
    if (g_level < 1) g_level = 1;
    if (g_level > 9) g_level = 9;
    if ((v = core->config_get(core, "gzip", "max_size")))
        g_max_size = (size_t)atol(v);

    core->path_register(core, "/gzip/resources/status", "gzip");
    core->path_set_access(core, "/gzip/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/gzip/resources/status", "Gzip compression: level, zlib version");
    core->path_register(core, "/gzip/functions/compress", "gzip");
    core->path_set_access(core, "/gzip/functions/compress", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/gzip/functions/compress", "Gzip compress. Body: raw data");
    core->path_register(core, "/gzip/functions/decompress", "gzip");
    core->path_set_access(core, "/gzip/functions/decompress", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/gzip/functions/decompress", "Gzip decompress. Body: compressed data");

    core->log(core, PORTAL_LOG_INFO, "gzip",
              "Gzip compression ready (level: %d, zlib: %s)",
              g_level, zlibVersion());
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/gzip/resources/status");
    core->path_unregister(core, "/gzip/functions/compress");
    core->path_unregister(core, "/gzip/functions/decompress");
    core->log(core, PORTAL_LOG_INFO, "gzip", "Gzip compression unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[4096];
    int n;

    if (strcmp(msg->path, "/gzip/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "Gzip Compression\n"
            "Level: %d\n"
            "zlib version: %s\n"
            "Max size: %zu bytes\n"
            "Compressed: %lld operations\n"
            "Decompressed: %lld operations\n"
            "Bytes in: %lld\n"
            "Bytes out: %lld\n",
            g_level, zlibVersion(), g_max_size,
            (long long)g_compressed, (long long)g_decompressed,
            (long long)g_bytes_in, (long long)g_bytes_out);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/gzip/functions/compress") == 0) {
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
            return -1;
        }

        void *out = NULL;
        size_t outlen = 0;
        int crc = gz_compress(data, dlen, &out, &outlen);
        if (crc < 0) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            n = snprintf(buf, sizeof(buf),
                "Compression failed (rc=%d, input: %zu bytes, level: %d)\n",
                crc, dlen, g_level);
            portal_resp_set_body(resp, buf, (size_t)n);
            core->log(core, PORTAL_LOG_ERROR, "gzip",
                      "Compress failed: rc=%d input=%zu level=%d", crc, dlen, g_level);
            return -1;
        }

        g_compressed++;
        g_bytes_in += (int64_t)dlen;
        g_bytes_out += (int64_t)outlen;
        core->event_emit(core, "/events/gzip/compress", "data", 4);

        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, out, outlen);
        free(out);
        return 0;
    }

    if (strcmp(msg->path, "/gzip/functions/decompress") == 0) {
        const void *data = msg->body;
        size_t dlen = msg->body_len;
        if (!data || dlen == 0) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: gzip compressed data in body\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        void *out = NULL;
        size_t outlen = 0;
        if (gz_decompress(data, dlen, &out, &outlen) < 0) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Decompression failed\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        g_decompressed++;
        g_bytes_in += (int64_t)dlen;
        g_bytes_out += (int64_t)outlen;
        core->event_emit(core, "/events/gzip/decompress", "data", 4);

        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, out, outlen);
        free(out);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
