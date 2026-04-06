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
 * core_wire.c — Binary wire protocol for node-to-node communication
 *
 * Serializes/deserializes portal messages and responses to a compact
 * binary format. Length-prefixed, network byte order. Used by mod_node
 * and the core TCP/UDP listeners for federation.
 */

#include <stdlib.h>
#include <string.h>
#include "core_wire.h"

/* --- Helpers for writing/reading binary data --- */

static void write_u8(uint8_t **p, uint8_t v)   { **p = v; (*p)++; }
static void write_u16(uint8_t **p, uint16_t v)  { (*p)[0] = v >> 8; (*p)[1] = v & 0xff; *p += 2; }
static void write_u32(uint8_t **p, uint32_t v)  { (*p)[0] = v >> 24; (*p)[1] = (v >> 16) & 0xff; (*p)[2] = (v >> 8) & 0xff; (*p)[3] = v & 0xff; *p += 4; }
static void write_u64(uint8_t **p, uint64_t v)  { for (int i = 7; i >= 0; i--) { (*p)[7-i] = (v >> (i*8)) & 0xff; } *p += 8; }
static void write_str(uint8_t **p, const char *s, uint16_t len) { write_u16(p, len); if (len > 0) { memcpy(*p, s, len); *p += len; } }
static void write_blob(uint8_t **p, const void *d, uint32_t len) { write_u32(p, len); if (len > 0) { memcpy(*p, d, len); *p += len; } }

static uint8_t  read_u8(const uint8_t **p)  { uint8_t v = **p; (*p)++; return v; }
static uint16_t read_u16(const uint8_t **p) { uint16_t v = ((uint16_t)(*p)[0] << 8) | (*p)[1]; *p += 2; return v; }
static uint32_t read_u32(const uint8_t **p) { uint32_t v = ((uint32_t)(*p)[0] << 24) | ((uint32_t)(*p)[1] << 16) | ((uint32_t)(*p)[2] << 8) | (*p)[3]; *p += 4; return v; }
static uint64_t read_u64(const uint8_t **p) { uint64_t v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | (*p)[i]; *p += 8; return v; }

static char *read_str(const uint8_t **p) {
    uint16_t len = read_u16(p);
    if (len == 0) return NULL;
    char *s = malloc(len + 1);
    memcpy(s, *p, len);
    s[len] = '\0';
    *p += len;
    return s;
}

/* --- Message encoding --- */

int portal_wire_encode_msg(const portal_msg_t *msg, uint8_t **buf, size_t *out_len)
{
    /* Calculate total size */
    size_t size = 4;  /* total_length field */
    size += 8 + 1;    /* id + method */
    uint16_t path_len = msg->path ? (uint16_t)strlen(msg->path) : 0;
    size += 2 + path_len;
    size += 2;  /* header_count */
    for (uint16_t i = 0; i < msg->header_count; i++) {
        size += 2 + strlen(msg->headers[i].key);
        size += 2 + strlen(msg->headers[i].value);
    }
    size += 4 + msg->body_len;
    size += 1;  /* has_ctx */
    if (msg->ctx) {
        uint16_t ulen = msg->ctx->auth.user ? (uint16_t)strlen(msg->ctx->auth.user) : 0;
        uint16_t tlen = msg->ctx->auth.token ? (uint16_t)strlen(msg->ctx->auth.token) : 0;
        size += 2 + ulen + 2 + tlen + 8 + 8 + 8 + 2;
        size += 2;  /* label_count */
        for (int i = 0; i < msg->ctx->auth.labels.count; i++)
            size += 2 + strlen(msg->ctx->auth.labels.labels[i]);
    }

    *buf = malloc(size);
    if (!*buf) return -1;
    *out_len = size;

    uint8_t *p = *buf;
    write_u32(&p, (uint32_t)(size - 4));  /* total minus the length field itself */
    write_u64(&p, msg->id);
    write_u8(&p, msg->method);
    write_str(&p, msg->path ? msg->path : "", path_len);
    write_u16(&p, msg->header_count);
    for (uint16_t i = 0; i < msg->header_count; i++) {
        write_str(&p, msg->headers[i].key, (uint16_t)strlen(msg->headers[i].key));
        write_str(&p, msg->headers[i].value, (uint16_t)strlen(msg->headers[i].value));
    }
    write_blob(&p, msg->body, (uint32_t)msg->body_len);

    if (msg->ctx) {
        write_u8(&p, 1);
        uint16_t ulen = msg->ctx->auth.user ? (uint16_t)strlen(msg->ctx->auth.user) : 0;
        uint16_t tlen = msg->ctx->auth.token ? (uint16_t)strlen(msg->ctx->auth.token) : 0;
        write_str(&p, msg->ctx->auth.user ? msg->ctx->auth.user : "", ulen);
        write_str(&p, msg->ctx->auth.token ? msg->ctx->auth.token : "", tlen);
        write_u64(&p, msg->ctx->trace.trace_id);
        write_u64(&p, msg->ctx->trace.parent_id);
        write_u64(&p, msg->ctx->trace.timestamp_us);
        write_u16(&p, msg->ctx->trace.hops);
        write_u16(&p, (uint16_t)msg->ctx->auth.labels.count);
        for (int i = 0; i < msg->ctx->auth.labels.count; i++)
            write_str(&p, msg->ctx->auth.labels.labels[i],
                      (uint16_t)strlen(msg->ctx->auth.labels.labels[i]));
    } else {
        write_u8(&p, 0);
    }

    return 0;
}

int portal_wire_decode_msg(const uint8_t *buf, size_t len, portal_msg_t *msg)
{
    if (len < 4) return -1;
    const uint8_t *p = buf;

    (void)read_u32(&p);  /* total_length — already known */
    msg->id = read_u64(&p);
    msg->method = read_u8(&p);
    msg->path = read_str(&p);
    msg->header_count = read_u16(&p);

    if (msg->header_count > 0) {
        msg->headers = calloc(msg->header_count, sizeof(portal_header_t));
        for (uint16_t i = 0; i < msg->header_count; i++) {
            msg->headers[i].key = read_str(&p);
            msg->headers[i].value = read_str(&p);
        }
    }

    uint32_t body_len = read_u32(&p);
    if (body_len > 0) {
        msg->body = malloc(body_len);
        memcpy(msg->body, p, body_len);
        msg->body_len = body_len;
        p += body_len;
    }

    uint8_t has_ctx = read_u8(&p);
    if (has_ctx) {
        msg->ctx = calloc(1, sizeof(portal_ctx_t));
        msg->ctx->auth.user = read_str(&p);
        msg->ctx->auth.token = read_str(&p);
        msg->ctx->trace.trace_id = read_u64(&p);
        msg->ctx->trace.parent_id = read_u64(&p);
        msg->ctx->trace.timestamp_us = read_u64(&p);
        msg->ctx->trace.hops = read_u16(&p);
        uint16_t label_count = read_u16(&p);
        for (uint16_t i = 0; i < label_count; i++) {
            char *label = read_str(&p);
            if (label) {
                portal_labels_add(&msg->ctx->auth.labels, label);
                free(label);
            }
        }
    }

    return 0;
}

/* --- Response encoding --- */

int portal_wire_encode_resp(const portal_resp_t *resp, uint8_t **buf, size_t *out_len)
{
    size_t size = 4;  /* total_length */
    size += 2;        /* status */
    size += 2;        /* header_count */
    for (uint16_t i = 0; i < resp->header_count; i++) {
        size += 2 + strlen(resp->headers[i].key);
        size += 2 + strlen(resp->headers[i].value);
    }
    size += 4 + resp->body_len;

    *buf = malloc(size);
    if (!*buf) return -1;
    *out_len = size;

    uint8_t *p = *buf;
    write_u32(&p, (uint32_t)(size - 4));
    write_u16(&p, resp->status);
    write_u16(&p, resp->header_count);
    for (uint16_t i = 0; i < resp->header_count; i++) {
        write_str(&p, resp->headers[i].key, (uint16_t)strlen(resp->headers[i].key));
        write_str(&p, resp->headers[i].value, (uint16_t)strlen(resp->headers[i].value));
    }
    write_blob(&p, resp->body, (uint32_t)resp->body_len);

    return 0;
}

int portal_wire_decode_resp(const uint8_t *buf, size_t len, portal_resp_t *resp)
{
    if (len < 4) return -1;
    const uint8_t *p = buf;

    (void)read_u32(&p);
    resp->status = read_u16(&p);
    resp->header_count = read_u16(&p);

    if (resp->header_count > 0) {
        resp->headers = calloc(resp->header_count, sizeof(portal_header_t));
        for (uint16_t i = 0; i < resp->header_count; i++) {
            resp->headers[i].key = read_str(&p);
            resp->headers[i].value = read_str(&p);
        }
    }

    uint32_t body_len = read_u32(&p);
    if (body_len > 0) {
        resp->body = malloc(body_len);
        memcpy(resp->body, p, body_len);
        resp->body_len = body_len;
    }

    return 0;
}

int32_t portal_wire_read_length(const uint8_t *buf)
{
    return (int32_t)(((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                     ((uint32_t)buf[2] << 8) | buf[3]);
}
