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
 * core_message.c — Universal message system
 *
 * Allocates, builds, and frees portal messages and responses.
 * Provides label set operations and timestamp utilities.
 * Every interaction in Portal flows through these structures.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <sys/time.h>
#include "core_message.h"
#include "portal/constants.h"

static atomic_uint_least64_t g_msg_id = 1;

uint64_t portal_msg_next_id(void)
{
    return atomic_fetch_add(&g_msg_id, 1);
}

uint64_t portal_time_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

portal_msg_t *portal_msg_alloc(void)
{
    portal_msg_t *msg = calloc(1, sizeof(*msg));
    if (msg)
        msg->id = portal_msg_next_id();
    return msg;
}

void portal_msg_free(portal_msg_t *msg)
{
    if (!msg) return;
    free(msg->path);
    for (uint16_t i = 0; i < msg->header_count; i++) {
        free(msg->headers[i].key);
        free(msg->headers[i].value);
    }
    free(msg->headers);
    free(msg->body);
    if (msg->ctx) {
        free(msg->ctx->auth.user);
        free(msg->ctx->auth.token);
        free(msg->ctx->source_node);
        free(msg->ctx->source_module);
        free(msg->ctx);
    }
    free(msg);
}

portal_resp_t *portal_resp_alloc(void)
{
    return calloc(1, sizeof(portal_resp_t));
}

void portal_resp_free(portal_resp_t *resp)
{
    if (!resp) return;
    for (uint16_t i = 0; i < resp->header_count; i++) {
        free(resp->headers[i].key);
        free(resp->headers[i].value);
    }
    free(resp->headers);
    free(resp->body);
    free(resp);
}

int portal_msg_set_path(portal_msg_t *msg, const char *path)
{
    free(msg->path);
    msg->path = strdup(path);
    return msg->path ? 0 : -1;
}

int portal_msg_set_method(portal_msg_t *msg, uint8_t method)
{
    msg->method = method;
    return 0;
}

int portal_msg_set_body(portal_msg_t *msg, const void *data, size_t len)
{
    free(msg->body);
    if (!data || len == 0) {
        msg->body = NULL;
        msg->body_len = 0;
        return 0;
    }
    msg->body = malloc(len);
    if (!msg->body) return -1;
    memcpy(msg->body, data, len);
    msg->body_len = len;
    return 0;
}

int portal_msg_add_header(portal_msg_t *msg, const char *key, const char *value)
{
    if (msg->header_count >= PORTAL_MAX_HEADERS)
        return -1;

    portal_header_t *new_hdrs = realloc(msg->headers,
        (msg->header_count + 1) * sizeof(portal_header_t));
    if (!new_hdrs) return -1;

    msg->headers = new_hdrs;
    msg->headers[msg->header_count].key = strdup(key);
    msg->headers[msg->header_count].value = strdup(value);
    msg->header_count++;
    return 0;
}

int portal_resp_set_status(portal_resp_t *resp, uint16_t status)
{
    resp->status = status;
    return 0;
}

int portal_resp_set_body(portal_resp_t *resp, const void *data, size_t len)
{
    free(resp->body);
    if (!data || len == 0) {
        resp->body = NULL;
        resp->body_len = 0;
        return 0;
    }
    resp->body = malloc(len);
    if (!resp->body) return -1;
    memcpy(resp->body, data, len);
    resp->body_len = len;
    return 0;
}

/* --- Label API --- */

int portal_labels_add(portal_labels_t *ls, const char *label)
{
    if (!ls || !label || ls->count >= PORTAL_MAX_LABELS)
        return -1;

    /* Check for duplicate */
    for (int i = 0; i < ls->count; i++) {
        if (strcmp(ls->labels[i], label) == 0)
            return 0;  /* already present, not an error */
    }

    snprintf(ls->labels[ls->count], PORTAL_MAX_LABEL_LEN, "%s", label);
    ls->count++;
    return 0;
}

int portal_labels_remove(portal_labels_t *ls, const char *label)
{
    if (!ls || !label) return -1;

    for (int i = 0; i < ls->count; i++) {
        if (strcmp(ls->labels[i], label) == 0) {
            /* Swap with last */
            if (i < ls->count - 1)
                memcpy(ls->labels[i], ls->labels[ls->count - 1],
                       PORTAL_MAX_LABEL_LEN);
            ls->count--;
            return 0;
        }
    }
    return -1;  /* not found */
}

int portal_labels_has(const portal_labels_t *ls, const char *label)
{
    if (!ls || !label) return 0;

    for (int i = 0; i < ls->count; i++) {
        if (strcmp(ls->labels[i], label) == 0)
            return 1;
    }
    return 0;
}

int portal_labels_intersects(const portal_labels_t *a, const portal_labels_t *b)
{
    if (!a || !b) return 0;

    for (int i = 0; i < a->count; i++) {
        for (int j = 0; j < b->count; j++) {
            if (strcmp(a->labels[i], b->labels[j]) == 0)
                return 1;
        }
    }
    return 0;
}

void portal_labels_clear(portal_labels_t *ls)
{
    if (ls) ls->count = 0;
}
