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
 * types.h — Portal data types: messages, responses, labels, auth, trace
 *
 * The universal message structure flows through every interaction.
 * Labels provide group-based access control on paths.
 */

#ifndef PORTAL_TYPES_H
#define PORTAL_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include "constants.h"

/* Key-value header */
typedef struct {
    char *key;
    char *value;
} portal_header_t;

/* Label set — used for both users and paths */
typedef struct {
    char    labels[PORTAL_MAX_LABELS][PORTAL_MAX_LABEL_LEN];
    int     count;
} portal_labels_t;

/* Authentication context */
typedef struct {
    char            *user;
    char            *token;
    portal_labels_t  labels;    /* user's access labels */
} portal_auth_t;

/* Trace context for debugging/observability */
typedef struct {
    uint64_t  trace_id;
    uint64_t  parent_id;
    uint64_t  timestamp_us;
    uint16_t  hops;
} portal_trace_t;

/* Message context — travels with every message */
typedef struct {
    portal_auth_t   auth;
    portal_trace_t  trace;
    char           *source_node;
    char           *source_module;
} portal_ctx_t;

/* The universal message */
typedef struct {
    uint64_t          id;
    char             *path;
    uint8_t           method;
    uint16_t          header_count;
    portal_header_t  *headers;
    void             *body;
    size_t            body_len;
    portal_ctx_t     *ctx;
} portal_msg_t;

/* Response */
typedef struct {
    uint16_t          status;
    uint16_t          header_count;
    portal_header_t  *headers;
    void             *body;
    size_t            body_len;
} portal_resp_t;

/* Label API */
int  portal_labels_add(portal_labels_t *ls, const char *label);
int  portal_labels_remove(portal_labels_t *ls, const char *label);
int  portal_labels_has(const portal_labels_t *ls, const char *label);
int  portal_labels_intersects(const portal_labels_t *a, const portal_labels_t *b);
void portal_labels_clear(portal_labels_t *ls);

/* Message allocation API */
portal_msg_t  *portal_msg_alloc(void);
void           portal_msg_free(portal_msg_t *msg);
portal_resp_t *portal_resp_alloc(void);
void           portal_resp_free(portal_resp_t *resp);

int  portal_msg_set_path(portal_msg_t *msg, const char *path);
int  portal_msg_set_method(portal_msg_t *msg, uint8_t method);
int  portal_msg_set_body(portal_msg_t *msg, const void *data, size_t len);
int  portal_msg_add_header(portal_msg_t *msg, const char *key, const char *value);
int  portal_resp_set_status(portal_resp_t *resp, uint16_t status);
int  portal_resp_set_body(portal_resp_t *resp, const void *data, size_t len);

#endif /* PORTAL_TYPES_H */
