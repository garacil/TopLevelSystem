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
 * test_wire.c — Unit tests for binary wire protocol (encode/decode roundtrip)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "portal/portal.h"
#include "../src/core/core_wire.h"
#include "../src/core/core_message.h"

static void test_encode_decode_msg(void)
{
    printf("test_encode_decode_msg... ");

    portal_msg_t *msg = portal_msg_alloc();
    portal_msg_set_path(msg, "/test/hello");
    portal_msg_set_method(msg, PORTAL_METHOD_GET);
    portal_msg_add_header(msg, "key1", "value1");
    portal_msg_add_header(msg, "key2", "value2");
    portal_msg_set_body(msg, "hello world", 11);

    /* Add context */
    msg->ctx = calloc(1, sizeof(portal_ctx_t));
    msg->ctx->auth.user = strdup("admin");
    msg->ctx->auth.token = strdup("abc123");
    portal_labels_add(&msg->ctx->auth.labels, "admin");
    portal_labels_add(&msg->ctx->auth.labels, "dev");
    msg->ctx->trace.trace_id = 42;
    msg->ctx->trace.hops = 3;

    /* Encode */
    uint8_t *buf = NULL;
    size_t len = 0;
    assert(portal_wire_encode_msg(msg, &buf, &len) == 0);
    assert(buf != NULL);
    assert(len > 0);

    /* Decode */
    portal_msg_t decoded = {0};
    assert(portal_wire_decode_msg(buf, len, &decoded) == 0);

    /* Verify */
    assert(decoded.id == msg->id);
    assert(decoded.method == PORTAL_METHOD_GET);
    assert(strcmp(decoded.path, "/test/hello") == 0);
    assert(decoded.header_count == 2);
    assert(strcmp(decoded.headers[0].key, "key1") == 0);
    assert(strcmp(decoded.headers[0].value, "value1") == 0);
    assert(decoded.body_len == 11);
    assert(memcmp(decoded.body, "hello world", 11) == 0);
    assert(decoded.ctx != NULL);
    assert(strcmp(decoded.ctx->auth.user, "admin") == 0);
    assert(strcmp(decoded.ctx->auth.token, "abc123") == 0);
    assert(decoded.ctx->trace.trace_id == 42);
    assert(decoded.ctx->trace.hops == 3);
    assert(decoded.ctx->auth.labels.count == 2);
    assert(portal_labels_has(&decoded.ctx->auth.labels, "admin"));
    assert(portal_labels_has(&decoded.ctx->auth.labels, "dev"));

    portal_msg_free(msg);
    free(buf);
    /* Free decoded manually */
    free(decoded.path);
    for (uint16_t i = 0; i < decoded.header_count; i++) {
        free(decoded.headers[i].key);
        free(decoded.headers[i].value);
    }
    free(decoded.headers);
    free(decoded.body);
    free(decoded.ctx->auth.user);
    free(decoded.ctx->auth.token);
    free(decoded.ctx);

    printf("OK\n");
}

static void test_encode_decode_resp(void)
{
    printf("test_encode_decode_resp... ");

    portal_resp_t resp = {0};
    resp.status = PORTAL_OK;
    resp.body = strdup("response body here");
    resp.body_len = strlen(resp.body);

    uint8_t *buf = NULL;
    size_t len = 0;
    assert(portal_wire_encode_resp(&resp, &buf, &len) == 0);

    portal_resp_t decoded = {0};
    assert(portal_wire_decode_resp(buf, len, &decoded) == 0);

    assert(decoded.status == PORTAL_OK);
    assert(decoded.body_len == resp.body_len);
    assert(memcmp(decoded.body, "response body here", decoded.body_len) == 0);

    free(resp.body);
    free(buf);
    free(decoded.body);

    printf("OK\n");
}

static void test_empty_msg(void)
{
    printf("test_empty_msg... ");

    portal_msg_t *msg = portal_msg_alloc();
    portal_msg_set_path(msg, "/ping");
    portal_msg_set_method(msg, PORTAL_METHOD_GET);

    uint8_t *buf = NULL;
    size_t len = 0;
    assert(portal_wire_encode_msg(msg, &buf, &len) == 0);

    portal_msg_t decoded = {0};
    assert(portal_wire_decode_msg(buf, len, &decoded) == 0);
    assert(strcmp(decoded.path, "/ping") == 0);
    assert(decoded.body_len == 0);
    assert(decoded.ctx == NULL);

    portal_msg_free(msg);
    free(buf);
    free(decoded.path);

    printf("OK\n");
}

int main(void)
{
    printf("=== Portal Wire Protocol Tests ===\n\n");
    test_encode_decode_msg();
    test_encode_decode_resp();
    test_empty_msg();
    printf("\nAll tests passed.\n");
    return 0;
}
