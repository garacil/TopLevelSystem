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
 * core_wire.h — Binary wire protocol for node-to-node message serialization
 */

#ifndef CORE_WIRE_H
#define CORE_WIRE_H

#include "portal/types.h"

/*
 * Portal Wire Protocol — binary serialization for node-to-node communication.
 *
 * Format:
 *   [4] total_length (excluding these 4 bytes)
 *   [8] msg_id
 *   [1] method
 *   [2] path_len    [N] path
 *   [2] header_count
 *     for each: [2] key_len [N] key [2] val_len [N] val
 *   [4] body_len    [N] body
 *   [1] has_ctx
 *     if has_ctx:
 *       [2] user_len  [N] user
 *       [2] token_len [N] token
 *       [8] trace_id  [8] parent_id  [8] timestamp  [2] hops
 *       [2] label_count
 *         for each: [2] len [N] label
 */

/* Encode a message into a newly allocated buffer. Caller must free *buf. */
int  portal_wire_encode_msg(const portal_msg_t *msg, uint8_t **buf, size_t *len);

/* Decode a buffer into a message. Caller must free with portal_msg_free(). */
int  portal_wire_decode_msg(const uint8_t *buf, size_t len, portal_msg_t *msg);

/* Encode a response. Caller must free *buf. */
int  portal_wire_encode_resp(const portal_resp_t *resp, uint8_t **buf, size_t *len);

/* Decode a buffer into a response. Caller must free with portal_resp_free(). */
int  portal_wire_decode_resp(const uint8_t *buf, size_t len, portal_resp_t *resp);

/* Read the total_length prefix (first 4 bytes). Returns the length or -1. */
int32_t portal_wire_read_length(const uint8_t *buf);

#endif /* CORE_WIRE_H */
