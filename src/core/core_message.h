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
 * core_message.h — Message and response allocation, building, and lifecycle
 */

#ifndef CORE_MESSAGE_H
#define CORE_MESSAGE_H

#include "portal/types.h"
#include <stdatomic.h>

/* Allocate a new message. Caller must free with portal_msg_free(). */
portal_msg_t  *portal_msg_alloc(void);
void           portal_msg_free(portal_msg_t *msg);

/* Allocate a new response. Caller must free with portal_resp_free(). */
portal_resp_t *portal_resp_alloc(void);
void           portal_resp_free(portal_resp_t *resp);

/* Set message fields (copies strings) */
int  portal_msg_set_path(portal_msg_t *msg, const char *path);
int  portal_msg_set_method(portal_msg_t *msg, uint8_t method);
int  portal_msg_set_body(portal_msg_t *msg, const void *data, size_t len);
int  portal_msg_add_header(portal_msg_t *msg, const char *key, const char *value);

/* Set response fields */
int  portal_resp_set_status(portal_resp_t *resp, uint16_t status);
int  portal_resp_set_body(portal_resp_t *resp, const void *data, size_t len);

/* Generate unique message ID */
uint64_t portal_msg_next_id(void);

/* Current time in microseconds since epoch */
uint64_t portal_time_us(void);

#endif /* CORE_MESSAGE_H */
