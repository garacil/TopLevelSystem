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
 * constants.h — Portal version, limits, methods, status codes, log levels
 */

#ifndef PORTAL_CONSTANTS_H
#define PORTAL_CONSTANTS_H

#define PORTAL_VERSION_MAJOR 1
#define PORTAL_VERSION_MINOR 0
#define PORTAL_VERSION_PATCH 0
#define PORTAL_VERSION_STR   "1.0.0"

#define PORTAL_MAX_PATH_LEN     1024
#define PORTAL_MAX_MODULE_NAME  64
#define PORTAL_MAX_MODULES      256
#define PORTAL_MAX_HEADERS      32
#define PORTAL_MAX_EVENTS       64
#define PORTAL_MAX_LABELS       32
#define PORTAL_MAX_LABEL_LEN    64

/* Special user */
#define PORTAL_ROOT_USER        "root"

/* Methods */
#define PORTAL_METHOD_GET    0x01
#define PORTAL_METHOD_SET    0x02
#define PORTAL_METHOD_CALL   0x03
#define PORTAL_METHOD_EVENT  0x04
#define PORTAL_METHOD_SUB    0x05
#define PORTAL_METHOD_UNSUB  0x06
#define PORTAL_METHOD_META   0x07

/* Status codes */
#define PORTAL_OK              200
#define PORTAL_CREATED         201
#define PORTAL_ACCEPTED        202
#define PORTAL_BAD_REQUEST     400
#define PORTAL_UNAUTHORIZED    401
#define PORTAL_FORBIDDEN       403
#define PORTAL_NOT_FOUND       404
#define PORTAL_CONFLICT        409
#define PORTAL_GONE            410
#define PORTAL_INTERNAL_ERROR  500
#define PORTAL_UNAVAILABLE     503

/* Log levels */
#define PORTAL_LOG_ERROR   0
#define PORTAL_LOG_WARN    1
#define PORTAL_LOG_INFO    2
#define PORTAL_LOG_DEBUG   3
#define PORTAL_LOG_TRACE   4

/* Resource access modes (Law 8) */
#define PORTAL_ACCESS_READ   0x01   /* R  — read only */
#define PORTAL_ACCESS_WRITE  0x02   /* W  — write only */
#define PORTAL_ACCESS_RW     0x03   /* RW — read and write */

/* Module load return codes */
#define PORTAL_MODULE_OK    0
#define PORTAL_MODULE_FAIL -1

/* Default paths */
#define PORTAL_DEFAULT_CONFIG    "./portal.conf"
#define PORTAL_DEFAULT_MODULES   "./modules"
#define PORTAL_DEFAULT_SOCKET    "/var/run/portal.sock"

#endif /* PORTAL_CONSTANTS_H */
