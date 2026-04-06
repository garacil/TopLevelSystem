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
 * core_handlers.h — Internal path handler dispatcher for core services
 */

#ifndef CORE_HANDLERS_H
#define CORE_HANDLERS_H

#include "portal/core.h"
#include "portal/types.h"

/*
 * Internal handler for /core paths.
 * The core registers itself as the "core" module for these paths:
 *
 *   /core/modules      GET → list modules
 *   /core/modules/<n>  CALL action=load|unload
 *   /core/paths        GET → list paths
 *   /core/status       GET → core status
 */
int core_handle_message(portal_core_t *core, const portal_msg_t *msg,
                         portal_resp_t *resp);

#endif /* CORE_HANDLERS_H */
