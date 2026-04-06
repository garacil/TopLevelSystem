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
 * core_log.h — Logging macros: LOG_ERROR, LOG_WARN, LOG_INFO, LOG_DEBUG, LOG_TRACE
 */

#ifndef CORE_LOG_H
#define CORE_LOG_H

void portal_log_set_level(int level);
int  portal_log_get_level(void);
void portal_log_write(int level, const char *module, const char *fmt, ...);

#define LOG_ERROR(mod, ...) portal_log_write(PORTAL_LOG_ERROR, mod, __VA_ARGS__)
#define LOG_WARN(mod, ...)  portal_log_write(PORTAL_LOG_WARN,  mod, __VA_ARGS__)
#define LOG_INFO(mod, ...)  portal_log_write(PORTAL_LOG_INFO,  mod, __VA_ARGS__)
#define LOG_DEBUG(mod, ...) portal_log_write(PORTAL_LOG_DEBUG, mod, __VA_ARGS__)
#define LOG_TRACE(mod, ...) portal_log_write(PORTAL_LOG_TRACE, mod, __VA_ARGS__)

#endif /* CORE_LOG_H */
