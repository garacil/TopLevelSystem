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
 * core_log.c — Portal logging subsystem
 *
 * Color-coded, timestamped log output to stderr.
 * Levels: ERROR, WARN, INFO, DEBUG, TRACE.
 * All modules log through core->log() which calls portal_log_write().
 */

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include "portal/constants.h"

static int g_log_level = PORTAL_LOG_INFO;

static const char *level_str[] = {
    "ERROR", "WARN", "INFO", "DEBUG", "TRACE"
};

static const char *level_color[] = {
    "\033[31m", "\033[33m", "\033[32m", "\033[36m", "\033[90m"
};

void portal_log_set_level(int level)
{
    if (level >= PORTAL_LOG_ERROR && level <= PORTAL_LOG_TRACE)
        g_log_level = level;
}

int portal_log_get_level(void)
{
    return g_log_level;
}

void portal_log_write(int level, const char *module, const char *fmt, ...)
{
    if (level > g_log_level)
        return;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);

    fprintf(stderr, "%s%04d-%02d-%02d %02d:%02d:%02d.%03ld [%-5s] [%-12s] ",
            level_color[level],
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec,
            tv.tv_usec / 1000,
            level_str[level],
            module ? module : "core");

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\033[0m\n");
}
