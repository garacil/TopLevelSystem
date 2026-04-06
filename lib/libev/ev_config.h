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
 * Portal — libev embedded configuration
 *
 * This header configures which backends libev compiles with.
 * libev auto-detects at runtime which backend to use.
 */

#ifndef EV_CONFIG_H
#define EV_CONFIG_H

/* Enable multiplexing backends based on platform */
#if defined(__linux__)
    #define EV_USE_EPOLL     1
    #define EV_USE_LINUXAIO  0
    #define EV_USE_IOURING   0
    #define EV_USE_SELECT    1   /* fallback */
    #define EV_USE_POLL      1
    #define EV_USE_KQUEUE    0
    #define EV_USE_PORT      0
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    #define EV_USE_KQUEUE    1
    #define EV_USE_SELECT    1   /* fallback */
    #define EV_USE_POLL      1
    #define EV_USE_EPOLL     0
    #define EV_USE_LINUXAIO  0
    #define EV_USE_IOURING   0
    #define EV_USE_PORT      0
#elif defined(_WIN32) || defined(_WIN64)
    #define EV_USE_SELECT    1
    #define EV_USE_POLL      0
    #define EV_USE_EPOLL     0
    #define EV_USE_KQUEUE    0
    #define EV_USE_LINUXAIO  0
    #define EV_USE_IOURING   0
    #define EV_USE_PORT      0
#elif defined(__ANDROID__)
    #define EV_USE_EPOLL     1
    #define EV_USE_SELECT    1
    #define EV_USE_POLL      1
    #define EV_USE_KQUEUE    0
    #define EV_USE_LINUXAIO  0
    #define EV_USE_IOURING   0
    #define EV_USE_PORT      0
#else
    /* Safe fallback */
    #define EV_USE_SELECT    1
    #define EV_USE_POLL      1
    #define EV_USE_EPOLL     0
    #define EV_USE_KQUEUE    0
    #define EV_USE_LINUXAIO  0
    #define EV_USE_IOURING   0
    #define EV_USE_PORT      0
#endif

/* Common settings */
#define EV_STANDALONE     1     /* no autoconf, we configure manually */
#define EV_USE_MONOTONIC  1
#define EV_USE_REALTIME   0
#define EV_USE_NANOSLEEP  1
#define EV_USE_EVENTFD    1
#define EV_USE_SIGNALFD   1
#define EV_MULTIPLICITY   1     /* allow multiple event loops */

/* Disable features we don't need */
#define EV_USE_4HEAP      1
#define EV_HEAP_CACHE_AT  1
#define EV_VERIFY         0     /* disable in production, set 1 for debug */
#define EV_FEATURES       0x7f  /* full features */

#endif /* EV_CONFIG_H */
