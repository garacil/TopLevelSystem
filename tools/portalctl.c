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
 * portalctl — CLI client for Portal
 *
 * Connects to Portal's UNIX socket and sends commands.
 * In interactive mode, uses raw terminal for arrow key history.
 *
 * Usage:
 *   portalctl <command>           Send a single command
 *   portalctl                     Interactive mode (raw terminal)
 *   portalctl -s <path> <cmd>     Use custom socket path
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define DEFAULT_SOCKET "/var/run/portal.sock"
#define BUF_SIZE       8192

static int connect_to_portal(const char *socket_path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Cannot connect to %s: %s\n", socket_path, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static void read_response(int fd)
{
    char buf[BUF_SIZE];
    while (1) {
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = '\0';
        printf("%s", buf);
        fflush(stdout);
        if (strstr(buf, "portal:") && strstr(buf, "> "))
            break;
    }
}

static int run_single_command(const char *socket_path, const char *cmd)
{
    int fd = connect_to_portal(socket_path);
    if (fd < 0) return 1;

    read_response(fd);
    write(fd, cmd, strlen(cmd));
    write(fd, "\r\n", 2);
    read_response(fd);
    write(fd, "quit\r\n", 6);
    char buf[256];
    read(fd, buf, sizeof(buf));
    close(fd);
    return 0;
}

static int run_interactive(const char *socket_path)
{
    int fd = connect_to_portal(socket_path);
    if (fd < 0) return 1;

    /* Set terminal to raw mode */
    struct termios orig_term, raw_term;
    int tty = isatty(STDIN_FILENO);
    if (tty) {
        tcgetattr(STDIN_FILENO, &orig_term);
        raw_term = orig_term;
        raw_term.c_lflag &= ~(ICANON | ECHO | ISIG);
        raw_term.c_iflag &= ~(IXON | ICRNL);
        raw_term.c_cc[VMIN] = 1;
        raw_term.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw_term);
    }

    /* Bidirectional: stdin ↔ socket */
    fd_set rfds;
    char buf[4096];
    int running = 1;

    while (running) {
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        FD_SET(fd, &rfds);
        int maxfd = fd > STDIN_FILENO ? fd : STDIN_FILENO;

        if (select(maxfd + 1, &rfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (FD_ISSET(fd, &rfds)) {
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n <= 0) break;
            write(STDOUT_FILENO, buf, (size_t)n);
        }

        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) break;
            for (ssize_t i = 0; i < n; i++) {
                if (buf[i] == 4) { running = 0; break; }  /* Ctrl+D */
            }
            if (running)
                write(fd, buf, (size_t)n);
        }
    }

    if (tty)
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_term);

    write(fd, "quit\r\n", 6);
    close(fd);
    printf("\n");
    return 0;
}

int main(int argc, char **argv)
{
    const char *socket_path = DEFAULT_SOCKET;
    int arg_start = 1;

    if (argc >= 3 && strcmp(argv[1], "-s") == 0) {
        socket_path = argv[2];
        arg_start = 3;
    }

    if (arg_start < argc) {
        char cmd[2048] = {0};
        for (int i = arg_start; i < argc; i++) {
            if (i > arg_start) strcat(cmd, " ");
            strcat(cmd, argv[i]);
        }
        return run_single_command(socket_path, cmd);
    }

    return run_interactive(socket_path);
}
