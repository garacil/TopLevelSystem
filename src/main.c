/*
 * Portal — Universal Modular Core
 * Entry point: parse args, init core, load modules, run event loop, shutdown.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <getopt.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <signal.h>
#include <termios.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#endif

static volatile sig_atomic_t g_cli_winch = 0;

static void cli_sigwinch_handler(int sig)
{
    (void)sig;
    g_cli_winch = 1;
}

#include <arpa/inet.h>
#include <netinet/in.h>
#include "portal/portal.h"
#include "core/core_log.h"
#include "core/core_config.h"
#include "core/portal_instance.h"

/* Wire protocol for core TCP/UDP */
extern int     portal_wire_encode_resp(const portal_resp_t *resp, uint8_t **buf, size_t *len);
extern int     portal_wire_decode_msg(const uint8_t *buf, size_t len, portal_msg_t *msg);
extern int32_t portal_wire_read_length(const uint8_t *buf);

static portal_instance_t g_instance;
static int g_tcp_fd = -1;
static int g_udp_fd = -1;

/* Handle incoming TCP wire protocol connection */
static void on_tcp_client(int fd, uint32_t events, void *userdata)
{
    (void)userdata;
    if (events & EV_ERROR) {
        g_instance.api.fd_del(&g_instance.api, fd);
        close(fd);
        return;
    }

    /* Read length prefix */
    uint8_t hdr[4];
    ssize_t n = read(fd, hdr, 4);
    if (n != 4) {
        g_instance.api.fd_del(&g_instance.api, fd);
        close(fd);
        return;
    }

    int32_t msg_len = portal_wire_read_length(hdr);
    if (msg_len <= 0 || msg_len > 65536) {
        g_instance.api.fd_del(&g_instance.api, fd);
        close(fd);
        return;
    }

    uint8_t *buf = malloc((size_t)msg_len + 4);
    memcpy(buf, hdr, 4);
    size_t got = 0;
    while (got < (size_t)msg_len) {
        n = read(fd, buf + 4 + got, (size_t)msg_len - got);
        if (n <= 0) { free(buf); close(fd); return; }
        got += (size_t)n;
    }

    /* Decode, route, encode response */
    portal_msg_t incoming = {0};
    if (portal_wire_decode_msg(buf, (size_t)msg_len + 4, &incoming) == 0) {
        portal_resp_t resp = {0};
        g_instance.api.send(&g_instance.api, &incoming, &resp);

        uint8_t *resp_buf = NULL;
        size_t resp_len = 0;
        if (portal_wire_encode_resp(&resp, &resp_buf, &resp_len) == 0) {
            write(fd, resp_buf, resp_len);
            free(resp_buf);
        }

        free(incoming.path);
        for (uint16_t i = 0; i < incoming.header_count; i++) {
            free(incoming.headers[i].key);
            free(incoming.headers[i].value);
        }
        free(incoming.headers);
        free(incoming.body);
        if (incoming.ctx) {
            free(incoming.ctx->auth.user);
            free(incoming.ctx->auth.token);
            free(incoming.ctx);
        }
        free(resp.body);
    }
    free(buf);
}

/* Accept new TCP connection */
static void on_tcp_accept(int fd, uint32_t events, void *userdata)
{
    (void)events; (void)userdata;
    int client = accept(fd, NULL, NULL);
    if (client < 0) return;
    g_instance.api.fd_add(&g_instance.api, client, EV_READ, on_tcp_client, NULL);
    LOG_DEBUG("core", "TCP client connected (fd=%d)", client);
}

/* Handle UDP datagram (stateless: one message per packet) */
static void on_udp_data(int fd, uint32_t events, void *userdata)
{
    (void)events; (void)userdata;
    uint8_t buf[65536];
    struct sockaddr_in sender;
    socklen_t slen = sizeof(sender);

    ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                          (struct sockaddr *)&sender, &slen);
    if (n <= 4) return;

    portal_msg_t incoming = {0};
    if (portal_wire_decode_msg(buf, (size_t)n, &incoming) == 0) {
        portal_resp_t resp = {0};
        g_instance.api.send(&g_instance.api, &incoming, &resp);

        uint8_t *resp_buf = NULL;
        size_t resp_len = 0;
        if (portal_wire_encode_resp(&resp, &resp_buf, &resp_len) == 0) {
            sendto(fd, resp_buf, resp_len, 0,
                   (struct sockaddr *)&sender, slen);
            free(resp_buf);
        }

        free(incoming.path);
        for (uint16_t i = 0; i < incoming.header_count; i++) {
            free(incoming.headers[i].key);
            free(incoming.headers[i].value);
        }
        free(incoming.headers);
        free(incoming.body);
        if (incoming.ctx) {
            free(incoming.ctx->auth.user);
            free(incoming.ctx->auth.token);
            free(incoming.ctx);
        }
        free(resp.body);
    }
}

/* Start core TCP/UDP listeners */
static void start_network_listeners(void)
{
    if (g_instance.config.tcp_port > 0) {
        g_tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (g_tcp_fd >= 0) {
            int opt = 1;
            setsockopt(g_tcp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port = htons((uint16_t)g_instance.config.tcp_port);
            if (bind(g_tcp_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                listen(g_tcp_fd, 16);
                g_instance.api.fd_add(&g_instance.api, g_tcp_fd, EV_READ,
                                       on_tcp_accept, NULL);
                LOG_INFO("core", "TCP listening on port %d",
                         g_instance.config.tcp_port);
            } else {
                LOG_ERROR("core", "TCP bind(%d) failed: %s",
                          g_instance.config.tcp_port, strerror(errno));
                close(g_tcp_fd); g_tcp_fd = -1;
            }
        }
    }

    if (g_instance.config.udp_port > 0) {
        g_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (g_udp_fd >= 0) {
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port = htons((uint16_t)g_instance.config.udp_port);
            if (bind(g_udp_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                g_instance.api.fd_add(&g_instance.api, g_udp_fd, EV_READ,
                                       on_udp_data, NULL);
                LOG_INFO("core", "UDP listening on port %d",
                         g_instance.config.udp_port);
            } else {
                LOG_ERROR("core", "UDP bind(%d) failed: %s",
                          g_instance.config.udp_port, strerror(errno));
                close(g_udp_fd); g_udp_fd = -1;
            }
        }
    }
}

/* Timer callback: clean expired sessions */
static void session_cleanup_cb(void *userdata)
{
    portal_instance_t *inst = userdata;
    portal_auth_cleanup_sessions(&inst->auth);
    lock_cleanup(inst);  /* release expired resource locks */
}

/* SIGHUP callback: reload configuration */
static void sighup_cb(void *userdata)
{
    portal_instance_t *inst = userdata;
    LOG_INFO("core", "Reloading configuration...");
    portal_auth_load_users(&inst->auth, inst->config.users_file);
    LOG_INFO("core", "Configuration reloaded");
}

/* -r mode: connect to running portal as root CLI (raw terminal) */
static int run_remote_cli(const char *socket_path, const char *instance_name)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Cannot connect to %s: %s\n",
                socket_path, strerror(errno));
        close(fd);
        return 1;
    }

    /* Set terminal to raw mode (pass escape sequences through) */
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

        /* Send terminal size so shell mode uses real dimensions */
        struct winsize ws;
        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0) {
            char wscmd[64];
            snprintf(wscmd, sizeof(wscmd), "__winsize %d %d\r\n", ws.ws_row, ws.ws_col);
            write(fd, wscmd, strlen(wscmd));
            /* Consume response silently */
            char wbuf[256];
            struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
            fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
            if (select(fd + 1, &wfds, NULL, NULL, &tv) > 0)
                (void)read(fd, wbuf, sizeof(wbuf));
        }

        /* SIGWINCH: propagate terminal resize */
        struct sigaction sa_w;
        memset(&sa_w, 0, sizeof(sa_w));
        sa_w.sa_handler = cli_sigwinch_handler;
        sa_w.sa_flags = SA_RESTART;
        sigaction(SIGWINCH, &sa_w, NULL);
    }

    /* Auto-login as root — read password from instance's user file */
    {
        char root_conf[PORTAL_MAX_PATH_LEN + 64];
        char root_pass[128] = "portal";  /* fallback */
        if (instance_name)
            snprintf(root_conf, sizeof(root_conf),
                     "/etc/portal/%s/users/root.conf", instance_name);
        else
            snprintf(root_conf, sizeof(root_conf),
                     "/etc/portal/users/root.conf");
        FILE *rf = fopen(root_conf, "r");
        if (rf) {
            char rline[256];
            while (fgets(rline, sizeof(rline), rf)) {
                if (strncmp(rline, "password", 8) == 0) {
                    char *eq = strchr(rline, '=');
                    if (eq) {
                        eq++;
                        while (*eq == ' ') eq++;
                        size_t plen = strlen(eq);
                        while (plen > 0 && (eq[plen-1] == '\n' || eq[plen-1] == '\r'))
                            plen--;
                        if (plen > 0 && plen < sizeof(root_pass)) {
                            memcpy(root_pass, eq, plen);
                            root_pass[plen] = '\0';
                        }
                    }
                }
            }
            fclose(rf);
        }
        char login_cmd[256];
        int lclen = snprintf(login_cmd, sizeof(login_cmd),
                              "login root %s\r\n", root_pass);
        write(fd, login_cmd, (size_t)lclen);
    }

    /* Bidirectional forwarding: stdin → socket, socket → stdout */
    fd_set rfds;
    char buf[4096];
    int running = 1;

    while (running) {
        /* Check for pending terminal resize */
        if (g_cli_winch) {
            g_cli_winch = 0;
            struct winsize ws2;
            if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws2) == 0 && ws2.ws_row > 0) {
                char wscmd[64];
                snprintf(wscmd, sizeof(wscmd), "__winsize %d %d\r\n", ws2.ws_row, ws2.ws_col);
                write(fd, wscmd, strlen(wscmd));
            }
        }

        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        FD_SET(fd, &rfds);
        int maxfd = fd > STDIN_FILENO ? fd : STDIN_FILENO;

        if (select(maxfd + 1, &rfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* Data from server → stdout */
        if (FD_ISSET(fd, &rfds)) {
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n <= 0) break;
            write(STDOUT_FILENO, buf, (size_t)n);
        }

        /* Data from stdin → server */
        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) break;
            /* Ctrl+D = exit */
            for (ssize_t i = 0; i < n; i++) {
                if (buf[i] == 4) { running = 0; break; }  /* Ctrl+D */
            }
            if (running)
                write(fd, buf, (size_t)n);
        }
    }

    /* Restore terminal */
    if (tty)
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_term);

    write(fd, "quit\r\n", 6);
    close(fd);
    printf("\n");
    return 0;
}

/* --- Instance creator --- */

static void generate_random_str(char *buf, size_t len)
{
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    FILE *f = fopen("/dev/urandom", "rb");
    for (size_t i = 0; i < len; i++) {
        unsigned char c = 0;
        if (f) { if (fread(&c, 1, 1, f) != 1) c = (unsigned char)rand(); }
        else c = (unsigned char)rand();
        buf[i] = chars[c % (sizeof(chars) - 1)];
    }
    buf[len] = '\0';
    if (f) fclose(f);
}

static void generate_hex_str(char *buf, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    FILE *f = fopen("/dev/urandom", "rb");
    for (size_t i = 0; i < len; i++) {
        unsigned char c = 0;
        if (f) { if (fread(&c, 1, 1, f) != 1) c = (unsigned char)rand(); }
        else c = (unsigned char)rand();
        buf[i] = hex[c % 16];
    }
    buf[len] = '\0';
    if (f) fclose(f);
}

/* Scan existing instances for used ports */
static int scan_used_port(const char *base_dir, const char *key, int default_base)
{
    int max_port = default_base - 1;
    DIR *d = opendir(base_dir);
    if (!d) return default_base;

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char conf[512];
        snprintf(conf, sizeof(conf), "%s/%s/portal.conf", base_dir, entry->d_name);

        FILE *f = fopen(conf, "r");
        if (!f) continue;

        char line[256];
        while (fgets(line, sizeof(line), f)) {
            char k[64]; int v;
            if (sscanf(line, " %63[^= ] = %d", k, &v) == 2) {
                if (strcmp(k, key) == 0 && v > max_port)
                    max_port = v;
            }
        }
        fclose(f);
    }
    closedir(d);
    return max_port + 1;
}

static int create_instance(const char *name)
{
    char base[512];
    snprintf(base, sizeof(base), "/etc/portal/%s", name);

    /* Check if already exists */
    struct stat st;
    if (stat(base, &st) == 0) {
        fprintf(stderr, "Error: Instance '%s' already exists at %s\n", name, base);
        return 1;
    }

    printf("Creating Portal instance '%s'...\n\n", name);

    /* Create directories — proper FHS layout */
    char path[600];
    char app_base[512], log_base[512];
    snprintf(app_base, sizeof(app_base), "/var/lib/portal/%s", name);
    snprintf(log_base, sizeof(log_base), "/var/log/portal/%s", name);

    /* /etc/portal/<name>/ — configuration */
    mkdir("/etc/portal", 0755);
    mkdir(base, 0755);
    snprintf(path, sizeof(path), "%s/users", base); mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/groups", base); mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/modules", base); mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/certs", base); mkdir(path, 0755);

    /* /var/lib/portal/<name>/ — code + data */
    mkdir("/var/lib/portal", 0755);
    mkdir(app_base, 0755);
    snprintf(path, sizeof(path), "%s/logic", app_base); mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/data", app_base); mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/modules", app_base); mkdir(path, 0755);

    /* /var/log/portal/<name>/ — logs */
    mkdir("/var/log/portal", 0755);
    mkdir(log_base, 0755);

    /* Auto-detect ports */
    int tcp_port  = scan_used_port("/etc/portal", "tcp_port", 9800);
    int udp_port  = tcp_port;
    int web_port  = scan_used_port("/etc/portal", "port", 8080);
    int tls_port  = scan_used_port("/etc/portal", "tls_port", 8443);
    int node_port = scan_used_port("/etc/portal", "listen_port", 9700);

    /* Generate credentials */
    char root_pass[17], root_key[65];
    generate_random_str(root_pass, 16);
    generate_hex_str(root_key, 64);

    /* Derive SSH, MQTT, WebSocket ports from web_port base offset */
    int ssh_port  = 2220 + (web_port - 8080);
    int mqtt_port = 1883 + (web_port - 8080);
    int ws_port   = 9090 + (web_port - 8080);

    /* Write portal.conf — full configuration with all modules */
    snprintf(path, sizeof(path), "%s/portal.conf", base);
    FILE *f = fopen(path, "w");
    if (!f) { fprintf(stderr, "Error: Cannot write %s\n", path); return 1; }

    fprintf(f,
        "# =============================================================================\n"
        "# Portal v%s — Instance: %s\n"
        "# =============================================================================\n"
        "# Created: portal -C %s\n"
        "# Config:  /etc/portal/%s/\n"
        "# Data:    /var/lib/portal/%s/\n"
        "# Logs:    /var/log/portal/%s/\n"
        "# =============================================================================\n\n",
        PORTAL_VERSION_STR, name, name, name, name, name);

    /* [core] section */
    fprintf(f,
        "[core]\n"
        "modules_dir = /usr/lib/portal/modules\n"
        "socket_path = /var/run/portal-%s.sock\n"
        "pid_file    = /var/run/portal-%s.pid\n"
        "data_dir    = /etc/portal/%s\n"
        "app_dir     = /var/lib/portal/%s\n"
        "log_dir     = /var/log/portal/%s\n"
        "tcp_port    = %d\n"
        "udp_port    = %d\n"
        "log_level   = info\n\n",
        name, name, name, name, name, tcp_port, udp_port);

    /* [modules] — only modules loaded from portal.conf (before modules/ scan) */
    fprintf(f,
        "# Modules loaded here run BEFORE per-module configs in modules/ dir.\n"
        "# Additional modules are auto-loaded from modules/mod_*.conf files.\n"
        "# To disable a module: set 'enabled = false' in its .conf file.\n"
        "[modules]\n"
        "load = cli\n\n");

    /* Note: module-specific configs go in modules/ dir */
    fprintf(f,
        "# Module-specific settings are in individual files:\n"
        "#   /etc/portal/%s/modules/mod_<name>.conf\n"
        "# Each file auto-loads and configures its module.\n"
        "# Add 'enabled = false' inside a file to disable it.\n\n"
        "# --- Federation peers (add manually) ---\n"
        "; [nodes]\n"
        "; peer0 = other=127.0.0.1:9700\n",
        name);

    fclose(f);

    /* --- Generate per-module config files --- */
    /* Core modules go in modules/core/, application modules in modules/ */
    char mpath[600];
    snprintf(path, sizeof(path), "%s/modules/core", base);
    mkdir(path, 0755);

    #define CORE_CONF(modname) do { \
        snprintf(mpath, sizeof(mpath), "%s/modules/core/mod_%s.conf", base, modname); \
        f = fopen(mpath, "w"); \
        if (!f) break; \
    } while(0)

    #define MOD_CONF(modname) do { \
        snprintf(mpath, sizeof(mpath), "%s/modules/mod_%s.conf", base, modname); \
        f = fopen(mpath, "w"); \
        if (!f) break; \
    } while(0)

    #define MOD_CLOSE() fclose(f)

    /* === Core infrastructure (modules/core/) === */
    CORE_CONF("cli");
    fprintf(f, "# mod_cli — Command-line interface (UNIX socket)\nenabled = true\n");
    MOD_CLOSE();

    CORE_CONF("node");
    fprintf(f,
        "# mod_node — Node federation (peer-to-peer)\n"
        "#\n"
        "# node_name        : Unique name for this node (used in federation paths)\n"
        "# listen_port      : TCP port for incoming peer connections\n"
        "# threads_per_peer : Worker threads per connected peer (1-16)\n"
        "# tls              : Enable TLS encryption for federation (true/false)\n"
        "# cert_file        : PEM certificate file for TLS\n"
        "# key_file         : PEM private key file for TLS\n"
        "# tls_verify       : Require valid peer certificates (false = self-signed OK)\n"
        "# federation_key   : Shared secret for node authentication (both sides must match)\n"
        "enabled = true\n\n"
        "[mod_node]\n"
        "node_name        = %s\n"
        "listen_port      = %d\n"
        "threads_per_peer = 4\n"
        "tls              = true\n"
        "cert_file        = /etc/portal/%s/certs/server.crt\n"
        "key_file         = /etc/portal/%s/certs/server.key\n"
        "tls_verify       = false\n"
        "# federation_key   = change-me-to-a-secret\n",
        name, node_port, name, name);
    MOD_CLOSE();

    CORE_CONF("web");
    fprintf(f,
        "# mod_web — HTTP/HTTPS REST API gateway\n"
        "# bind      : Listen address (0.0.0.0 = all)\n"
        "# port      : HTTP port (0 = disabled)\n"
        "# tls_port  : HTTPS port (0 = disabled)\n"
        "# api_prefix: URL prefix for API endpoints\n"
        "# cert_file : TLS certificate (PEM)\n"
        "# key_file  : TLS private key (PEM)\n"
        "enabled = true\n\n"
        "[mod_web]\n"
        "bind       = 0.0.0.0\n"
        "port       = %d\n"
        "tls_port   = %d\n"
        "api_prefix = /api\n"
        "cert_file  = /etc/portal/%s/certs/server.crt\n"
        "key_file   = /etc/portal/%s/certs/server.key\n", web_port, tls_port, name, name);
    MOD_CLOSE();

    CORE_CONF("ssh");
    fprintf(f,
        "# mod_ssh — SSH server for remote CLI\n"
        "# port     : SSH listen port\n"
        "# host_key : Path to host key (RSA)\n"
        "enabled = true\n\n"
        "[mod_ssh]\n"
        "port     = %d\n"
        "host_key = /etc/portal/%s/certs/ssh_host_key\n", ssh_port, name);
    MOD_CLOSE();

    CORE_CONF("config_sqlite");
    fprintf(f,
        "# mod_config_sqlite — SQLite storage backend\n"
        "# database : SQLite file path\n"
        "enabled = true\n\n"
        "[mod_config_sqlite]\n"
        "database = /var/lib/portal/%s/data/portal.db\n", name);
    MOD_CLOSE();

    CORE_CONF("config_psql");
    fprintf(f,
        "# mod_config_psql — PostgreSQL storage backend\n"
        "# host / port / user / password / database\n"
        "enabled = false\n\n"
        "[mod_config_psql]\n"
        "host     = localhost\n"
        "port     = 5432\n"
        "user     = portal\n"
        "password =\n"
        "database = portal_conf\n");
    MOD_CLOSE();

    MOD_CONF("cache");
    fprintf(f,
        "# mod_cache — In-memory key-value cache with TTL\n"
        "# max_entries      : Maximum cached entries\n"
        "# cleanup_interval : Seconds between cleanup\n"
        "enabled = true\n\n"
        "[mod_cache]\n"
        "max_entries      = 10000\n"
        "cleanup_interval = 30\n");
    MOD_CLOSE();

    MOD_CONF("cron");
    fprintf(f, "# mod_cron — Scheduled task executor\n"
        "enabled = true\n\n[mod_cron]\nmax_jobs = 100\n");
    MOD_CLOSE();

    MOD_CONF("scheduler");
    fprintf(f, "# mod_scheduler — One-shot delayed tasks\n"
        "enabled = true\n\n[mod_scheduler]\nmax_tasks = 256\n");
    MOD_CLOSE();

    MOD_CONF("worker");
    fprintf(f, "# mod_worker — Thread pool for background tasks\n"
        "enabled = true\n\n[mod_worker]\nmax_pools = 16\ndefault_threads = 4\n");
    MOD_CLOSE();

    MOD_CONF("queue");
    fprintf(f, "# mod_queue — FIFO message queues\n"
        "enabled = true\n\n[mod_queue]\nmax_queues = 64\nmax_depth = 10000\n");
    MOD_CLOSE();

    MOD_CONF("email");
    fprintf(f,
        "# mod_email — SMTP email sender\n"
        "# smtp_host/port/user/pass : SMTP server\n"
        "# from : Default sender address\n"
        "enabled = true\n\n"
        "[mod_email]\nsmtp_host = localhost\nsmtp_port = 25\nsmtp_user =\nsmtp_pass =\n"
        "from = %s@portal.local\n", name);
    MOD_CLOSE();

    MOD_CONF("file");
    fprintf(f, "# mod_file — Sandboxed filesystem operations\n"
        "enabled = true\n\n[mod_file]\nbase_dir = /var/lib/portal/%s/data/files\n"
        "max_file_size = 10485760\n", name);
    MOD_CLOSE();

    MOD_CONF("kv");
    fprintf(f, "# mod_kv — Persistent key-value store\n"
        "enabled = true\n\n[mod_kv]\ndata_dir = /var/lib/portal/%s/data/kv\n"
        "max_value_size = 1048576\n", name);
    MOD_CLOSE();

    MOD_CONF("mqtt");
    fprintf(f, "# mod_mqtt — MQTT broker\n"
        "enabled = true\n\n[mod_mqtt]\nport = %d\nmax_clients = 256\n", mqtt_port);
    MOD_CLOSE();

    MOD_CONF("websocket");
    fprintf(f, "# mod_websocket — WebSocket server\n"
        "enabled = true\n\n[mod_websocket]\nport = %d\nmax_clients = 256\n", ws_port);
    MOD_CLOSE();

    MOD_CONF("shm");
    fprintf(f, "# mod_shm — Shared memory regions\n"
        "enabled = true\n\n[mod_shm]\nmax_regions = 32\nmax_size = 10485760\n");
    MOD_CLOSE();

    MOD_CONF("serial");
    fprintf(f, "# mod_serial — RS232/serial port\n"
        "enabled = true\n\n[mod_serial]\nmax_ports = 16\n");
    MOD_CLOSE();

    MOD_CONF("firewall");
    fprintf(f, "# mod_firewall — Rate limiting + IP filtering\n"
        "enabled = true\n\n[mod_firewall]\nrate_limit = 100\nrate_window = 60\n");
    MOD_CLOSE();

    MOD_CONF("crypto");
    fprintf(f, "# mod_crypto — SHA-256, MD5, Base64, Hex\nenabled = true\n");
    MOD_CLOSE();

    MOD_CONF("validator");
    fprintf(f, "# mod_validator — Input validation\nenabled = true\n");
    MOD_CLOSE();

    MOD_CONF("ldap");
    fprintf(f,
        "# mod_ldap — LDAP/AD authentication\n"
        "enabled = false\n\n"
        "[mod_ldap]\nserver = ldap://localhost:389\nbase_dn = dc=example,dc=com\n"
        "bind_dn =\nbind_pass =\nuser_filter = (uid=%%s)\n");
    MOD_CLOSE();

    MOD_CONF("proxy");
    fprintf(f, "# mod_proxy — HTTP reverse proxy\n"
        "enabled = true\n\n[mod_proxy]\nmax_routes = 64\ntimeout = 10\n");
    MOD_CLOSE();

    MOD_CONF("dns");
    fprintf(f, "# mod_dns — DNS resolver\nenabled = true\n");
    MOD_CLOSE();

    MOD_CONF("webhook");
    fprintf(f, "# mod_webhook — Webhook dispatcher\n"
        "enabled = true\n\n[mod_webhook]\nmax_hooks = 64\ntimeout = 5\nretry = 3\n");
    MOD_CLOSE();

    MOD_CONF("process");
    fprintf(f,
        "# mod_process — System command execution (sandboxed)\n"
        "# allowed : Comma-separated allowed commands\n"
        "enabled = true\n\n[mod_process]\n"
        "allowed = ls,cat,df,free,uname,ps,date,whoami,id,uptime,ip,ss,hostname\n"
        "timeout = 10\nmax_output = 65536\n");
    MOD_CLOSE();

    MOD_CONF("sysinfo");
    fprintf(f, "# mod_sysinfo — System information\nenabled = true\n");
    MOD_CLOSE();

    MOD_CONF("log");
    fprintf(f, "# mod_log — Log viewer\n"
        "enabled = true\n\n[mod_log]\nlog_dir = /var/log/portal/%s\nmax_lines = 500\n", name);
    MOD_CLOSE();

    MOD_CONF("backup");
    fprintf(f, "# mod_backup — Instance backup/restore\n"
        "enabled = true\n\n[mod_backup]\nbackup_dir = /var/lib/portal/%s/data/backups\n"
        "max_backups = 50\n", name);
    MOD_CLOSE();

    MOD_CONF("audit");
    fprintf(f, "# mod_audit — Audit trail\n"
        "enabled = true\n\n[mod_audit]\nmax_entries = 10000\n"
        "log_file = /var/log/portal/%s/audit.log\n", name);
    MOD_CLOSE();

    MOD_CONF("xz");
    fprintf(f, "# mod_xz — XZ/LZMA compression\n"
        "enabled = true\n\n[mod_xz]\nlevel = 6\nmax_size = 10485760\n");
    MOD_CLOSE();

    MOD_CONF("gzip");
    fprintf(f, "# mod_gzip — Gzip compression (zlib)\n"
        "enabled = true\n\n[mod_gzip]\nlevel = 6\nmax_size = 10485760\n");
    MOD_CLOSE();

    MOD_CONF("gpio");
    fprintf(f, "# mod_gpio — GPIO pin control (IoT)\n"
        "enabled = true\n\n[mod_gpio]\nsysfs_path = /sys/class/gpio\nmax_pins = 64\n"
        "simulate = false\n");
    MOD_CLOSE();

    MOD_CONF("template");
    fprintf(f, "# mod_template — Template rendering\n"
        "enabled = true\n\n[mod_template]\ntemplate_dir = /var/lib/portal/%s/data/templates\n"
        "max_templates = 256\n", name);
    MOD_CLOSE();

    /* IoT */
    MOD_CONF("iot");
    fprintf(f,
        "# mod_iot — IoT device discovery, control, and monitoring\n"
        "# Drivers: mqtt (Tasmota/Shelly/Sonoff/Zigbee), http (Shelly/Hue), tapo (TP-Link), gpio\n"
        "enabled = true\n\n"
        "[mod_iot]\n"
        "max_devices = 256\n"
        "poll_interval = 30\n"
        "tapo_email =\n"
        "tapo_password =\n");
    MOD_CLOSE();

    /* API Gateway */
    MOD_CONF("api_gateway");
    fprintf(f,
        "# mod_api_gateway — External API routing with caching + rate limiting\n"
        "enabled = true\n\n"
        "[mod_api_gateway]\n"
        "max_routes = 128\n"
        "default_cache_ttl = 60\n"
        "default_timeout = 10\n");
    MOD_CLOSE();

    /* ACME */
    MOD_CONF("acme");
    fprintf(f,
        "# mod_acme — ACME/Let's Encrypt certificate automation\n"
        "enabled = true\n\n"
        "[mod_acme]\n"
        "acme_email =\n"
        "cert_dir = /etc/portal/%s/certs\n"
        "renew_days = 30\n", name);
    MOD_CLOSE();

    /* Admin dashboard */
    MOD_CONF("admin");
    fprintf(f,
        "# mod_admin — Web administration dashboard\n"
        "enabled = true\n\n"
        "[mod_admin]\n"
        "title = Portal Admin\n");
    MOD_CLOSE();

    /* Modules with no config */
    const char *simple_mods[] = {
        "health", "json", "http_client", "metrics", "hello", "myapp",
        "logic", "logic_lua", "logic_python", "logic_c", "logic_pascal", NULL
    };
    const char *simple_descs[] = {
        "Health checks", "JSON response wrapper", "HTTP/HTTPS client",
        "System metrics", "Hello world example", "Example app",
        "Logic framework", "Lua engine", "Python engine", "C engine", "Pascal engine"
    };
    for (int i = 0; simple_mods[i]; i++) {
        snprintf(mpath, sizeof(mpath), "%s/modules/mod_%s.conf", base, simple_mods[i]);
        f = fopen(mpath, "w");
        if (f) {
            fprintf(f, "# mod_%s — %s\nenabled = true\n", simple_mods[i], simple_descs[i]);
            fclose(f);
        }
    }

    #undef CORE_CONF
    #undef MOD_CONF
    #undef MOD_CLOSE

    /* Write users/root.conf */
    snprintf(path, sizeof(path), "%s/users/root.conf", base);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "password = %s\napi_key = %s\ngroups = root,admin\n",
                root_pass, root_key);
        fclose(f);
    }

    /* Write groups/admin.conf */
    snprintf(path, sizeof(path), "%s/groups/admin.conf", base);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "description = Administrators\ncreated_by = portal --create\n");
        fclose(f);
    }

    /* Write RULES.md — Laws of God */
    snprintf(path, sizeof(path), "%s/RULES.md", base);
    f = fopen(path, "w");
    if (f) {
        fprintf(f,
            "# Portal — Laws of God\n\n"
            "These rules are absolute for this instance and all its modules.\n\n"
            "1. **Document everything** — No undocumented feature exists.\n"
            "2. **Always write in English** — All code, docs, configs, comments.\n"
            "3. **Architecture-first** — Order, simplicity, elegant solutions.\n"
            "4. **Perfect order** — Structure and classification in everything.\n"
            "5. **Update docs after testing** — Docs must always reflect current state.\n"
            "6. **Test everything** — Build, test, verify every feature before release.\n"
            "7. **Core is READ-ONLY** — The core is frozen. New functionality = modules.\n"
            "   Core changes only through the engineer.\n"
            "8. **Resource Properties** — Every resource declares: READ, WRITE, or RW.\n"
            "   No resource exists without a declared access mode.\n"
            "9. **Module Authentication** — Every module authenticates on load\n"
            "   (user+password or API key). Default = root. Permissions inherited.\n"
            "10. **Everything Is an Event** — Every write, execution, or modification\n"
            "    emits an event. Events chain: one event triggers N others.\n"
            "    Nothing happens silently in Portal.\n\n"
            "> The core is the foundation. You don't change the foundation — you build on it.\n"
            "> Every resource has clear access rights. Every module has clear identity.\n"
            "> Every change is observable.\n");
        fclose(f);
    }

    /* Generate TLS certificate */
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "openssl req -x509 -newkey rsa:2048 "
        "-keyout %s/certs/server.key -out %s/certs/server.crt "
        "-days 3650 -nodes -subj '/CN=portal-%s' 2>/dev/null",
        base, base, name);
    system(cmd);

    /* Generate SSH host key (RSA for libssh compatibility) */
    snprintf(cmd, sizeof(cmd),
        "ssh-keygen -t rsa -b 2048 -f %s/certs/ssh_host_key -N '' -q 2>/dev/null",
        base);
    system(cmd);

    /* Write systemd service */
    snprintf(path, sizeof(path), "/etc/systemd/system/portal-%s.service", name);
    f = fopen(path, "w");
    if (f) {
        fprintf(f,
            "[Unit]\n"
            "Description=Portal — %s instance\n"
            "After=network.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            "ExecStart=/usr/local/bin/portal -n %s -f\n"
            "ExecReload=/bin/kill -HUP $MAINPID\n"
            "Restart=on-failure\n"
            "RestartSec=5\n\n"
            "NoNewPrivileges=true\n"
            "ProtectSystem=strict\n"
            "ProtectHome=true\n"
            "ReadWritePaths=/var/run /var/lib/portal/%s /var/log/portal/%s /etc/portal/%s\n"
            "PrivateTmp=true\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n",
            name, name, name, name, name);
        fclose(f);
    }

    /* Print summary */
    printf("\n");
    printf("Portal instance '%s' created successfully!\n", name);
    printf("================================================\n\n");
    printf("  Config:    /etc/portal/%s/\n", name);
    printf("  Data:      /var/lib/portal/%s/\n", name);
    printf("  Logs:      /var/log/portal/%s/\n\n", name);
    printf("  Root password:  %s\n", root_pass);
    printf("  Root API key:   %s\n\n", root_key);
    printf("  Ports:\n");
    printf("    CLI socket:  /var/run/portal-%s.sock\n", name);
    printf("    HTTP:        http://0.0.0.0:%d/api\n", web_port);
    printf("    HTTPS:       https://0.0.0.0:%d/api\n", tls_port);
    printf("    SSH:         port %d\n", ssh_port);
    printf("    Node:        port %d\n", node_port);
    printf("    Core TCP:    port %d\n", tcp_port);
    printf("    MQTT:        port %d\n", mqtt_port);
    printf("    WebSocket:   port %d\n\n", ws_port);
    printf("  Modules: 45 (all loaded by default)\n\n");
    printf("  Start:     portal -n %s -f -d\n", name);
    printf("  CLI:       portal -n %s -r\n", name);
    printf("  Systemd:   systemctl enable portal-%s\n", name);
    printf("             systemctl start portal-%s\n\n", name);

    return 0;
}

static int delete_instance(const char *name)
{
    char base[512];
    snprintf(base, sizeof(base), "/etc/portal/%s", name);

    struct stat st;
    if (stat(base, &st) != 0) {
        fprintf(stderr, "Error: Instance '%s' not found at %s\n", name, base);
        return 1;
    }

    /* Stop and disable systemd service */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "systemctl stop portal-%s 2>/dev/null", name);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "systemctl disable portal-%s 2>/dev/null", name);
    system(cmd);

    /* Remove systemd service file */
    char svc[256];
    snprintf(svc, sizeof(svc), "/etc/systemd/system/portal-%s.service", name);
    unlink(svc);

    /* Remove socket and pid file */
    snprintf(cmd, sizeof(cmd), "/var/run/portal-%s.sock", name);
    unlink(cmd);
    snprintf(cmd, sizeof(cmd), "/var/run/portal-%s.pid", name);
    unlink(cmd);

    /* Remove instance directory */
    char rmcmd[1024];
    snprintf(rmcmd, sizeof(rmcmd), "rm -rf %s", base);
    system(rmcmd);

    printf("Portal instance '%s' deleted.\n", name);
    printf("  Removed: %s\n", base);
    printf("  Removed: %s\n", svc);
    printf("  Service stopped and disabled.\n");

    return 0;
}

/* Update all existing instances: add missing module configs */
static int update_instances(void)
{
    DIR *pd = opendir("/etc/portal");
    if (!pd) { fprintf(stderr, "No instances in /etc/portal/\n"); return 1; }

    printf("Updating Portal instances...\n\n");

    struct dirent *pent;
    while ((pent = readdir(pd)) != NULL) {
        if (pent->d_name[0] == '.') continue;
        char conf[600];
        snprintf(conf, sizeof(conf), "/etc/portal/%s/portal.conf", pent->d_name);
        struct stat st;
        if (stat(conf, &st) != 0) continue;  /* not an instance */

        char mdir[600], cdir[600];
        snprintf(mdir, sizeof(mdir), "/etc/portal/%s/modules", pent->d_name);
        snprintf(cdir, sizeof(cdir), "/etc/portal/%s/modules/core", pent->d_name);
        mkdir(mdir, 0755);
        mkdir(cdir, 0755);

        int added = 0;

        /* Scan installed .so files */
        DIR *sd = opendir("/usr/lib/portal/modules");
        if (!sd) continue;
        struct dirent *sent;
        while ((sent = readdir(sd)) != NULL) {
            if (strncmp(sent->d_name, "mod_", 4) != 0) continue;
            size_t nlen = strlen(sent->d_name);
            if (nlen < 8 || strcmp(sent->d_name + nlen - 3, ".so") != 0) continue;

            /* Extract name: mod_xxx.so → xxx */
            char mod[64];
            size_t ml = nlen - 4 - 3;
            if (ml >= sizeof(mod)) ml = sizeof(mod) - 1;
            memcpy(mod, sent->d_name + 4, ml);
            mod[ml] = '\0';

            /* Check if config exists (in core/ or modules/) */
            char cf1[700], cf2[700];
            snprintf(cf1, sizeof(cf1), "%s/mod_%s.conf", mdir, mod);
            snprintf(cf2, sizeof(cf2), "%s/mod_%s.conf", cdir, mod);
            if (stat(cf1, &st) == 0 || stat(cf2, &st) == 0) continue;

            /* Missing — create full commented config */
            FILE *f = fopen(cf1, "w");
            if (!f) continue;

            /* Match each module with its full config template */
            if (strcmp(mod, "iot") == 0) {
                fprintf(f,
                    "# mod_iot — IoT device discovery, control, and monitoring\n"
                    "# Drivers: mqtt (Tasmota/Shelly/Sonoff/Zigbee), http (Shelly/Hue), tapo (TP-Link), gpio\n"
                    "#\n"
                    "# max_devices     : Maximum registered devices\n"
                    "# poll_interval   : Seconds between status polls for non-MQTT devices\n"
                    "# tapo_email      : TP-Link account email (for Tapo devices)\n"
                    "# tapo_password   : TP-Link account password\n"
                    "enabled = true\n\n"
                    "[mod_iot]\n"
                    "max_devices = 256\n"
                    "poll_interval = 30\n"
                    "tapo_email =\n"
                    "tapo_password =\n");
            } else if (strcmp(mod, "api_gateway") == 0) {
                fprintf(f,
                    "# mod_api_gateway — External API routing with caching + rate limiting\n"
                    "#\n"
                    "# max_routes        : Maximum named API routes\n"
                    "# default_cache_ttl : Default cache duration in seconds (0 = no cache)\n"
                    "# default_timeout   : HTTP timeout for upstream requests in seconds\n"
                    "enabled = true\n\n"
                    "[mod_api_gateway]\n"
                    "max_routes = 128\n"
                    "default_cache_ttl = 60\n"
                    "default_timeout = 10\n");
            } else if (strcmp(mod, "acme") == 0) {
                fprintf(f,
                    "# mod_acme — ACME/Let's Encrypt TLS certificate automation\n"
                    "#\n"
                    "# acme_email  : Email for Let's Encrypt account registration\n"
                    "# cert_dir    : Directory to store certificates\n"
                    "# renew_days  : Renew when certificate expires within this many days\n"
                    "enabled = true\n\n"
                    "[mod_acme]\n"
                    "acme_email =\n"
                    "cert_dir = /etc/portal/%s/certs\n"
                    "renew_days = 30\n", pent->d_name);
            } else if (strcmp(mod, "admin") == 0) {
                fprintf(f,
                    "# mod_admin — Web administration dashboard\n"
                    "#\n"
                    "# title : Dashboard page title\n"
                    "enabled = true\n\n"
                    "[mod_admin]\n"
                    "title = Portal Admin\n");
            } else if (strcmp(mod, "cache") == 0) {
                fprintf(f,
                    "# mod_cache — In-memory key-value cache with TTL\n"
                    "#\n"
                    "# max_entries      : Maximum cached entries\n"
                    "# cleanup_interval : Seconds between expired entry cleanup\n"
                    "enabled = true\n\n"
                    "[mod_cache]\n"
                    "max_entries = 10000\n"
                    "cleanup_interval = 30\n");
            } else if (strcmp(mod, "cron") == 0) {
                fprintf(f,
                    "# mod_cron — Scheduled task executor (interval-based)\n"
                    "#\n"
                    "# max_jobs : Maximum scheduled jobs\n"
                    "enabled = true\n\n"
                    "[mod_cron]\n"
                    "max_jobs = 100\n");
            } else if (strcmp(mod, "scheduler") == 0) {
                fprintf(f,
                    "# mod_scheduler — One-shot delayed task scheduler\n"
                    "#\n"
                    "# max_tasks : Maximum pending tasks\n"
                    "enabled = true\n\n"
                    "[mod_scheduler]\n"
                    "max_tasks = 256\n");
            } else if (strcmp(mod, "worker") == 0) {
                fprintf(f,
                    "# mod_worker — Thread pool for background tasks\n"
                    "#\n"
                    "# max_pools       : Maximum worker pools\n"
                    "# default_threads : Default threads per pool\n"
                    "enabled = true\n\n"
                    "[mod_worker]\n"
                    "max_pools = 16\n"
                    "default_threads = 4\n");
            } else if (strcmp(mod, "queue") == 0) {
                fprintf(f,
                    "# mod_queue — FIFO message queues\n"
                    "#\n"
                    "# max_queues : Maximum named queues\n"
                    "# max_depth  : Maximum items per queue\n"
                    "enabled = true\n\n"
                    "[mod_queue]\n"
                    "max_queues = 64\n"
                    "max_depth = 10000\n");
            } else if (strcmp(mod, "email") == 0) {
                fprintf(f,
                    "# mod_email — SMTP email sender\n"
                    "#\n"
                    "# smtp_host : SMTP server hostname\n"
                    "# smtp_port : SMTP port (25=plain, 587=STARTTLS)\n"
                    "# smtp_user : SMTP auth username (empty = no auth)\n"
                    "# smtp_pass : SMTP auth password\n"
                    "# from      : Default sender address\n"
                    "enabled = true\n\n"
                    "[mod_email]\n"
                    "smtp_host = localhost\n"
                    "smtp_port = 25\n"
                    "smtp_user =\n"
                    "smtp_pass =\n"
                    "from = %s@portal.local\n", pent->d_name);
            } else if (strcmp(mod, "file") == 0) {
                fprintf(f,
                    "# mod_file — Sandboxed filesystem operations\n"
                    "#\n"
                    "# base_dir      : Root directory (sandbox, no .. allowed)\n"
                    "# max_file_size : Maximum file size in bytes\n"
                    "enabled = true\n\n"
                    "[mod_file]\n"
                    "base_dir = /var/lib/portal/%s/data/files\n"
                    "max_file_size = 10485760\n", pent->d_name);
            } else if (strcmp(mod, "kv") == 0) {
                fprintf(f,
                    "# mod_kv — Persistent key-value store (file-backed)\n"
                    "#\n"
                    "# data_dir       : Directory where keys are stored as files\n"
                    "# max_value_size : Maximum value size in bytes\n"
                    "enabled = true\n\n"
                    "[mod_kv]\n"
                    "data_dir = /var/lib/portal/%s/data/kv\n"
                    "max_value_size = 1048576\n", pent->d_name);
            } else if (strcmp(mod, "firewall") == 0) {
                fprintf(f,
                    "# mod_firewall — Rate limiting + IP/source filtering\n"
                    "#\n"
                    "# rate_limit  : Max requests per source per window\n"
                    "# rate_window : Window duration in seconds\n"
                    "enabled = true\n\n"
                    "[mod_firewall]\n"
                    "rate_limit = 100\n"
                    "rate_window = 60\n");
            } else if (strcmp(mod, "proxy") == 0) {
                fprintf(f,
                    "# mod_proxy — HTTP reverse proxy\n"
                    "#\n"
                    "# max_routes : Maximum named proxy routes\n"
                    "# timeout    : Upstream connection timeout in seconds\n"
                    "enabled = true\n\n"
                    "[mod_proxy]\n"
                    "max_routes = 64\n"
                    "timeout = 10\n");
            } else if (strcmp(mod, "webhook") == 0) {
                fprintf(f,
                    "# mod_webhook — Webhook dispatcher (HTTP POST)\n"
                    "#\n"
                    "# max_hooks : Maximum registered webhooks\n"
                    "# timeout   : HTTP POST timeout in seconds\n"
                    "# retry     : Retry attempts on failure\n"
                    "enabled = true\n\n"
                    "[mod_webhook]\n"
                    "max_hooks = 64\n"
                    "timeout = 5\n"
                    "retry = 3\n");
            } else if (strcmp(mod, "process") == 0) {
                fprintf(f,
                    "# mod_process — System command execution (sandboxed, admin only)\n"
                    "#\n"
                    "# allowed    : Comma-separated allowed commands\n"
                    "# timeout    : Execution timeout in seconds\n"
                    "# max_output : Maximum output capture in bytes\n"
                    "enabled = true\n\n"
                    "[mod_process]\n"
                    "allowed = ls,cat,df,free,uname,ps,date,whoami,id,uptime,ip,ss,hostname,env\n"
                    "timeout = 10\n"
                    "max_output = 65536\n");
            } else if (strcmp(mod, "log") == 0) {
                fprintf(f,
                    "# mod_log — Log viewer and searcher\n"
                    "#\n"
                    "# log_dir   : Directory containing log files\n"
                    "# max_lines : Maximum lines returned per query\n"
                    "enabled = true\n\n"
                    "[mod_log]\n"
                    "log_dir = /var/log/portal/%s\n"
                    "max_lines = 500\n", pent->d_name);
            } else if (strcmp(mod, "backup") == 0) {
                fprintf(f,
                    "# mod_backup — Instance backup and restore\n"
                    "#\n"
                    "# backup_dir  : Directory for backup archives\n"
                    "# max_backups : Maximum stored backups\n"
                    "enabled = true\n\n"
                    "[mod_backup]\n"
                    "backup_dir = /var/lib/portal/%s/data/backups\n"
                    "max_backups = 50\n", pent->d_name);
            } else if (strcmp(mod, "audit") == 0) {
                fprintf(f,
                    "# mod_audit — Audit trail logging\n"
                    "#\n"
                    "# max_entries : Maximum entries in circular buffer\n"
                    "# log_file    : Persistent audit log file (empty = memory only)\n"
                    "enabled = true\n\n"
                    "[mod_audit]\n"
                    "max_entries = 10000\n"
                    "log_file = /var/log/portal/%s/audit.log\n", pent->d_name);
            } else if (strcmp(mod, "template") == 0) {
                fprintf(f,
                    "# mod_template — Template rendering engine ({{var}} syntax)\n"
                    "#\n"
                    "# template_dir  : Directory containing template files\n"
                    "# max_templates : Maximum cached templates\n"
                    "enabled = true\n\n"
                    "[mod_template]\n"
                    "template_dir = /var/lib/portal/%s/data/templates\n"
                    "max_templates = 256\n", pent->d_name);
            } else if (strcmp(mod, "xz") == 0) {
                fprintf(f,
                    "# mod_xz — XZ/LZMA compression\n"
                    "#\n"
                    "# level    : Compression level (0=fast, 9=best)\n"
                    "# max_size : Maximum input size in bytes\n"
                    "enabled = true\n\n"
                    "[mod_xz]\n"
                    "level = 6\n"
                    "max_size = 10485760\n");
            } else if (strcmp(mod, "gzip") == 0) {
                fprintf(f,
                    "# mod_gzip — Gzip compression (zlib)\n"
                    "#\n"
                    "# level    : Compression level (1=fast, 9=best)\n"
                    "# max_size : Maximum input size in bytes\n"
                    "enabled = true\n\n"
                    "[mod_gzip]\n"
                    "level = 6\n"
                    "max_size = 10485760\n");
            } else if (strcmp(mod, "gpio") == 0) {
                fprintf(f,
                    "# mod_gpio — GPIO pin control for IoT/embedded\n"
                    "#\n"
                    "# sysfs_path : Path to GPIO sysfs interface\n"
                    "# max_pins   : Maximum exportable pins\n"
                    "# simulate   : Force simulation mode (true/false)\n"
                    "enabled = true\n\n"
                    "[mod_gpio]\n"
                    "sysfs_path = /sys/class/gpio\n"
                    "max_pins = 64\n"
                    "simulate = false\n");
            } else if (strcmp(mod, "mqtt") == 0) {
                fprintf(f,
                    "# mod_mqtt — Lightweight MQTT broker\n"
                    "#\n"
                    "# port             : MQTT listen port\n"
                    "# max_clients      : Maximum connected clients\n"
                    "# max_message_size : Maximum message size in bytes\n"
                    "enabled = true\n\n"
                    "[mod_mqtt]\n"
                    "port = 1883\n"
                    "max_clients = 256\n"
                    "max_message_size = 65536\n");
            } else if (strcmp(mod, "websocket") == 0) {
                fprintf(f,
                    "# mod_websocket — WebSocket server\n"
                    "#\n"
                    "# port        : WebSocket listen port\n"
                    "# max_clients : Maximum connected clients\n"
                    "enabled = true\n\n"
                    "[mod_websocket]\n"
                    "port = 9090\n"
                    "max_clients = 256\n");
            } else if (strcmp(mod, "shm") == 0) {
                fprintf(f,
                    "# mod_shm — POSIX shared memory regions\n"
                    "#\n"
                    "# max_regions : Maximum shared memory regions\n"
                    "# max_size    : Maximum size per region in bytes\n"
                    "enabled = true\n\n"
                    "[mod_shm]\n"
                    "max_regions = 32\n"
                    "max_size = 10485760\n");
            } else if (strcmp(mod, "serial") == 0) {
                fprintf(f,
                    "# mod_serial — RS232/serial port communication\n"
                    "#\n"
                    "# max_ports : Maximum open serial ports\n"
                    "enabled = true\n\n"
                    "[mod_serial]\n"
                    "max_ports = 16\n");
            } else if (strcmp(mod, "ldap") == 0) {
                fprintf(f,
                    "# mod_ldap — LDAP/Active Directory authentication\n"
                    "#\n"
                    "# server      : LDAP server URL (ldap://host:port)\n"
                    "# base_dn     : Base distinguished name\n"
                    "# bind_dn     : DN to bind as (empty = anonymous)\n"
                    "# bind_pass   : Bind password\n"
                    "# user_filter : User search filter (%%s = username)\n"
                    "enabled = false\n\n"
                    "[mod_ldap]\n"
                    "server = ldap://localhost:389\n"
                    "base_dn = dc=example,dc=com\n"
                    "bind_dn =\n"
                    "bind_pass =\n"
                    "user_filter = (uid=%%s)\n");
            } else {
                /* Generic config for simple modules */
                fprintf(f, "# mod_%s\nenabled = true\n", mod);
            }

            fclose(f);
            added++;
        }
        closedir(sd);

        if (added > 0)
            printf("  %s: added %d missing module configs\n", pent->d_name, added);
        else
            printf("  %s: up to date\n", pent->d_name);
    }
    closedir(pd);
    printf("\nDone.\n");
    return 0;
}

static int show_status(void)
{
    DIR *d = opendir("/etc/portal");
    if (!d) { fprintf(stderr, "No instances found in /etc/portal/\n"); return 1; }

    printf("Portal v" PORTAL_VERSION_STR " — Instance Status\n");
    printf("================================================\n\n");
    printf("  %-16s %-8s %-6s %-8s %-8s %-8s %s\n",
           "INSTANCE", "STATUS", "PID", "HTTP", "HTTPS", "NODE", "MODULES");
    printf("  %-16s %-8s %-6s %-8s %-8s %-8s %s\n",
           "--------", "------", "---", "----", "-----", "----", "-------");

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        /* Check if it's a portal instance (has portal.conf) */
        char conf[600];
        snprintf(conf, sizeof(conf), "/etc/portal/%s/portal.conf", ent->d_name);
        struct stat st;
        if (stat(conf, &st) != 0) continue;

        /* Check PID file */
        char pid_file[512];
        snprintf(pid_file, sizeof(pid_file), "/var/run/portal-%s.pid", ent->d_name);
        int pid = 0;
        const char *status = "stopped";
        FILE *pf = fopen(pid_file, "r");
        if (pf) {
            if (fscanf(pf, "%d", &pid) == 1) {
                char proc[64];
                snprintf(proc, sizeof(proc), "/proc/%d", pid);
                if (stat(proc, &st) == 0) status = "running";
                else { status = "dead"; pid = 0; }
            }
            fclose(pf);
        }

        /* Also check via socket */
        if (pid == 0) {
            char sock[512];
            snprintf(sock, sizeof(sock), "/var/run/portal-%s.sock", ent->d_name);
            if (stat(sock, &st) == 0 && S_ISSOCK(st.st_mode))
                status = "running";
        }

        /* Read ports from config */
        char http[16] = "-", https[16] = "-", node[16] = "-";
        char modules_str[16] = "-";
        FILE *cf = fopen(conf, "r");
        if (cf) {
            char line[512];
            while (fgets(line, sizeof(line), cf)) {
                /* Trim */
                char *s = line;
                while (*s == ' ' || *s == '\t') s++;
                /* Skip comments */
                if (*s == '#' || *s == ';') continue;
            }
            fclose(cf);
        }

        /* Read ports from per-module configs */
        char web_conf[600];
        snprintf(web_conf, sizeof(web_conf), "/etc/portal/%s/modules/core/mod_web.conf", ent->d_name);
        cf = fopen(web_conf, "r");
        if (cf) {
            char line[512];
            while (fgets(line, sizeof(line), cf)) {
                char *s = line; while (*s == ' ') s++;
                if (strncmp(s, "port", 4) == 0 && (s[4] == ' ' || s[4] == '=')) {
                    char *eq = strchr(s, '=');
                    if (eq) { while (*++eq == ' '); snprintf(http, sizeof(http), "%s", eq);
                        char *nl = strchr(http, '\n'); if (nl) *nl = '\0'; }
                }
                if (strncmp(s, "tls_port", 8) == 0) {
                    char *eq = strchr(s, '=');
                    if (eq) { while (*++eq == ' '); snprintf(https, sizeof(https), "%s", eq);
                        char *nl = strchr(https, '\n'); if (nl) *nl = '\0'; }
                }
            }
            fclose(cf);
        }

        char node_conf[600];
        snprintf(node_conf, sizeof(node_conf), "/etc/portal/%s/modules/core/mod_node.conf", ent->d_name);
        cf = fopen(node_conf, "r");
        if (cf) {
            char line[512];
            while (fgets(line, sizeof(line), cf)) {
                char *s = line; while (*s == ' ') s++;
                if (strncmp(s, "listen_port", 11) == 0) {
                    char *eq = strchr(s, '=');
                    if (eq) { while (*++eq == ' '); snprintf(node, sizeof(node), "%s", eq);
                        char *nl = strchr(node, '\n'); if (nl) *nl = '\0'; }
                }
            }
            fclose(cf);
        }

        /* Count module configs */
        int mcount = 0;
        char mdir[600];
        snprintf(mdir, sizeof(mdir), "/etc/portal/%s/modules/core", ent->d_name);
        DIR *md = opendir(mdir);
        if (md) { struct dirent *me; while ((me = readdir(md))) if (strstr(me->d_name, ".conf")) mcount++; closedir(md); }
        snprintf(mdir, sizeof(mdir), "/etc/portal/%s/modules", ent->d_name);
        md = opendir(mdir);
        if (md) { struct dirent *me; while ((me = readdir(md))) if (strstr(me->d_name, ".conf")) mcount++; closedir(md); }
        snprintf(modules_str, sizeof(modules_str), "%d", mcount);

        printf("  %-16s %-8s %-6d %-8s %-8s %-8s %s\n",
               ent->d_name, status, pid, http, https, node, modules_str);
    }
    closedir(d);
    printf("\n");
    return 0;
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Portal v" PORTAL_VERSION_STR " — Universal Modular Core\n"
        "\n"
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  -C <name>   Create a new instance\n"
        "  -D <name>   Delete an instance\n"
        "  -n <name>   Instance name\n"
        "  -f          Run in foreground\n"
        "  -d          Debug mode\n"
        "  -r          Connect to running instance CLI\n"
        "  -s          Show status of all instances\n"
        "  -U          Update all instances (add missing module configs)\n"
        "  -v          Show version\n"
        "  -c <path>   Config file override\n"
        "  -h          Show this help\n",
        prog);
}

int main(int argc, char **argv)
{
    const char *config_path = PORTAL_DEFAULT_CONFIG;
    const char *instance_name = NULL;
    const char *create_name = NULL;
    const char *delete_name = NULL;
    int foreground = 0;
    int debug = 0;
    int remote_cli = 0;
    int opt;

    while ((opt = getopt(argc, argv, "C:D:c:n:fdrsUvh")) != -1) {
        switch (opt) {
        case 'C': create_name = optarg; break;
        case 'D': delete_name = optarg; break;
        case 'c': config_path = optarg; break;
        case 'n': instance_name = optarg; break;
        case 'f': foreground = 1; break;
        case 'd': debug = 1; break;
        case 'r': remote_cli = 1; break;
        case 's': return show_status();
        case 'U': return update_instances();
        case 'v':
            printf("Portal v%s\n", PORTAL_VERSION_STR);
            return 0;
        case 'h':
        default:
            print_usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    /* Create instance mode */
    if (create_name)
        return create_instance(create_name);

    /* Delete instance mode */
    if (delete_name)
        return delete_instance(delete_name);

    /* Remote CLI mode — just connect to running instance */
    if (remote_cli) {
        portal_config_t cfg;
        portal_config_defaults(&cfg);
        /* If instance name given, try instance-specific config */
        if (instance_name) {
            char inst_conf[PORTAL_MAX_PATH_LEN + 32];
            snprintf(inst_conf, sizeof(inst_conf), "/etc/portal/%s/portal.conf",
                     instance_name);
            portal_config_load(&cfg, inst_conf);
        } else {
            portal_config_load(&cfg, config_path);
        }
        return run_remote_cli(cfg.socket_path, instance_name);
    }

    /* Initialize instance */
    if (portal_instance_init(&g_instance) < 0) {
        fprintf(stderr, "Failed to initialize portal\n");
        return 1;
    }

    /* Apply instance name — overrides data_dir and config path */
    if (instance_name) {
        char inst_dir[PORTAL_MAX_PATH_LEN];
        snprintf(inst_dir, sizeof(inst_dir), "/etc/portal/%s", instance_name);
        snprintf(g_instance.config.data_dir, sizeof(g_instance.config.data_dir),
                 "%s", inst_dir);

        /* Use instance-specific config if it exists */
        char inst_conf[PORTAL_MAX_PATH_LEN + 32];
        snprintf(inst_conf, sizeof(inst_conf), "%s/portal.conf", inst_dir);
        if (access(inst_conf, F_OK) == 0)
            config_path = inst_conf;
    }

    /* Load config */
    portal_config_load(&g_instance.config, config_path);

    /* Instance name overrides data_dir after config load */
    if (instance_name)
        snprintf(g_instance.config.data_dir,
                 sizeof(g_instance.config.data_dir),
                 "/etc/portal/%s", instance_name);

    /* Load per-module config files from <data_dir>/modules/ */
    portal_config_load_modules_dir(&g_instance.config);

    /* Apply debug override */
    if (debug)
        g_instance.config.log_level = PORTAL_LOG_DEBUG;

    portal_log_set_level(g_instance.config.log_level);

    LOG_INFO("core", "Portal v%s starting", PORTAL_VERSION_STR);
    LOG_INFO("core", "Modules directory: %s", g_instance.config.modules_dir);

    /* Initialize module registry */
    portal_module_registry_init(&g_instance.modules,
                                 g_instance.config.modules_dir);

    /* Register internal core paths */
    portal_instance_register_core_paths(&g_instance);

    /* Initialize persistent store */
    portal_store_init(&g_instance.store, g_instance.config.data_dir);

    /* Load users: try store first, fall back to legacy users.conf */
    char users_dir[PORTAL_MAX_PATH_LEN + 32];
    snprintf(users_dir, sizeof(users_dir), "%s/users",
             g_instance.config.data_dir);
    if (access(users_dir, F_OK) == 0) {
        portal_auth_load_from_store(&g_instance.auth, &g_instance.store);
    }
    /* Also load legacy file (merges any users not in store) */
    portal_auth_load_users(&g_instance.auth, g_instance.config.users_file);

    /* Signals handled by libev inside the event loop */
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

    /* Load configured modules */
    for (int i = 0; i < g_instance.config.module_count; i++) {
        const char *name = g_instance.config.modules[i];
        if (portal_module_do_load(&g_instance.modules, name,
                                   &g_instance.api) < 0) {
            LOG_WARN("core", "Failed to load module '%s' (soft dependency — continuing)", name);
        }
    }

    /* Session cleanup timer (every 60 seconds) */
    portal_event_add_timer(&g_instance.events, 60.0,
                            session_cleanup_cb, &g_instance);

    /* SIGHUP → reload config */
    portal_event_set_sighup(&g_instance.events, sighup_cb, &g_instance);

    /* Daemonize if not foreground */
    if (!foreground) {
        pid_t pid = fork();
        if (pid < 0) {
            LOG_ERROR("core", "Fork failed");
            portal_instance_destroy(&g_instance);
            return 1;
        }
        if (pid > 0) {
            /* Write PID file */
            FILE *pf = fopen(g_instance.config.pid_file, "w");
            if (pf) {
                fprintf(pf, "%d\n", pid);
                fclose(pf);
            }
            printf("Portal started (pid %d)\n", pid);
            return 0;
        }
        setsid();
    }

    /* Start core TCP/UDP listeners */
    start_network_listeners();

    LOG_INFO("core", "Entering event loop");

    /* Run */
    portal_event_run(&g_instance.events);

    /* Shutdown */
    LOG_INFO("core", "Shutting down");
    portal_instance_destroy(&g_instance);
    unlink(g_instance.config.pid_file);
    LOG_INFO("core", "Goodbye");

    return 0;
}
