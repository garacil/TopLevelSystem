/*
 * mod_cli — CLI module for Portal
 *
 * Provides a command-line interface over a UNIX domain socket.
 * Connect with portalctl or: socat - UNIX-CONNECT:/var/run/portal.sock
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "ev_config.h"
#include "ev.h"

#include "portal/portal.h"

#define CLI_MAX_CLIENTS   16
#define CLI_BUF_SIZE      4096
#define CLI_MAX_HISTORY   64
#define CLI_MAX_LINE      1024

/* Per-client line editor + history */
typedef struct {
    char  line[CLI_MAX_LINE];           /* current line being edited */
    int   pos;                          /* cursor position in line */
    int   len;                          /* length of current line */
    char  history[CLI_MAX_HISTORY][CLI_MAX_LINE];
    int   hist_count;                   /* total history entries */
    int   hist_pos;                     /* current browsing position (-1 = new) */
    /* Escape sequence state machine */
    int   esc_state;                    /* 0=normal, 1=got ESC, 2=got ESC[ */
    int   tab_count;                    /* consecutive tab presses */
} cli_line_editor_t;

/* Per-client state */
typedef struct {
    int                fd;
    char               cwd[PORTAL_MAX_PATH_LEN];
    char               token[64];
    char               username[64];
    int                active;
    int                top_active;   /* 1 = interactive `top` running */
    char               top_sort;     /* 'c'=cpu, 'm'=mem, 'p'=pid */
    int                top_threads;  /* 0/1 — show threads instead of procs */
    /* Shell mode (PTY session) */
    int                shell_active;    /* 1 = PTY shell running */
    char               shell_peer[64];  /* federation peer (empty = local) */
    char               shell_session[32]; /* PTY session_id from mod_shell */
    cli_line_editor_t  editor;
} cli_client_t;

/* Module state */
static portal_core_t *g_core = NULL;
static int             g_sock_fd = -1;
static char            g_socket_path[108]; /* matches sun_path size */

static cli_client_t  g_clients[CLI_MAX_CLIENTS];
static int            g_client_count = 0;

/* --- Module info --- */

static portal_module_info_t mod_info = {
    .name        = "cli",
    .version     = "0.1.0",
    .description = "CLI over UNIX socket",
    .soft_deps   = NULL
};

portal_module_info_t *portal_module_info(void)
{
    return &mod_info;
}

/* --- Helpers --- */

static void send_str(int fd, const char *str)
{
    write(fd, str, strlen(str));
}

static cli_client_t *find_client(int fd)
{
    for (int i = 0; i < g_client_count; i++) {
        if (g_clients[i].fd == fd && g_clients[i].active)
            return &g_clients[i];
    }
    return NULL;
}

static void send_prompt(int fd)
{
    cli_client_t *c = find_client(fd);
    if (c && c->shell_active) {
        return; /* PTY session provides its own prompt */
    } else if (c && strcmp(c->cwd, "/") != 0) {
        char buf[PORTAL_MAX_PATH_LEN + 16];
        snprintf(buf, sizeof(buf), "portal:%s> ", c->cwd);
        send_str(fd, buf);
    } else {
        send_str(fd, "portal:/> ");
    }
}

static void remove_client(int fd)
{
    g_core->trace_del(g_core, fd);  /* cleanup verbose/debug trace */
    g_core->fd_del(g_core, fd);
    close(fd);
    for (int i = 0; i < g_client_count; i++) {
        if (g_clients[i].fd == fd) {
            g_clients[i].active = 0;
            g_clients[i].top_active = 0;
            g_client_count--;
            break;
        }
    }
}

/* ── Attach CLI user's auth context to a portal message ── */
static void cli_attach_auth(int fd, portal_msg_t *msg)
{
    cli_client_t *c = find_client(fd);
    if (c && c->token[0]) {
        portal_ctx_t *ctx = calloc(1, sizeof(portal_ctx_t));
        if (ctx) {
            ctx->auth.user = strdup(c->username);
            ctx->auth.token = strdup(c->token);
            msg->ctx = ctx;
        }
    }
}

/* --- Command handlers --- */

/* ── help for built-in commands ── */

static void cmd_help_builtin(int fd, const char *cmd)
{
    if (strcmp(cmd, "get") == 0) {
        send_str(fd,
            "\n  get <path>[?key=value&...]\n\n"
            "    Read a resource or call a function at any Portal path.\n"
            "    Resolves relative paths when cd is active.\n"
            "    Query parameters become message headers.\n\n"
            "    Examples:\n"
            "      get /core/status\n"
            "      get /ssip/resources/report\n"
            "      get /ssip/functions/enable?job=check_sip\n"
            "      get /ssip/functions/set_interval?interval=120\n"
            "      cd /ssip/resources && get status    (relative path)\n\n");
    } else if (strcmp(cmd, "ls") == 0) {
        send_str(fd,
            "\n  ls [path]\n\n"
            "    List child paths at the given location (or current cd).\n"
            "    Shows path name and owning module.\n\n"
            "    Examples:\n"
            "      ls                     (list root)\n"
            "      ls /ssip               (list ssip children)\n"
            "      ls /ssip/functions      (list all ssip functions)\n"
            "      cd /ssip && ls          (same as ls /ssip)\n\n");
    } else if (strcmp(cmd, "cd") == 0) {
        send_str(fd,
            "\n  cd <path>\n\n"
            "    Change the working directory. Affects ls and get (relative paths).\n"
            "    The prompt shows the current path.\n\n"
            "    Examples:\n"
            "      cd /ssip/functions\n"
            "      get check_sip           (resolves to /ssip/functions/check_sip)\n"
            "      cd /                    (back to root)\n\n");
    } else if (strcmp(cmd, "set") == 0) {
        send_str(fd,
            "\n  set <path> <value>\n\n"
            "    Write a value to a path (sends SET method).\n\n"
            "    Examples:\n"
            "      set /kv/mykey hello_world\n"
            "      set /cache/session abc123\n\n");
    } else if (strcmp(cmd, "shell") == 0) {
        send_str(fd,
            "\n  shell [peer]\n\n"
            "    Open an interactive PTY shell on a remote peer or locally.\n"
            "    Supports full terminal: htop, vi, top, less, sudo.\n"
            "    Type 'exit' to return to Portal CLI.\n\n"
            "    Examples:\n"
            "      shell ssip841           (remote shell on ssip841 via federation)\n"
            "      shell                   (local shell on this machine)\n\n");
    } else {
        char buf[128];
        snprintf(buf, sizeof(buf), "No help available for '%s'.\n", cmd);
        send_str(fd, buf);
    }
}

/* ── help for a specific path: show module, access, labels, description ── */

struct help_path_ctx {
    const char *target_path;
    char module[64];
    uint8_t access_mode;
    char labels[256];
    char description[256];
    int found;
};

static void help_path_lookup_cb(const char *path, const char *module_name, void *ud)
{
    struct help_path_ctx *ctx = (struct help_path_ctx *)ud;
    if (strcmp(path, ctx->target_path) == 0) {
        snprintf(ctx->module, sizeof(ctx->module), "%s", module_name);
        ctx->found = 1;
    }
}

static void cmd_help_path(int fd, const char *path)
{
    /* Look up the path via path_iter to get the module name */
    struct help_path_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.target_path = path;
    g_core->path_iter(g_core, help_path_lookup_cb, &ctx);

    if (!ctx.found) {
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "Path '%s' not found. Try: ls %s\n", path,
                 strrchr(path, '/') ? path : "/");
        send_str(fd, buf);
        return;
    }

    /* Get full path info by sending a META message (or direct struct access) */
    /* We use the core's internal path_lookup_entry via a send to /core/resolve */
    /* For now: display what we know from iter + a GET to show live data */

    char buf[2048];
    int pos = 0;

    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                    "\n  %s\n\n", path);
    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                    "    Module:  %s\n", ctx.module);

    /* Determine access mode and description by looking at path convention */
    const char *type = "unknown";
    if (strstr(path, "/resources/")) type = "READ (resource)";
    else if (strstr(path, "/functions/")) type = "RW (function)";
    else if (strstr(path, "/events/")) type = "READ (event)";

    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                    "    Access:  %s\n", type);

    /* Try to get the description by doing a GET — the response tells us something */
    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                    "\n    CLI usage:\n");

    if (strstr(path, "/resources/")) {
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        "      get %s\n", path);
    } else if (strstr(path, "/functions/")) {
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        "      get %s\n"
                        "      get %s?param=value\n", path, path);
    }

    /* Suggest help <module> for more context */
    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                    "\n    See also: help %s\n\n", ctx.module);

    send_str(fd, buf);
}

/* ── help <module>: dynamic path discovery for any module ── */

struct help_module_ctx {
    int fd;
    const char *module;
    char resources[32][256];
    char functions[32][256];
    int res_count;
    int fn_count;
};

static void help_module_path_cb(const char *path, const char *module_name, void *ud)
{
    struct help_module_ctx *ctx = (struct help_module_ctx *)ud;
    if (strcmp(module_name, ctx->module) != 0) return;

    /* Classify as resource or function based on path convention */
    if (ctx->res_count < 32 && strstr(path, "/resources/"))
        snprintf(ctx->resources[ctx->res_count++], 256, "%s", path);
    else if (ctx->fn_count < 32 && strstr(path, "/functions/"))
        snprintf(ctx->functions[ctx->fn_count++], 256, "%s", path);
    else if (ctx->res_count < 32)
        snprintf(ctx->resources[ctx->res_count++], 256, "%s", path);
}

static void cmd_help_module(int fd, const char *module)
{
    struct help_module_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.fd = fd;
    ctx.module = module;

    /* Enumerate all paths belonging to this module */
    g_core->path_iter(g_core, help_module_path_cb, &ctx);

    if (ctx.res_count == 0 && ctx.fn_count == 0) {
        char buf[384];
        snprintf(buf, sizeof(buf),
                 "Module '%s' not found or has no registered paths.\n"
                 "Type 'module list' to see loaded modules.\n", module);
        send_str(fd, buf);
        return;
    }

    char buf[4096];
    int pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                    "\n  %s — registered paths:\n\n", module);

    if (ctx.res_count > 0) {
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        "  Resources (read with 'get'):\n");
        for (int i = 0; i < ctx.res_count; i++)
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                            "    get %s\n", ctx.resources[i]);
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, "\n");
    }

    if (ctx.fn_count > 0) {
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        "  Functions (call with 'get <path>?param=value'):\n");
        for (int i = 0; i < ctx.fn_count; i++)
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                            "    get %s\n", ctx.functions[i]);
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, "\n");
    }

    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                    "  Explore: ls /%s\n\n", module);

    send_str(fd, buf);
}

/* ── help: compact, grouped, discoverable ── */

struct help_modules_ctx {
    char names[128][64];
    int count;
};

static void help_list_modules_cb(const char *name, const char *version,
                                  int loaded, uint64_t msg_count,
                                  uint64_t last_msg_us, void *ud)
{
    (void)version; (void)msg_count; (void)last_msg_us;
    struct help_modules_ctx *ctx = (struct help_modules_ctx *)ud;
    if (!loaded || ctx->count >= 128) return;
    /* Skip core infrastructure modules from the help list */
    if (strcmp(name, "cli") == 0 || strcmp(name, "config_sqlite") == 0 ||
        strcmp(name, "config_psql") == 0 || strcmp(name, "web") == 0 ||
        strcmp(name, "ssh") == 0)
        return;
    snprintf(ctx->names[ctx->count++], 64, "%s", name);
}

static void cmd_help(int fd)
{
    send_str(fd,
        "\n"
        "  Navigate\n"
        "    ls [path]           List paths at current or given location\n"
        "    cd <path>           Change directory (get resolves relative paths)\n"
        "    get <path>          Read any resource or call any function\n"
        "    pwd                 Show current path\n"
        "\n"
        "  Quick\n"
        "    status              Core status          health    Module health\n"
        "    sysinfo             System info           metrics   CPU/mem/disk\n"
        "    uptime              Uptime                version   Portal version\n"
        "    top                 Live process viewer   events    List events\n"
        "\n"
        "  Session\n"
        "    login <user> [pass]   Log in             logout    Log out\n"
        "    whoami                Show identity       passwd    Change password\n"
        "    key / key rotate      API key management\n"
        "\n"
        "  Modules\n"
        "    module list/load/unload/reload            Manage modules\n"
        "    config get/set/list <mod> <key> [val]     Module configuration\n"
        "\n"
        "  Debug\n"
        "    verbose [filter]    Trace messages        debug [filter]  + body dump\n"
        "    locks [path]        Resource locks        path list       All paths\n"
        "\n"
    );

    /* Dynamic module list */
    struct help_modules_ctx mctx;
    memset(&mctx, 0, sizeof(mctx));
    g_core->module_iter(g_core, help_list_modules_cb, &mctx);

    if (mctx.count > 0) {
        char buf[2048];
        int pos = 0;
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        "  Loaded modules — type 'help <name>' for paths:\n    ");
        for (int i = 0; i < mctx.count; i++) {
            if (i > 0 && i % 8 == 0)
                pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, "\n    ");
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                            "%-14s", mctx.names[i]);
        }
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, "\n\n");
        send_str(fd, buf);
    }

    send_str(fd,
        "  Tip: Tab to autocomplete · get works with cd (relative paths)\n"
        "       help <module> shows all paths · ls / to browse everything\n"
        "\n"
    );
}

static void cmd_core_get(int fd, const char *path)
{
    /* Clean path: trim trailing spaces and slashes */
    char clean[PORTAL_MAX_PATH_LEN];
    snprintf(clean, sizeof(clean), "%s", path);
    size_t clen = strlen(clean);
    while (clen > 1 && (clean[clen-1] == ' ' || clean[clen-1] == '/'))
        clean[--clen] = '\0';

    /* Split path?query — parse query params as headers (Law 12) */
    char *query = strchr(clean, '?');
    if (query) *query++ = '\0';

    portal_msg_t *msg = portal_msg_alloc();
    portal_resp_t *resp = portal_resp_alloc();
    if (msg && resp) {
        portal_msg_set_path(msg, clean);
        /* Use CALL method if query params present (functions), GET otherwise (resources) */
        portal_msg_set_method(msg, query ? PORTAL_METHOD_CALL : PORTAL_METHOD_GET);

        /* Parse query string: key=value&key2=value2 */
        if (query && query[0]) {
            char qbuf[1024];
            snprintf(qbuf, sizeof(qbuf), "%s", query);
            char *saveptr;
            char *pair = strtok_r(qbuf, "&", &saveptr);
            while (pair) {
                char *eq = strchr(pair, '=');
                if (eq) {
                    *eq = '\0';
                    portal_msg_add_header(msg, pair, eq + 1);
                }
                pair = strtok_r(NULL, "&", &saveptr);
            }
        }

        int rc = g_core->send(g_core, msg, resp);
        if (rc == 0 && resp->body) {
            size_t blen = resp->body_len;
            const uint8_t *body = resp->body;
            if (blen > 0 && body[blen - 1] == '\0') blen--;
            write(fd, "\r\033[K", 4);

            /* Detect binary: if any non-printable chars (except \n \r \t) */
            int is_binary = 0;
            for (size_t i = 0; i < blen && i < 256; i++) {
                if (body[i] < 32 && body[i] != '\n' && body[i] != '\r' && body[i] != '\t') {
                    is_binary = 1; break;
                }
                if (body[i] == 127) { is_binary = 1; break; }
            }

            if (is_binary) {
                /* Hex + ASCII dump */
                for (size_t off = 0; off < blen; off += 16) {
                    char hline[128];
                    int hp = snprintf(hline, sizeof(hline), "  %04zx  ", off);
                    for (size_t j = 0; j < 16; j++) {
                        if (off + j < blen)
                            hp += snprintf(hline + hp, sizeof(hline) - (size_t)hp,
                                          "%02x ", body[off + j]);
                        else
                            hp += snprintf(hline + hp, sizeof(hline) - (size_t)hp, "   ");
                    }
                    hp += snprintf(hline + hp, sizeof(hline) - (size_t)hp, " ");
                    for (size_t j = 0; j < 16 && off + j < blen; j++) {
                        uint8_t c = body[off + j];
                        hline[hp++] = (c >= 32 && c < 127) ? (char)c : '.';
                    }
                    hline[hp++] = '\n'; hline[hp] = '\0';
                    write(fd, hline, (size_t)hp);
                }
                char summary[64];
                int sn = snprintf(summary, sizeof(summary), "  (%zu bytes binary)\n", blen);
                write(fd, summary, (size_t)sn);
            } else {
                write(fd, body, blen);
                if (blen > 0 && body[blen - 1] != '\n')
                    write(fd, "\n", 1);
            }
        } else {
            write(fd, "\r\033[K", 4);
            send_str(fd, "(unavailable)\n");
        }
        portal_msg_free(msg);
        portal_resp_free(resp);
    }
}

static void cmd_status(int fd)
{
    cmd_core_get(fd, "/core/status");
}

static void cmd_version(int fd)
{
    char buf[384];
    snprintf(buf, sizeof(buf), "Portal v%s\n", PORTAL_VERSION_STR);
    send_str(fd, buf);
}

static void cmd_path_list(int fd)
{
    cmd_core_get(fd, "/core/paths");
}

static void cmd_module_list(int fd)
{
    cmd_core_get(fd, "/core/modules");
}

static void cmd_pwd(int fd)
{
    cli_client_t *c = find_client(fd);
    send_str(fd, c ? c->cwd : "/");
    send_str(fd, "\n");
}

static void cmd_cd(int fd, const char *target)
{
    cli_client_t *c = find_client(fd);
    if (!c) return;

    /* Use core resolve to normalize the path */
    portal_msg_t *msg = portal_msg_alloc();
    portal_resp_t *resp = portal_resp_alloc();
    if (!msg || !resp) return;

    portal_msg_set_path(msg, "/core/resolve");
    portal_msg_set_method(msg, PORTAL_METHOD_GET);
    portal_msg_add_header(msg, "cwd", c->cwd);
    portal_msg_add_header(msg, "target", target ? target : "/");

    g_core->send(g_core, msg, resp);
    if (resp->status == PORTAL_OK && resp->body)
        snprintf(c->cwd, sizeof(c->cwd), "%s", (char *)resp->body);

    portal_msg_free(msg);
    portal_resp_free(resp);
}

static void cmd_ls(int fd, const char *arg)
{
    cli_client_t *c = find_client(fd);
    if (!c) return;

    /* Determine prefix: argument or current cwd */
    const char *prefix;
    if (arg && arg[0] != '\0')
        prefix = (arg[0] == '/') ? arg : arg;  /* absolute or relative */
    else
        prefix = c->cwd;

    portal_msg_t *msg = portal_msg_alloc();
    portal_resp_t *resp = portal_resp_alloc();
    if (!msg || !resp) return;

    /*
     * Remote ls: detect if prefix targets a remote node.
     * /devtest2         → remote ls with prefix=/
     * /devtest2/hello   → remote ls with prefix=/hello
     * /devtest2/hello/resources → remote ls with prefix=/hello/resources
     *
     * Detection: try sending to /<node>/core/ls — if it works, it's remote
     */
    if (prefix[0] == '/' && strlen(prefix) > 1) {
        const char *first_seg = prefix + 1;
        const char *slash = strchr(first_seg, '/');

        char node_name[PORTAL_MAX_MODULE_NAME];
        const char *remote_prefix = "/";

        if (slash) {
            size_t nlen = (size_t)(slash - first_seg);
            if (nlen < sizeof(node_name)) {
                memcpy(node_name, first_seg, nlen);
                node_name[nlen] = '\0';
                remote_prefix = slash;  /* /hello or /hello/resources */
            }
        } else {
            snprintf(node_name, sizeof(node_name), "%s", first_seg);
            remote_prefix = "/";  /* top level of remote node */
        }

        /* Try remote ls — if it works, this is a remote node */
        {
            char remote_ls[PORTAL_MAX_PATH_LEN];
            snprintf(remote_ls, sizeof(remote_ls), "/%s/core/ls", node_name);

            portal_msg_set_path(msg, remote_ls);
            portal_msg_set_method(msg, PORTAL_METHOD_GET);
            portal_msg_add_header(msg, "prefix", remote_prefix);

            int rc = g_core->send(g_core, msg, resp);
            if (rc == 0 && resp->body && resp->body_len > 0) {
                send_str(fd, resp->body);
                portal_msg_free(msg);
                portal_resp_free(resp);
                return;
            }
            /* If remote failed, fall through to local ls */
            portal_msg_free(msg);
            portal_resp_free(resp);
            msg = portal_msg_alloc();
            resp = portal_resp_alloc();
            if (!msg || !resp) return;
        }
    }

    /* Local ls */
    portal_msg_set_path(msg, "/core/ls");
    portal_msg_set_method(msg, PORTAL_METHOD_GET);
    portal_msg_add_header(msg, "prefix", prefix);

    int rc = g_core->send(g_core, msg, resp);
    if (rc == 0 && resp->body)
        send_str(fd, resp->body);
    else
        send_str(fd, "(unavailable)\n");

    portal_msg_free(msg);
    portal_resp_free(resp);
}

static void cmd_login(int fd, const char *args)
{
    cli_client_t *c = find_client(fd);
    if (!c) return;

    /* Parse "username password" */
    char user[64] = {0}, pass[128] = {0};
    if (!args || sscanf(args, "%63s %127s", user, pass) < 1) {
        send_str(fd, "Usage: login <username> [password]\n");
        return;
    }

    portal_msg_t *msg = portal_msg_alloc();
    portal_resp_t *resp = portal_resp_alloc();
    if (!msg || !resp) return;

    portal_msg_set_path(msg, "/auth/login");
    portal_msg_set_method(msg, PORTAL_METHOD_CALL);
    portal_msg_add_header(msg, "username", user);
    portal_msg_add_header(msg, "password", pass);

    int rc = g_core->send(g_core, msg, resp);
    if (rc == 0 && resp->status == PORTAL_OK && resp->body) {
        /* Token is in body (with trailing newline) */
        char *token = resp->body;
        size_t tlen = strlen(token);
        if (tlen > 0 && token[tlen-1] == '\n') token[tlen-1] = '\0';
        snprintf(c->token, sizeof(c->token), "%s", token);
        snprintf(c->username, sizeof(c->username), "%s", user);
        char buf[384];
        snprintf(buf, sizeof(buf), "Logged in as %s\n", user);
        send_str(fd, buf);
    } else {
        send_str(fd, "Login failed\n");
    }

    portal_msg_free(msg);
    portal_resp_free(resp);
}

static void cmd_logout(int fd)
{
    cli_client_t *c = find_client(fd);
    if (!c) return;

    if (c->token[0] == '\0') {
        send_str(fd, "Not logged in\n");
        return;
    }

    portal_msg_t *msg = portal_msg_alloc();
    portal_resp_t *resp = portal_resp_alloc();
    if (!msg || !resp) return;

    portal_msg_set_path(msg, "/auth/logout");
    portal_msg_set_method(msg, PORTAL_METHOD_CALL);
    portal_msg_add_header(msg, "token", c->token);

    g_core->send(g_core, msg, resp);
    c->token[0] = '\0';
    c->username[0] = '\0';
    send_str(fd, "Logged out\n");

    portal_msg_free(msg);
    portal_resp_free(resp);
}

static void cmd_whoami(int fd)
{
    cli_client_t *c = find_client(fd);
    if (!c) return;

    portal_msg_t *msg = portal_msg_alloc();
    portal_resp_t *resp = portal_resp_alloc();
    if (!msg || !resp) return;

    portal_msg_set_path(msg, "/auth/whoami");
    portal_msg_set_method(msg, PORTAL_METHOD_GET);
    if (c->token[0] != '\0')
        portal_msg_add_header(msg, "token", c->token);

    int rc = g_core->send(g_core, msg, resp);
    if (rc == 0 && resp->body)
        send_str(fd, resp->body);
    else
        send_str(fd, "anonymous (not logged in)\n");

    portal_msg_free(msg);
    portal_resp_free(resp);
}

static void cmd_module_load(int fd, const char *name)
{
    portal_msg_t *msg = portal_msg_alloc();
    portal_resp_t *resp = portal_resp_alloc();
    if (msg && resp) {
        char path[256];
        snprintf(path, sizeof(path), "/core/modules/%s", name);
        portal_msg_set_path(msg, path);
        portal_msg_set_method(msg, PORTAL_METHOD_CALL);
        portal_msg_add_header(msg, "action", "load");
        int rc = g_core->send(g_core, msg, resp);
        if (rc == 0 && resp->status == PORTAL_OK) {
            char buf[384];
            snprintf(buf, sizeof(buf), "Module '%s' loaded\n", name);
            send_str(fd, buf);
        } else {
            char buf[384];
            snprintf(buf, sizeof(buf), "Failed to load module '%s'\n", name);
            send_str(fd, buf);
        }
        portal_msg_free(msg);
        portal_resp_free(resp);
    }
}

static void cmd_module_unload(int fd, const char *name)
{
    if (strcmp(name, "cli") == 0) {
        send_str(fd, "Cannot unload CLI module from CLI\n");
        return;
    }
    portal_msg_t *msg = portal_msg_alloc();
    portal_resp_t *resp = portal_resp_alloc();
    if (msg && resp) {
        char path[256];
        snprintf(path, sizeof(path), "/core/modules/%s", name);
        portal_msg_set_path(msg, path);
        portal_msg_set_method(msg, PORTAL_METHOD_CALL);
        portal_msg_add_header(msg, "action", "unload");
        int rc = g_core->send(g_core, msg, resp);
        if (rc == 0 && resp->status == PORTAL_OK) {
            char buf[384];
            snprintf(buf, sizeof(buf), "Module '%s' unloaded\n", name);
            send_str(fd, buf);
        } else {
            char buf[384];
            snprintf(buf, sizeof(buf), "Failed to unload module '%s'\n", name);
            send_str(fd, buf);
        }
        portal_msg_free(msg);
        portal_resp_free(resp);
    }
}

/* --- Interactive `top` --- */

static void render_top_frame(cli_client_t *c)
{
    portal_msg_t *msg = portal_msg_alloc();
    portal_resp_t *resp = portal_resp_alloc();
    if (!msg || !resp) {
        if (msg) portal_msg_free(msg);
        if (resp) portal_resp_free(resp);
        return;
    }
    portal_msg_set_path(msg, "/process/resources/portal_top");
    portal_msg_set_method(msg, PORTAL_METHOD_GET);

    g_core->send(g_core, msg, resp);

    /* Home cursor, clear to end of screen */
    write(c->fd, "\033[H\033[2J", 7);

    /* Header */
    char hdr[128];
    int hn = snprintf(hdr, sizeof(hdr),
        "\033[7m portal top — modules + threads — [q]uit \033[0m\r\n");
    write(c->fd, hdr, (size_t)hn);

    if (resp->body && resp->body_len > 0)
        write(c->fd, resp->body, resp->body_len);
    else
        write(c->fd, "(no data)\r\n", 11);

    portal_msg_free(msg);
    portal_resp_free(resp);
}

static void cmd_top_enter(int fd)
{
    cli_client_t *c = find_client(fd);
    if (!c) return;
    c->top_active  = 1;
    c->top_sort    = 'c';
    c->top_threads = 0;
    /* Hide cursor, clear screen, home */
    write(fd, "\033[?25l\033[2J\033[H", 14);
    render_top_frame(c);
}

static void cmd_top_exit(cli_client_t *c)
{
    if (!c) return;
    c->top_active = 0;
    /* Show cursor, clear, home */
    write(c->fd, "\033[?25h\033[2J\033[H", 14);
    send_prompt(c->fd);
}

static void top_timer_cb(void *userdata)
{
    (void)userdata;
    for (int i = 0; i < CLI_MAX_CLIENTS; i++) {
        if (g_clients[i].active && g_clients[i].top_active)
            render_top_frame(&g_clients[i]);
    }
}

/* --- Command dispatch --- */

static void handle_command(int fd, char *line)
{
    /* Trim trailing newline/CR/space */
    size_t len = strlen(line);
    while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' || line[len-1] == ' '))
        line[--len] = '\0';

    if (len == 0) {
        send_prompt(fd);
        return;
    }

    /* ── Shell PTY mode: intercept all input, send to PTY session ── */
    cli_client_t *sh = find_client(fd);
    if (sh && sh->shell_active) {
        if (strcmp(line, "exit") == 0) {
            /* Close PTY session */
            char spath[256];
            if (sh->shell_peer[0])
                snprintf(spath, sizeof(spath), "/%s/shell/functions/close", sh->shell_peer);
            else
                snprintf(spath, sizeof(spath), "/shell/functions/close");

            portal_msg_t *cm = portal_msg_alloc();
            portal_resp_t *cr = portal_resp_alloc();
            if (cm && cr) {
                portal_msg_set_path(cm, spath);
                portal_msg_set_method(cm, PORTAL_METHOD_CALL);
                portal_msg_add_header(cm, "session", sh->shell_session);
                cli_attach_auth(fd, cm);
                g_core->send(g_core, cm, cr);
                portal_msg_free(cm); portal_resp_free(cr);
            }
            sh->shell_active = 0;
            sh->shell_peer[0] = '\0';
            sh->shell_session[0] = '\0';
            send_str(fd, "Disconnected\n");
            send_prompt(fd);
            return;
        }

        /* Write input + newline to PTY */
        char spath[256];
        if (sh->shell_peer[0])
            snprintf(spath, sizeof(spath), "/%s/shell/functions/write", sh->shell_peer);
        else
            snprintf(spath, sizeof(spath), "/shell/functions/write");

        /* Send the command + newline as raw bytes to the PTY */
        char input[4096];
        int ilen = snprintf(input, sizeof(input), "%s\n", line);

        portal_msg_t *wm = portal_msg_alloc();
        portal_resp_t *wr = portal_resp_alloc();
        if (wm && wr) {
            portal_msg_set_path(wm, spath);
            portal_msg_set_method(wm, PORTAL_METHOD_CALL);
            portal_msg_add_header(wm, "session", sh->shell_session);
            portal_msg_set_body(wm, input, (size_t)ilen);
            cli_attach_auth(fd, wm);
            g_core->send(g_core, wm, wr);
            portal_msg_free(wm); portal_resp_free(wr);
        }

        /* Read output from PTY */
        if (sh->shell_peer[0])
            snprintf(spath, sizeof(spath), "/%s/shell/functions/read", sh->shell_peer);
        else
            snprintf(spath, sizeof(spath), "/shell/functions/read");

        portal_msg_t *rm = portal_msg_alloc();
        portal_resp_t *rr = portal_resp_alloc();
        if (rm && rr) {
            portal_msg_set_path(rm, spath);
            portal_msg_set_method(rm, PORTAL_METHOD_CALL);
            portal_msg_add_header(rm, "session", sh->shell_session);
            cli_attach_auth(fd, rm);
            g_core->send(g_core, rm, rr);
            if (rr->body && rr->body_len > 0)
                write(fd, rr->body, rr->body_len);
            portal_msg_free(rm); portal_resp_free(rr);
        }
        /* No explicit prompt — the PTY shell provides its own prompt */
        return;
    }

    if (strcmp(line, "help") == 0 || strcmp(line, "?") == 0) {
        cmd_help(fd);
    } else if (strncmp(line, "help ", 5) == 0) {
        const char *arg = line + 5;
        while (*arg == ' ') arg++;
        if (arg[0] == '/') {
            /* help /some/path → show path info */
            cmd_help_path(fd, arg);
        } else if (strcmp(arg, "get") == 0 || strcmp(arg, "ls") == 0 ||
                   strcmp(arg, "cd") == 0 || strcmp(arg, "set") == 0 ||
                   strcmp(arg, "shell") == 0) {
            /* help <builtin_command> → show command usage */
            cmd_help_builtin(fd, arg);
        } else {
            /* help <module_name> → show module paths */
            cmd_help_module(fd, arg);
        }
    } else if (strcmp(line, "status") == 0) {
        cmd_status(fd);
    } else if (strcmp(line, "version") == 0) {
        cmd_version(fd);
    } else if (strcmp(line, "pwd") == 0) {
        cmd_pwd(fd);
    } else if (strcmp(line, "cd") == 0) {
        cmd_cd(fd, "/");
    } else if (strncmp(line, "cd ", 3) == 0) {
        cmd_cd(fd, line + 3);
    } else if (strcmp(line, "ls") == 0) {
        cmd_ls(fd, NULL);
    } else if (strncmp(line, "ls ", 3) == 0) {
        cmd_ls(fd, line + 3);
    } else if (strncmp(line, "login ", 6) == 0) {
        cmd_login(fd, line + 6);
    } else if (strcmp(line, "login") == 0) {
        send_str(fd, "Usage: login <username> [password]\n");
    } else if (strcmp(line, "logout") == 0) {
        cmd_logout(fd);
    } else if (strcmp(line, "whoami") == 0) {
        cmd_whoami(fd);
    } else if (strcmp(line, "module list") == 0) {
        cmd_module_list(fd);
    } else if (strncmp(line, "module load ", 12) == 0) {
        cmd_module_load(fd, line + 12);
    } else if (strncmp(line, "module unload ", 14) == 0) {
        cmd_module_unload(fd, line + 14);
    } else if (strncmp(line, "module reload ", 14) == 0) {
        /* Reuse load with action=reload */
        const char *name = line + 14;
        portal_msg_t *msg = portal_msg_alloc();
        portal_resp_t *resp = portal_resp_alloc();
        if (msg && resp) {
            char path[256];
            snprintf(path, sizeof(path), "/core/modules/%s", name);
            portal_msg_set_path(msg, path);
            portal_msg_set_method(msg, PORTAL_METHOD_CALL);
            portal_msg_add_header(msg, "action", "reload");
            int rc = g_core->send(g_core, msg, resp);
            char buf[384];
            snprintf(buf, sizeof(buf), rc == 0 ? "Module '%s' reloaded\n" : "Failed to reload '%s'\n", name);
            send_str(fd, buf);
            portal_msg_free(msg);
            portal_resp_free(resp);
        }
    } else if (strcmp(line, "path list") == 0) {
        cmd_path_list(fd);
    } else if (strncmp(line, "get ", 4) == 0) {
        const char *target = line + 4;
        while (*target == ' ') target++;
        if (*target == '/') {
            cmd_core_get(fd, target);
        } else {
            /* Resolve relative path using cwd */
            cli_client_t *gc = find_client(fd);
            char resolved[PORTAL_MAX_PATH_LEN * 2];
            if (gc && strcmp(gc->cwd, "/") != 0)
                snprintf(resolved, sizeof(resolved), "%s/%s", gc->cwd, target);
            else
                snprintf(resolved, sizeof(resolved), "/%s", target);
            cmd_core_get(fd, resolved);
        }
    } else if (strcmp(line, "storage") == 0) {
        cmd_core_get(fd, "/core/storage");
    } else if (strcmp(line, "events") == 0) {
        cmd_core_get(fd, "/events");
    } else if (strncmp(line, "node location ", 14) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/node/functions/location");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "name", line + 14);
            g_core->send(g_core, m, r);
            if (r->body)
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "node gps ", 9) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/node/functions/location");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "gps", line + 9);
            g_core->send(g_core, m, r);
            if (r->body)
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strcmp(line, "node geolocate") == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/node/functions/geolocate");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            g_core->send(g_core, m, r);
            if (r->body)
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
            else
                send_str(fd, "(geolocation failed)\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strcmp(line, "locks") == 0) {
        cmd_core_get(fd, "/core/locks");
    } else if (strncmp(line, "locks ", 6) == 0) {
        /* locks /serial — filter by resource prefix */
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/core/locks");
            portal_msg_set_method(m, PORTAL_METHOD_GET);
            portal_msg_add_header(m, "resource", line + 6);
            g_core->send(g_core, m, r);
            if (r->body)
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
            else
                send_str(fd, "(none)\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "lock ", 5) == 0) {
        cli_client_t *c = find_client(fd);
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            char owner[128];
            snprintf(owner, sizeof(owner), "%s@cli:%d",
                     c && c->username[0] ? c->username : "?", fd);
            portal_msg_set_path(m, "/core/locks/lock");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "resource", line + 5);
            portal_msg_add_header(m, "owner", owner);
            g_core->send(g_core, m, r);
            if (r->body)
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "unlock ", 7) == 0) {
        cli_client_t *c = find_client(fd);
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            char owner[128];
            snprintf(owner, sizeof(owner), "%s@cli:%d",
                     c && c->username[0] ? c->username : "?", fd);
            portal_msg_set_path(m, "/core/locks/unlock");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "resource", line + 7);
            portal_msg_add_header(m, "owner", owner);
            g_core->send(g_core, m, r);
            if (r->body)
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strcmp(line, "top") == 0) {
        cmd_top_enter(fd);
        return;  /* no prompt — top owns the screen */
    } else if (strcmp(line, "verbose off") == 0) {
        g_core->trace_del(g_core, fd);
        send_str(fd, "Verbose off\n");
    } else if (strncmp(line, "verbose", 7) == 0) {
        const char *filter = "/";
        if (line[7] == ' ') {
            filter = line + 8;
            while (*filter == ' ') filter++;  /* trim spaces */
            if (*filter == '\0') filter = "/";
        }
        /* Build prompt string for trace redraw */
        cli_client_t *c = find_client(fd);
        char prompt[64];
        if (c && strcmp(c->cwd, "/") != 0)
            snprintf(prompt, sizeof(prompt), "portal:%.50s> ", c->cwd);
        else
            snprintf(prompt, sizeof(prompt), "portal:/> ");
        g_core->trace_add(g_core, fd, filter, prompt,
                          c ? c->editor.line : NULL,
                          c ? &c->editor.len : NULL,
                          c ? &c->editor.pos : NULL, 0);
        char buf[256];
        snprintf(buf, sizeof(buf), "Verbose on: %s\n", filter);
        send_str(fd, buf);
    } else if (strcmp(line, "debug off") == 0) {
        g_core->trace_del(g_core, fd);
        send_str(fd, "Debug off\n");
    } else if (strncmp(line, "debug", 5) == 0) {
        const char *filter = "/";
        if (line[5] == ' ') {
            filter = line + 6;
            while (*filter == ' ') filter++;
            if (*filter == '\0') filter = "/";
        }
        cli_client_t *c = find_client(fd);
        char prompt[64];
        if (c && strcmp(c->cwd, "/") != 0)
            snprintf(prompt, sizeof(prompt), "portal:%.50s> ", c->cwd);
        else
            snprintf(prompt, sizeof(prompt), "portal:/> ");
        g_core->trace_add(g_core, fd, filter, prompt,
                          c ? c->editor.line : NULL,
                          c ? &c->editor.len : NULL,
                          c ? &c->editor.pos : NULL, 1);
        char buf[256];
        snprintf(buf, sizeof(buf), "Debug on: %s\n", filter);
        send_str(fd, buf);
    } else if (strncmp(line, "subscribe ", 10) == 0) {
        cli_client_t *c = find_client(fd);
        if (c) {
            portal_msg_t *msg = portal_msg_alloc();
            portal_resp_t *resp = portal_resp_alloc();
            if (msg && resp) {
                portal_msg_set_path(msg, line + 10);
                portal_msg_set_method(msg, PORTAL_METHOD_SUB);
                char fd_str[16];
                snprintf(fd_str, sizeof(fd_str), "%d", fd);
                portal_msg_add_header(msg, "notify_fd", fd_str);
                if (c->username[0]) {
                    msg->ctx = calloc(1, sizeof(portal_ctx_t));
                    if (msg->ctx) {
                        msg->ctx->auth.user = strdup(c->username);
                        if (c->token[0])
                            msg->ctx->auth.token = strdup(c->token);
                    }
                }
                int rc = g_core->send(g_core, msg, resp);
                send_str(fd, (rc == 0 && resp->body) ? resp->body : "Subscribe failed\n");
                portal_msg_free(msg);
                portal_resp_free(resp);
            }
        }
    } else if (strncmp(line, "unsubscribe ", 12) == 0) {
        cli_client_t *c = find_client(fd);
        if (c) {
            portal_msg_t *msg = portal_msg_alloc();
            portal_resp_t *resp = portal_resp_alloc();
            if (msg && resp) {
                portal_msg_set_path(msg, line + 12);
                portal_msg_set_method(msg, PORTAL_METHOD_UNSUB);
                if (c->username[0]) {
                    msg->ctx = calloc(1, sizeof(portal_ctx_t));
                    if (msg->ctx) msg->ctx->auth.user = strdup(c->username);
                }
                g_core->send(g_core, msg, resp);
                send_str(fd, resp->status == PORTAL_OK ? "Unsubscribed\n" : "Not found\n");
                portal_msg_free(msg);
                portal_resp_free(resp);
            }
        }
    } else if (strncmp(line, "passwd ", 7) == 0) {
        /* Change own password */
        cli_client_t *c = find_client(fd);
        if (c && c->username[0]) {
            portal_msg_t *m = portal_msg_alloc();
            portal_resp_t *r = portal_resp_alloc();
            if (m && r) {
                char p[256];
                snprintf(p, sizeof(p), "/users/%s/password", c->username);
                portal_msg_set_path(m, p);
                portal_msg_set_method(m, PORTAL_METHOD_CALL);
                portal_msg_add_header(m, "password", line + 7);
                g_core->send(g_core, m, r);
                send_str(fd, (r->body) ? r->body : "Failed\n");
                portal_msg_free(m); portal_resp_free(r);
            }
        } else {
            send_str(fd, "Not logged in\n");
        }
    } else if (strcmp(line, "key") == 0 || strcmp(line, "key rotate") == 0) {
        cli_client_t *c = find_client(fd);
        if (c) {
            const char *kpath = strcmp(line, "key rotate") == 0
                                ? "/auth/key/rotate" : "/auth/key";
            portal_msg_t *msg = portal_msg_alloc();
            portal_resp_t *resp = portal_resp_alloc();
            if (msg && resp) {
                portal_msg_set_path(msg, kpath);
                portal_msg_set_method(msg, strcmp(line, "key rotate") == 0
                                     ? PORTAL_METHOD_CALL : PORTAL_METHOD_GET);
                if (c->token[0])
                    portal_msg_add_header(msg, "token", c->token);
                int rc = g_core->send(g_core, msg, resp);
                send_str(fd, (rc == 0 && resp->body) ? resp->body : "Not logged in\n");
                portal_msg_free(msg);
                portal_resp_free(resp);
            }
        }
    } else if (strcmp(line, "user list") == 0) {
        cmd_core_get(fd, "/users");
    } else if (strncmp(line, "user info ", 10) == 0) {
        char p[256]; snprintf(p, sizeof(p), "/users/%s", line + 10);
        cmd_core_get(fd, p);
    } else if (strncmp(line, "user create ", 12) == 0) {
        char uname[64] = {0}, upass[128] = {0};
        sscanf(line + 12, "%63s %127s", uname, upass);
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            char p[256]; snprintf(p, sizeof(p), "/users/%s", uname);
            portal_msg_set_path(m, p);
            portal_msg_set_method(m, PORTAL_METHOD_SET);
            portal_msg_add_header(m, "password", upass);
            g_core->send(g_core, m, r);
            send_str(fd, (r->status <= 201) ? "User created\n" : "Failed\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "user passwd ", 12) == 0) {
        char uname[64] = {0}, upass[128] = {0};
        sscanf(line + 12, "%63s %127s", uname, upass);
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            char p[256]; snprintf(p, sizeof(p), "/users/%s/password", uname);
            portal_msg_set_path(m, p);
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "password", upass);
            g_core->send(g_core, m, r);
            send_str(fd, (r->body) ? r->body : "Failed\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strcmp(line, "group list") == 0) {
        cmd_core_get(fd, "/groups");
    } else if (strncmp(line, "group info ", 11) == 0) {
        char p[256]; snprintf(p, sizeof(p), "/groups/%s", line + 11);
        cmd_core_get(fd, p);
    } else if (strncmp(line, "group create ", 13) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            char p[256]; snprintf(p, sizeof(p), "/groups/%s", line + 13);
            portal_msg_set_path(m, p);
            portal_msg_set_method(m, PORTAL_METHOD_SET);
            g_core->send(g_core, m, r);
            send_str(fd, (r->body) ? r->body : "Failed\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "group adduser ", 14) == 0) {
        char gname[64] = {0}, uname[64] = {0};
        sscanf(line + 14, "%63s %63s", gname, uname);
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            char p[256]; snprintf(p, sizeof(p), "/groups/%s/add", gname);
            portal_msg_set_path(m, p);
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "user", uname);
            g_core->send(g_core, m, r);
            send_str(fd, (r->body) ? r->body : "Failed\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "group deluser ", 14) == 0) {
        char gname[64] = {0}, uname[64] = {0};
        sscanf(line + 14, "%63s %63s", gname, uname);
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            char p[256]; snprintf(p, sizeof(p), "/groups/%s/remove", gname);
            portal_msg_set_path(m, p);
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "user", uname);
            g_core->send(g_core, m, r);
            send_str(fd, (r->body) ? r->body : "Failed\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    /* --- Cache commands --- */
    } else if (strncmp(line, "cache set ", 10) == 0) {
        /* cache set key value [ttl] */
        char k[128] = {0}, v[1024] = {0};
        int ttl = 0;
        if (sscanf(line + 10, "%127s %1023[^\n]", k, v) >= 2) {
            /* Check for ttl at end: "value 60" */
            char *last_space = strrchr(v, ' ');
            if (last_space && atoi(last_space + 1) > 0) {
                ttl = atoi(last_space + 1);
                *last_space = '\0';
            }
            portal_msg_t *m = portal_msg_alloc();
            portal_resp_t *r = portal_resp_alloc();
            if (m && r) {
                portal_msg_set_path(m, "/cache/functions/set");
                portal_msg_set_method(m, PORTAL_METHOD_CALL);
                portal_msg_add_header(m, "key", k);
                portal_msg_add_header(m, "value", v);
                if (ttl > 0) {
                    char ts[16]; snprintf(ts, sizeof(ts), "%d", ttl);
                    portal_msg_add_header(m, "ttl", ts);
                }
                g_core->send(g_core, m, r);
                send_str(fd, r->body ? r->body : "Error\n");
                portal_msg_free(m); portal_resp_free(r);
            }
        } else {
            send_str(fd, "Usage: cache set <key> <value> [ttl]\n");
        }
    } else if (strncmp(line, "cache get ", 10) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/cache/functions/get");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "key", line + 10);
            g_core->send(g_core, m, r);
            if (r->status == PORTAL_OK && r->body) {
                write(fd, r->body, r->body_len);
                write(fd, "\n", 1);
            } else {
                send_str(fd, "(not found)\n");
            }
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "cache del ", 10) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/cache/functions/del");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "key", line + 10);
            g_core->send(g_core, m, r);
            send_str(fd, r->body ? r->body : "Deleted\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strcmp(line, "cache keys") == 0) {
        cmd_core_get(fd, "/cache/resources/keys");
    } else if (strcmp(line, "cache status") == 0) {
        cmd_core_get(fd, "/cache/resources/status");
    } else if (strcmp(line, "cache flush") == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/cache/functions/flush");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            g_core->send(g_core, m, r);
            send_str(fd, r->body ? r->body : "Flushed\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    /* --- Cron commands --- */
    } else if (strcmp(line, "cron status") == 0) {
        cmd_core_get(fd, "/cron/resources/status");
    } else if (strcmp(line, "cron jobs") == 0 || strcmp(line, "cron list") == 0) {
        cmd_core_get(fd, "/cron/resources/jobs");
    } else if (strncmp(line, "cron add ", 9) == 0) {
        /* cron add <name> <interval> <path> */
        char name[64] = {0}, path[PORTAL_MAX_PATH_LEN] = {0};
        int interval = 0;
        if (sscanf(line + 9, "%63s %d %1023s", name, &interval, path) == 3) {
            portal_msg_t *m = portal_msg_alloc();
            portal_resp_t *r = portal_resp_alloc();
            if (m && r) {
                portal_msg_set_path(m, "/cron/functions/add");
                portal_msg_set_method(m, PORTAL_METHOD_CALL);
                portal_msg_add_header(m, "name", name);
                char is[16]; snprintf(is, sizeof(is), "%d", interval);
                portal_msg_add_header(m, "interval", is);
                portal_msg_add_header(m, "path", path);
                g_core->send(g_core, m, r);
                send_str(fd, r->body ? r->body : "Error\n");
                portal_msg_free(m); portal_resp_free(r);
            }
        } else {
            send_str(fd, "Usage: cron add <name> <interval_secs> <path>\n");
        }
    } else if (strncmp(line, "cron remove ", 12) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/cron/functions/remove");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "name", line + 12);
            g_core->send(g_core, m, r);
            send_str(fd, r->body ? r->body : "Removed\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "cron trigger ", 13) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/cron/functions/trigger");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "name", line + 13);
            g_core->send(g_core, m, r);
            send_str(fd, r->body ? r->body : "Triggered\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    /* --- Health commands --- */
    } else if (strcmp(line, "health") == 0 || strcmp(line, "health status") == 0) {
        cmd_core_get(fd, "/health/resources/status");
    } else if (strcmp(line, "health live") == 0) {
        cmd_core_get(fd, "/health/resources/live");
    } else if (strcmp(line, "health ready") == 0) {
        cmd_core_get(fd, "/health/resources/ready");
    } else if (strcmp(line, "uptime") == 0) {
        cmd_core_get(fd, "/health/resources/uptime");
    /* --- JSON commands --- */
    } else if (strncmp(line, "json ", 5) == 0) {
        /* json <path> → query path and return as JSON */
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/json/functions/wrap");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "path", line + 5);
            g_core->send(g_core, m, r);
            if (r->body) {
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
                write(fd, "\n", 1);
            } else {
                send_str(fd, "(unavailable)\n");
            }
            portal_msg_free(m); portal_resp_free(r);
        }
    /* --- HTTP client commands --- */
    } else if (strncmp(line, "curl ", 5) == 0) {
        /* curl <url> → HTTP GET via mod_http_client */
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/httpc/functions/get");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "url", line + 5);
            g_core->send(g_core, m, r);
            if (r->body) {
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
                write(fd, "\n", 1);
            } else {
                send_str(fd, "(request failed)\n");
            }
            portal_msg_free(m); portal_resp_free(r);
        }
    /* --- KV commands --- */
    } else if (strncmp(line, "kv set ", 7) == 0) {
        char k[256] = {0}, v[4096] = {0};
        if (sscanf(line + 7, "%255s %4095[^\n]", k, v) >= 2) {
            portal_msg_t *m = portal_msg_alloc();
            portal_resp_t *r = portal_resp_alloc();
            if (m && r) {
                portal_msg_set_path(m, "/kv/functions/set");
                portal_msg_set_method(m, PORTAL_METHOD_CALL);
                portal_msg_add_header(m, "key", k);
                portal_msg_add_header(m, "value", v);
                g_core->send(g_core, m, r);
                send_str(fd, r->body ? r->body : "Error\n");
                portal_msg_free(m); portal_resp_free(r);
            }
        } else {
            send_str(fd, "Usage: kv set <key> <value>\n");
        }
    } else if (strncmp(line, "kv get ", 7) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/kv/functions/get");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "key", line + 7);
            g_core->send(g_core, m, r);
            if (r->status == PORTAL_OK && r->body) {
                write(fd, r->body, r->body_len);
                write(fd, "\n", 1);
            } else {
                send_str(fd, "(not found)\n");
            }
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "kv del ", 7) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/kv/functions/del");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "key", line + 7);
            g_core->send(g_core, m, r);
            send_str(fd, r->body ? r->body : "Deleted\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strcmp(line, "kv keys") == 0) {
        cmd_core_get(fd, "/kv/resources/keys");
    /* --- Firewall commands --- */
    } else if (strncmp(line, "firewall deny ", 14) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/firewall/functions/deny");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "source", line + 14);
            g_core->send(g_core, m, r);
            send_str(fd, r->body ? r->body : "Blocked\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "firewall allow ", 15) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/firewall/functions/allow");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "source", line + 15);
            g_core->send(g_core, m, r);
            send_str(fd, r->body ? r->body : "Allowed\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "firewall check ", 15) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/firewall/functions/check");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "source", line + 15);
            g_core->send(g_core, m, r);
            if (r->body) {
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
                write(fd, "\n", 1);
            } else {
                send_str(fd, "(unknown)\n");
            }
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strcmp(line, "firewall rules") == 0) {
        cmd_core_get(fd, "/firewall/resources/rules");
    /* --- Backup commands --- */
    } else if (strncmp(line, "backup create", 13) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/backup/functions/create");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            const char *name = line + 13;
            while (*name == ' ') name++;
            if (*name) portal_msg_add_header(m, "name", name);
            g_core->send(g_core, m, r);
            send_str(fd, r->body ? r->body : "Created\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strcmp(line, "backup list") == 0) {
        cmd_core_get(fd, "/backup/resources/list");
    /* --- DNS commands --- */
    } else if (strncmp(line, "dns resolve ", 12) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/dns/functions/resolve");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "host", line + 12);
            g_core->send(g_core, m, r);
            if (r->body) {
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
                write(fd, "\n", 1);
            } else {
                send_str(fd, "(resolve failed)\n");
            }
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "dns reverse ", 12) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/dns/functions/reverse");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "ip", line + 12);
            g_core->send(g_core, m, r);
            if (r->body) {
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
                write(fd, "\n", 1);
            } else {
                send_str(fd, "(reverse lookup failed)\n");
            }
            portal_msg_free(m); portal_resp_free(r);
        }
    /* --- Node commands (with shortcuts: ping, tracert) --- */
    } else if (strncmp(line, "ping ", 5) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/node/functions/ping");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "name", line + 5);
            g_core->send(g_core, m, r);
            if (r->body)
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
            else
                send_str(fd, "(ping failed)\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strcmp(line, "ping") == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/node/functions/ping");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "name", "all");
            g_core->send(g_core, m, r);
            if (r->body)
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
            else
                send_str(fd, "(no peers)\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "tracert ", 8) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/node/functions/trace");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "path", line + 8);
            g_core->send(g_core, m, r);
            if (r->body)
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
            else
                send_str(fd, "(trace failed)\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strcmp(line, "node") == 0 || strcmp(line, "node status") == 0) {
        cmd_core_get(fd, "/node/resources/status");
    } else if (strcmp(line, "node peers") == 0) {
        cmd_core_get(fd, "/node/resources/peers");
    } else if (strncmp(line, "node status ", 12) == 0) {
        const char *peer = line + 12;
        /* Show local peer info */
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            char path[PORTAL_MAX_PATH_LEN];
            snprintf(path, sizeof(path), "/node/resources/peer/%s", peer);
            portal_msg_set_path(m, path);
            portal_msg_set_method(m, PORTAL_METHOD_GET);
            g_core->send(g_core, m, r);
            if (r->body)
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
            else
                send_str(fd, "(peer not found)\n");
            portal_msg_free(m); portal_resp_free(r);
        }
        /* Also query remote node status for location/GPS */
        m = portal_msg_alloc();
        r = portal_resp_alloc();
        if (m && r) {
            char path[PORTAL_MAX_PATH_LEN];
            snprintf(path, sizeof(path), "/%s/node/resources/status", peer);
            portal_msg_set_path(m, path);
            portal_msg_set_method(m, PORTAL_METHOD_GET);
            g_core->send(g_core, m, r);
            if (r->body && r->body_len > 0) {
                /* Extract Location and GPS lines */
                const char *body = r->body;
                const char *loc = strstr(body, "Location:");
                const char *gps = strstr(body, "GPS:");
                if (loc) {
                    const char *end = strchr(loc, '\n');
                    if (end) write(fd, loc, (size_t)(end - loc + 1));
                }
                if (gps) {
                    const char *end = strchr(gps, '\n');
                    if (end) write(fd, gps, (size_t)(end - gps + 1));
                }
            }
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "node ping ", 10) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/node/functions/ping");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "name", line + 10);
            g_core->send(g_core, m, r);
            if (r->body)
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
            else
                send_str(fd, "(ping failed)\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strcmp(line, "node ping") == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/node/functions/ping");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "name", "all");
            g_core->send(g_core, m, r);
            if (r->body)
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
            else
                send_str(fd, "(no peers)\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "node trace ", 11) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/node/functions/trace");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "path", line + 11);
            g_core->send(g_core, m, r);
            if (r->body)
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
            else
                send_str(fd, "(trace failed)\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    /* --- Schedule commands --- */
    } else if (strcmp(line, "schedule list") == 0) {
        cmd_core_get(fd, "/scheduler/resources/tasks");
    } else if (strncmp(line, "schedule ", 9) == 0) {
        char name[64] = {0}, path[PORTAL_MAX_PATH_LEN] = {0};
        int delay = 0;
        if (sscanf(line + 9, "%63s %d %1023s", name, &delay, path) == 3) {
            portal_msg_t *m = portal_msg_alloc();
            portal_resp_t *r = portal_resp_alloc();
            if (m && r) {
                portal_msg_set_path(m, "/scheduler/functions/schedule");
                portal_msg_set_method(m, PORTAL_METHOD_CALL);
                portal_msg_add_header(m, "name", name);
                char ds[16]; snprintf(ds, sizeof(ds), "%d", delay);
                portal_msg_add_header(m, "delay", ds);
                portal_msg_add_header(m, "path", path);
                g_core->send(g_core, m, r);
                send_str(fd, r->body ? r->body : "Scheduled\n");
                portal_msg_free(m); portal_resp_free(r);
            }
        } else {
            send_str(fd, "Usage: schedule <name> <delay_secs> <path>\n");
        }
    /* --- Process commands --- */
    } else if (strncmp(line, "process exec ", 13) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/process/functions/exec");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "cmd", line + 13);
            g_core->send(g_core, m, r);
            if (r->body) {
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
                write(fd, "\n", 1);
            } else {
                send_str(fd, "(exec failed)\n");
            }
            portal_msg_free(m); portal_resp_free(r);
        }
    /* --- Validate commands --- */
    } else if (strncmp(line, "validate email ", 15) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/validator/functions/email");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "value", line + 15);
            g_core->send(g_core, m, r);
            if (r->body) {
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
                write(fd, "\n", 1);
            } else {
                send_str(fd, "(validation failed)\n");
            }
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "validate ip ", 12) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/validator/functions/ip");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "value", line + 12);
            g_core->send(g_core, m, r);
            if (r->body) {
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
                write(fd, "\n", 1);
            } else {
                send_str(fd, "(validation failed)\n");
            }
            portal_msg_free(m); portal_resp_free(r);
        }
    /* --- Sysinfo & Metrics --- */
    } else if (strcmp(line, "sysinfo") == 0) {
        cmd_core_get(fd, "/sysinfo/resources/all");
    } else if (strcmp(line, "metrics") == 0) {
        cmd_core_get(fd, "/metrics/resources/all");
    /* --- Compress commands --- */
    } else if (strncmp(line, "compress gzip ", 14) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/compress/functions/gzip");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "data", line + 14);
            g_core->send(g_core, m, r);
            if (r->body) {
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
                write(fd, "\n", 1);
            } else {
                send_str(fd, "(compress failed)\n");
            }
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "compress xz ", 12) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/compress/functions/xz");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "data", line + 12);
            g_core->send(g_core, m, r);
            if (r->body) {
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
                write(fd, "\n", 1);
            } else {
                send_str(fd, "(compress failed)\n");
            }
            portal_msg_free(m); portal_resp_free(r);
        }
    /* --- Config commands --- */
    } else if (strncmp(line, "config get ", 11) == 0) {
        char mod[64] = {0}, key[256] = {0};
        if (sscanf(line + 11, "%63s %255s", mod, key) == 2) {
            portal_msg_t *m = portal_msg_alloc();
            portal_resp_t *r = portal_resp_alloc();
            if (m && r) {
                portal_msg_set_path(m, "/core/config/get");
                portal_msg_set_method(m, PORTAL_METHOD_GET);
                portal_msg_add_header(m, "module", mod);
                portal_msg_add_header(m, "key", key);
                g_core->send(g_core, m, r);
                if (r->body) send_str(fd, r->body);
                else send_str(fd, "(not found)\n");
                portal_msg_free(m); portal_resp_free(r);
            }
        } else {
            send_str(fd, "Usage: config get <module> <key>\n");
        }
    } else if (strncmp(line, "config set ", 11) == 0) {
        char mod[64] = {0}, key[256] = {0}, val[4096] = {0};
        if (sscanf(line + 11, "%63s %255s %4095[^\n]", mod, key, val) >= 3) {
            portal_msg_t *m = portal_msg_alloc();
            portal_resp_t *r = portal_resp_alloc();
            if (m && r) {
                portal_msg_set_path(m, "/core/config/set");
                portal_msg_set_method(m, PORTAL_METHOD_CALL);
                portal_msg_add_header(m, "module", mod);
                portal_msg_add_header(m, "key", key);
                portal_msg_add_header(m, "value", val);
                g_core->send(g_core, m, r);
                send_str(fd, r->body ? r->body : "OK\n");
                portal_msg_free(m); portal_resp_free(r);
            }
        } else {
            send_str(fd, "Usage: config set <module> <key> <value>\n");
        }
    } else if (strncmp(line, "config list", 11) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/core/config/list");
            portal_msg_set_method(m, PORTAL_METHOD_GET);
            const char *mod = (strlen(line) > 12) ? line + 12 : NULL;
            if (mod) portal_msg_add_header(m, "module", mod);
            g_core->send(g_core, m, r);
            if (r->body) send_str(fd, r->body);
            else send_str(fd, "(empty)\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    /* --- IoT commands --- */
    } else if (strcmp(line, "iot devices") == 0) {
        cmd_core_get(fd, "/iot/resources/devices");
    } else if (strncmp(line, "iot status", 10) == 0) {
        if (strlen(line) > 11) {
            portal_msg_t *m = portal_msg_alloc();
            portal_resp_t *r = portal_resp_alloc();
            if (m && r) {
                portal_msg_set_path(m, "/iot/functions/status");
                portal_msg_set_method(m, PORTAL_METHOD_GET);
                portal_msg_add_header(m, "name", line + 11);
                g_core->send(g_core, m, r);
                if (r->body) send_str(fd, r->body);
                else send_str(fd, "(no response)\n");
                portal_msg_free(m); portal_resp_free(r);
            }
        } else {
            cmd_core_get(fd, "/iot/functions/status");
        }
    } else if (strncmp(line, "iot discover ", 13) == 0) {
        char subnet[48] = {0}, brand[32] = {0};
        sscanf(line + 13, "%47s %31s", subnet, brand);
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/iot/functions/discover");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "subnet", subnet);
            if (brand[0]) portal_msg_add_header(m, "brand", brand);
            g_core->send(g_core, m, r);
            if (r->body) send_str(fd, r->body);
            else send_str(fd, "(no response)\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "iot on ", 7) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/iot/functions/on");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "name", line + 7);
            g_core->send(g_core, m, r);
            send_str(fd, r->body ? r->body : "OK\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "iot off ", 8) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/iot/functions/off");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "name", line + 8);
            g_core->send(g_core, m, r);
            send_str(fd, r->body ? r->body : "OK\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "iot toggle ", 11) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/iot/functions/toggle");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "name", line + 11);
            g_core->send(g_core, m, r);
            send_str(fd, r->body ? r->body : "OK\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strncmp(line, "iot add ", 8) == 0) {
        char name[64] = {0}, ip[48] = {0}, drv[16] = {0}, brn[16] = {0};
        int parsed = sscanf(line + 8, "%63s %47s %15s %15s", name, ip, drv, brn);
        if (parsed >= 2) {
            portal_msg_t *m = portal_msg_alloc();
            portal_resp_t *r = portal_resp_alloc();
            if (m && r) {
                portal_msg_set_path(m, "/iot/functions/add");
                portal_msg_set_method(m, PORTAL_METHOD_CALL);
                portal_msg_add_header(m, "name", name);
                portal_msg_add_header(m, "ip", ip);
                if (drv[0]) portal_msg_add_header(m, "driver", drv);
                if (brn[0]) portal_msg_add_header(m, "brand", brn);
                g_core->send(g_core, m, r);
                send_str(fd, r->body ? r->body : "OK\n");
                portal_msg_free(m); portal_resp_free(r);
            }
        } else {
            send_str(fd, "Usage: iot add <name> <ip> [driver] [brand]\n");
        }
    } else if (strncmp(line, "iot remove ", 11) == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/iot/functions/remove");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            portal_msg_add_header(m, "name", line + 11);
            g_core->send(g_core, m, r);
            send_str(fd, r->body ? r->body : "OK\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strcmp(line, "iot refresh") == 0) {
        portal_msg_t *m = portal_msg_alloc();
        portal_resp_t *r = portal_resp_alloc();
        if (m && r) {
            portal_msg_set_path(m, "/iot/functions/refresh");
            portal_msg_set_method(m, PORTAL_METHOD_CALL);
            g_core->send(g_core, m, r);
            if (r->body)
                write(fd, r->body, r->body_len > 0 ? r->body_len : strlen(r->body));
            else
                send_str(fd, "(refresh failed)\n");
            portal_msg_free(m); portal_resp_free(r);
        }
    } else if (strcmp(line, "shell") == 0 || strncmp(line, "shell ", 6) == 0) {
        /* Enter PTY shell mode: "shell" = local, "shell <peer>" = remote */
        cli_client_t *sc = find_client(fd);
        if (sc) {
            if (strlen(line) > 6)
                snprintf(sc->shell_peer, sizeof(sc->shell_peer), "%s", line + 6);
            else
                sc->shell_peer[0] = '\0';

            /* Open a PTY session on the target */
            char spath[256];
            if (sc->shell_peer[0])
                snprintf(spath, sizeof(spath), "/%s/shell/functions/open", sc->shell_peer);
            else
                snprintf(spath, sizeof(spath), "/shell/functions/open");

            portal_msg_t *om = portal_msg_alloc();
            portal_resp_t *or_resp = portal_resp_alloc();
            if (om && or_resp) {
                portal_msg_set_path(om, spath);
                portal_msg_set_method(om, PORTAL_METHOD_CALL);
                portal_msg_add_header(om, "rows", "24");
                portal_msg_add_header(om, "cols", "80");
                cli_attach_auth(fd, om);
                g_core->send(g_core, om, or_resp);

                if (or_resp->status == PORTAL_OK && or_resp->body && or_resp->body_len > 0) {
                    /* Session ID in response body */
                    char sid[32];
                    snprintf(sid, sizeof(sid), "%.*s",
                             (int)(or_resp->body_len > 31 ? 31 : or_resp->body_len),
                             (char *)or_resp->body);
                    sid[strcspn(sid, "\r\n")] = '\0';
                    snprintf(sc->shell_session, sizeof(sc->shell_session), "%s", sid);
                    sc->shell_active = 1;

                    char banner[256];
                    const char *host = sc->shell_peer[0] ? sc->shell_peer : "local";
                    snprintf(banner, sizeof(banner),
                             "PTY session %s on %s (type 'exit' to return)\n", sid, host);
                    send_str(fd, banner);

                    /* Read initial shell output (prompt, motd, etc.) */
                    char rpath[256];
                    if (sc->shell_peer[0])
                        snprintf(rpath, sizeof(rpath), "/%s/shell/functions/read", sc->shell_peer);
                    else
                        snprintf(rpath, sizeof(rpath), "/shell/functions/read");

                    portal_msg_t *rm = portal_msg_alloc();
                    portal_resp_t *rr = portal_resp_alloc();
                    if (rm && rr) {
                        portal_msg_set_path(rm, rpath);
                        portal_msg_set_method(rm, PORTAL_METHOD_CALL);
                        portal_msg_add_header(rm, "session", sc->shell_session);
                        cli_attach_auth(fd, rm);
                        g_core->send(g_core, rm, rr);
                        if (rr->body && rr->body_len > 0)
                            write(fd, rr->body, rr->body_len);
                        portal_msg_free(rm); portal_resp_free(rr);
                    }
                } else {
                    char err[128];
                    snprintf(err, sizeof(err), "Failed to open shell: %s\n",
                             or_resp->body ? (char *)or_resp->body : "no response");
                    send_str(fd, err);
                }
                portal_msg_free(om); portal_resp_free(or_resp);
            }
        }
    } else if (strcmp(line, "quit") == 0 || strcmp(line, "exit") == 0) {
        send_str(fd, "Goodbye.\n");
        remove_client(fd);
        return;
    } else {
        /* Try treating the unknown command as a path: get /<line> */
        if (line[0] != '/' && strchr(line, ' ') == NULL && strlen(line) > 1) {
            /* Could be a module name — suggest help */
            char buf[256];
            snprintf(buf, sizeof(buf),
                     "Unknown command: %s\n"
                     "Try: get /%s  ·  help %s  ·  ls /%s\n", line, line, line, line);
            send_str(fd, buf);
        } else {
            char buf[256];
            snprintf(buf, sizeof(buf),
                     "Unknown command: %s\nType 'help' for commands, Tab to autocomplete.\n", line);
            send_str(fd, buf);
        }
    }

    send_prompt(fd);
}

/* --- Event callbacks --- */

/* --- Line editor helpers --- */

static void editor_clear_line(int fd, cli_line_editor_t *ed)
{
    /* Move cursor to start, clear line */
    char clear[16];
    int n = snprintf(clear, sizeof(clear), "\r\033[K");
    write(fd, clear, (size_t)n);
    (void)ed;
}

static void editor_redraw(int fd, cli_client_t *c)
{
    /* Clear line, redraw prompt + current text */
    editor_clear_line(fd, &c->editor);
    send_prompt(fd);
    if (c->editor.len > 0)
        write(fd, c->editor.line, (size_t)c->editor.len);
    /* Move cursor to correct position */
    if (c->editor.pos < c->editor.len) {
        char move[16];
        int back = c->editor.len - c->editor.pos;
        int n = snprintf(move, sizeof(move), "\033[%dD", back);
        write(fd, move, (size_t)n);
    }
}

static void editor_history_add(cli_line_editor_t *ed, const char *line)
{
    if (!line[0]) return;  /* skip empty */
    /* Don't duplicate last entry */
    if (ed->hist_count > 0 &&
        strcmp(ed->history[(ed->hist_count - 1) % CLI_MAX_HISTORY], line) == 0)
        return;
    snprintf(ed->history[ed->hist_count % CLI_MAX_HISTORY],
             CLI_MAX_LINE, "%s", line);
    ed->hist_count++;
}

static void editor_history_up(int fd, cli_client_t *c)
{
    cli_line_editor_t *ed = &c->editor;
    if (ed->hist_count == 0) return;

    if (ed->hist_pos < 0)
        ed->hist_pos = ed->hist_count - 1;
    else if (ed->hist_pos > 0)
        ed->hist_pos--;
    else
        return;  /* at oldest */

    int idx = ed->hist_pos % CLI_MAX_HISTORY;
    snprintf(ed->line, CLI_MAX_LINE, "%s", ed->history[idx]);
    ed->len = (int)strlen(ed->line);
    ed->pos = ed->len;
    editor_redraw(fd, c);
}

static void editor_history_down(int fd, cli_client_t *c)
{
    cli_line_editor_t *ed = &c->editor;
    if (ed->hist_pos < 0) return;

    ed->hist_pos++;
    if (ed->hist_pos >= ed->hist_count) {
        /* Back to empty new line */
        ed->hist_pos = -1;
        ed->line[0] = '\0';
        ed->len = 0;
        ed->pos = 0;
    } else {
        int idx = ed->hist_pos % CLI_MAX_HISTORY;
        snprintf(ed->line, CLI_MAX_LINE, "%s", ed->history[idx]);
        ed->len = (int)strlen(ed->line);
        ed->pos = ed->len;
    }
    editor_redraw(fd, c);
}

static void editor_insert_char(int fd, cli_client_t *c, char ch)
{
    cli_line_editor_t *ed = &c->editor;
    if (ed->len >= CLI_MAX_LINE - 1) return;

    /* Insert at cursor position */
    if (ed->pos < ed->len)
        memmove(ed->line + ed->pos + 1, ed->line + ed->pos,
                (size_t)(ed->len - ed->pos));
    ed->line[ed->pos] = ch;
    ed->pos++;
    ed->len++;
    ed->line[ed->len] = '\0';

    /* Simple: redraw from cursor */
    write(fd, ed->line + ed->pos - 1, (size_t)(ed->len - ed->pos + 1));
    if (ed->pos < ed->len) {
        char move[16];
        int back = ed->len - ed->pos;
        int n = snprintf(move, sizeof(move), "\033[%dD", back);
        write(fd, move, (size_t)n);
    }
}

static void editor_backspace(int fd, cli_client_t *c)
{
    cli_line_editor_t *ed = &c->editor;
    if (ed->pos <= 0) return;

    memmove(ed->line + ed->pos - 1, ed->line + ed->pos,
            (size_t)(ed->len - ed->pos));
    ed->pos--;
    ed->len--;
    ed->line[ed->len] = '\0';
    editor_redraw(fd, c);
}

static void editor_left(int fd, cli_client_t *c)
{
    if (c->editor.pos > 0) {
        c->editor.pos--;
        write(fd, "\033[D", 3);
    }
}

static void editor_right(int fd, cli_client_t *c)
{
    if (c->editor.pos < c->editor.len) {
        c->editor.pos++;
        write(fd, "\033[C", 3);
    }
}

/* --- Tab completion --- */

#define TAB_MAX_MATCHES 64

static void editor_tab_complete(int fd, cli_client_t *c)
{
    cli_line_editor_t *ed = &c->editor;

    /* Find the word being completed (last space-separated token) */
    char *line = ed->line;
    line[ed->len] = '\0';

    /* Find the path token to complete */
    char *last_space = strrchr(line, ' ');
    char *word = last_space ? last_space + 1 : line;

    /* Context-aware completion for commands that take device/peer names */
    if (word[0] != '/' && last_space) {
        char cmd_buf[CLI_MAX_LINE];
        size_t cmd_len = (size_t)(last_space - line);
        memcpy(cmd_buf, line, cmd_len);
        cmd_buf[cmd_len] = '\0';

        /* iot on/off/status/toggle <device> — complete from device list */
        if (strcmp(cmd_buf, "iot on") == 0 || strcmp(cmd_buf, "iot off") == 0 ||
            strcmp(cmd_buf, "iot status") == 0 || strcmp(cmd_buf, "iot toggle") == 0) {
            portal_msg_t *dm = portal_msg_alloc();
            portal_resp_t *dr = portal_resp_alloc();
            if (dm && dr) {
                portal_msg_set_path(dm, "/iot/resources/devices");
                portal_msg_set_method(dm, PORTAL_METHOD_GET);
                g_core->send(g_core, dm, dr);
                if (dr->body) {
                    char matches[TAB_MAX_MATCHES][128];
                    int match_count = 0;
                    size_t wlen = strlen(word);
                    char *bl = dr->body;
                    while (*bl && match_count < TAB_MAX_MATCHES) {
                        char *nl = strchr(bl, '\n');
                        if (nl) *nl = '\0';
                        char *s = bl; while (*s == ' ') s++;
                        /* Extract first column (device name) */
                        if (*s && *s != '-' && *s != 'N' && *s != '(') { /* skip header/empty */
                            char dname[64]; int di = 0;
                            while (s[di] && s[di] != ' ' && di < 63) di++;
                            memcpy(dname, s, (size_t)di); dname[di] = '\0';
                            if (wlen == 0 || strncmp(dname, word, wlen) == 0)
                                snprintf(matches[match_count++], 128, "%s", dname);
                        }
                        if (!nl) break;
                        *nl = '\n'; bl = nl + 1;
                    }
                    if (match_count == 1) {
                        const char *rest = matches[0] + wlen;
                        for (size_t ri = 0; rest[ri] && ed->len < CLI_MAX_LINE - 2; ri++)
                            editor_insert_char(fd, c, rest[ri]);
                    } else if (match_count > 1) {
                        size_t common = strlen(matches[0]);
                        for (int mi = 1; mi < match_count; mi++) {
                            size_t j = 0;
                            while (j < common && matches[0][j] == matches[mi][j]) j++;
                            common = j;
                        }
                        if (common > wlen)
                            for (size_t ci = wlen; ci < common && ed->len < CLI_MAX_LINE - 2; ci++)
                                editor_insert_char(fd, c, matches[0][ci]);
                        if (ed->tab_count >= 1 || common <= wlen) {
                            write(fd, "\r\n", 2);
                            for (int mi = 0; mi < match_count; mi++) {
                                char mb[140];
                                int mn = snprintf(mb, sizeof(mb), "  %s\n", matches[mi]);
                                write(fd, mb, (size_t)mn);
                            }
                            editor_redraw(fd, c);
                        }
                    }
                }
                portal_msg_free(dm); portal_resp_free(dr);
                return;
            }
        }

        /* ping <peer> — complete from peer list */
        if (strcmp(cmd_buf, "ping") == 0 || strcmp(cmd_buf, "node status") == 0 ||
            strcmp(cmd_buf, "node ping") == 0) {
            portal_msg_t *pm = portal_msg_alloc();
            portal_resp_t *pr = portal_resp_alloc();
            if (pm && pr) {
                portal_msg_set_path(pm, "/node/resources/peers");
                portal_msg_set_method(pm, PORTAL_METHOD_GET);
                g_core->send(g_core, pm, pr);
                if (pr->body) {
                    char matches[TAB_MAX_MATCHES][128];
                    int match_count = 0;
                    size_t wlen = strlen(word);
                    /* Add "all" option */
                    if (wlen == 0 || strncmp("all", word, wlen) == 0)
                        snprintf(matches[match_count++], 128, "all");
                    char *bl = pr->body;
                    while (*bl && match_count < TAB_MAX_MATCHES) {
                        char *nl = strchr(bl, '\n');
                        if (nl) *nl = '\0';
                        char *s = bl; while (*s == ' ') s++;
                        if (*s && *s != 'C' && *s != '(') { /* skip header */
                            char pname[64]; int pi = 0;
                            while (s[pi] && s[pi] != ' ' && pi < 63) pi++;
                            memcpy(pname, s, (size_t)pi); pname[pi] = '\0';
                            if (wlen == 0 || strncmp(pname, word, wlen) == 0)
                                snprintf(matches[match_count++], 128, "%s", pname);
                        }
                        if (!nl) break;
                        *nl = '\n'; bl = nl + 1;
                    }
                    if (match_count == 1) {
                        const char *rest = matches[0] + wlen;
                        for (size_t ri = 0; rest[ri] && ed->len < CLI_MAX_LINE - 2; ri++)
                            editor_insert_char(fd, c, rest[ri]);
                    } else if (match_count > 1) {
                        size_t common = strlen(matches[0]);
                        for (int mi = 1; mi < match_count; mi++) {
                            size_t j = 0;
                            while (j < common && matches[0][j] == matches[mi][j]) j++;
                            common = j;
                        }
                        if (common > wlen)
                            for (size_t ci = wlen; ci < common && ed->len < CLI_MAX_LINE - 2; ci++)
                                editor_insert_char(fd, c, matches[0][ci]);
                        if (ed->tab_count >= 1 || common <= wlen) {
                            write(fd, "\r\n", 2);
                            for (int mi = 0; mi < match_count; mi++) {
                                char mb[140];
                                int mn = snprintf(mb, sizeof(mb), "  %s\n", matches[mi]);
                                write(fd, mb, (size_t)mn);
                            }
                            editor_redraw(fd, c);
                        }
                    }
                }
                portal_msg_free(pm); portal_resp_free(pr);
                return;
            }
        }
    }

    /* If word doesn't start with /, treat as command or subcommand */
    if (word[0] != '/') {

        /* Subcommand completion: first word is known command, complete second word */
        if (last_space) {
            char first[64];
            size_t flen = (size_t)(last_space - line);
            if (flen > 63) flen = 63;
            memcpy(first, line, flen); first[flen] = '\0';

            /* Subcommand tables */
            static const struct { const char *cmd; const char *subs[16]; } subcmds[] = {
                {"node",     {"peers","status","ping","trace","location","gps","geolocate",NULL}},
                {"iot",      {"devices","status","on","off","toggle","refresh","discover","add","remove",NULL}},
                {"module",   {"list","load","unload","reload",NULL}},
                {"cache",    {"get","set","del","keys","status","flush",NULL}},
                {"kv",       {"get","set","del","keys",NULL}},
                {"cron",     {"add","remove","trigger","jobs","status",NULL}},
                {"config",   {"get","set","list",NULL}},
                {"firewall", {"deny","allow","check","rules",NULL}},
                {"backup",   {"create","list","restore","delete",NULL}},
                {"user",     {"list","info","create","passwd",NULL}},
                {"group",    {"list","info","create","adduser","deluser",NULL}},
                {"dns",      {"resolve","reverse",NULL}},
                {"schedule", {"list",NULL}},
                {"validate", {"email","ip","url","hostname",NULL}},
                {"compress", {"gzip","xz",NULL}},
                {"key",      {"rotate",NULL}},
                {NULL,       {NULL}}
            };

            for (int si = 0; subcmds[si].cmd; si++) {
                if (strcmp(first, subcmds[si].cmd) != 0) continue;

                char matches[TAB_MAX_MATCHES][128];
                int match_count = 0;
                size_t wlen = strlen(word);
                for (int j = 0; subcmds[si].subs[j]; j++) {
                    if (strncmp(subcmds[si].subs[j], word, wlen) == 0 &&
                        match_count < TAB_MAX_MATCHES)
                        snprintf(matches[match_count++], 128, "%s", subcmds[si].subs[j]);
                }

                if (match_count == 1) {
                    const char *rest = matches[0] + wlen;
                    size_t rlen = strlen(rest);
                    for (size_t ri = 0; ri < rlen && ed->len < CLI_MAX_LINE - 2; ri++)
                        editor_insert_char(fd, c, rest[ri]);
                    editor_insert_char(fd, c, ' ');
                } else if (match_count > 1) {
                    size_t common = strlen(matches[0]);
                    for (int mi = 1; mi < match_count; mi++) {
                        size_t j = 0;
                        while (j < common && matches[0][j] == matches[mi][j]) j++;
                        common = j;
                    }
                    if (common > wlen)
                        for (size_t ci = wlen; ci < common && ed->len < CLI_MAX_LINE - 2; ci++)
                            editor_insert_char(fd, c, matches[0][ci]);
                    if (ed->tab_count >= 1 || common <= wlen) {
                        write(fd, "\r\n", 2);
                        for (int mi = 0; mi < match_count; mi++) {
                            char mb[140];
                            int mn = snprintf(mb, sizeof(mb), "  %s\n", matches[mi]);
                            write(fd, mb, (size_t)mn);
                        }
                        editor_redraw(fd, c);
                    }
                }
                return;
            }
            /* Not a known subcommand context — fall through to command completion */
        }

        /* First word: command completion */
        static const char *commands[] = {
            "help", "status", "ls", "cd", "pwd", "get", "login", "logout",
            "whoami", "passwd", "key", "events", "subscribe", "unsubscribe",
            "storage", "module", "user", "group", "kv", "firewall", "backup",
            "dns", "schedule", "process", "validate", "sysinfo", "metrics",
            "compress", "quit", "exit", "iot", "node", "ping", "tracert",
            "cache", "cron", "config", "health", "json", "curl", "locks",
            "lock", "unlock", "verbose", "debug", "top", NULL
        };
        char matches[TAB_MAX_MATCHES][128];
        int match_count = 0;
        size_t wlen = strlen(word);

        if (wlen == 0) return;

        for (int i = 0; commands[i]; i++) {
            if (strncmp(commands[i], word, wlen) == 0 && match_count < TAB_MAX_MATCHES)
                snprintf(matches[match_count++], 128, "%s", commands[i]);
        }

        if (match_count == 1) {
            /* Single match — complete it */
            const char *rest = matches[0] + wlen;
            size_t rlen = strlen(rest);
            for (size_t i = 0; i < rlen && ed->len < CLI_MAX_LINE - 2; i++)
                editor_insert_char(fd, c, rest[i]);
            editor_insert_char(fd, c, ' ');
        } else if (match_count > 1) {
            /* Find common prefix */
            size_t common = strlen(matches[0]);
            for (int i = 1; i < match_count; i++) {
                size_t j = 0;
                while (j < common && matches[0][j] == matches[i][j]) j++;
                common = j;
            }
            if (common > wlen) {
                for (size_t i = wlen; i < common && ed->len < CLI_MAX_LINE - 2; i++)
                    editor_insert_char(fd, c, matches[0][i]);
            }
            if (ed->tab_count >= 1 || common <= wlen) {
                /* Show all options */
                write(fd, "\r\n", 2);
                for (int i = 0; i < match_count; i++) {
                    char buf[140];
                    int n = snprintf(buf, sizeof(buf), "  %s\n", matches[i]);
                    write(fd, buf, (size_t)n);
                }
                editor_redraw(fd, c);
            }
        }
        return;
    }

    /* Path completion: find the parent and list children */
    /* e.g., "/hello/res" → parent="/hello", partial="res" */
    char parent[PORTAL_MAX_PATH_LEN];
    char partial[128] = "";

    char *last_slash = strrchr(word, '/');
    if (last_slash && last_slash != word) {
        size_t plen = (size_t)(last_slash - word);
        memcpy(parent, word, plen);
        parent[plen] = '\0';
        snprintf(partial, sizeof(partial), "%s", last_slash + 1);
    } else if (last_slash == word && strlen(word) > 1) {
        snprintf(parent, sizeof(parent), "/");
        snprintf(partial, sizeof(partial), "%s", word + 1);
    } else {
        snprintf(parent, sizeof(parent), "%s", c->cwd);
        snprintf(partial, sizeof(partial), "%s", word + 1);
    }

    /* Query ls for children at parent */
    portal_msg_t *msg = portal_msg_alloc();
    portal_resp_t *resp = portal_resp_alloc();
    if (!msg || !resp) return;

    /* Check if remote path — try to route through federation */
    if (parent[0] == '/' && strlen(parent) > 1) {
        const char *fseg = parent + 1;
        const char *sl = strchr(fseg, '/');

        char node[PORTAL_MAX_MODULE_NAME];
        const char *remote_prefix = "/";

        if (sl) {
            /* /devtest/hello → node=devtest, prefix=/hello */
            size_t nlen = (size_t)(sl - fseg);
            if (nlen < sizeof(node)) {
                memcpy(node, fseg, nlen);
                node[nlen] = '\0';
                remote_prefix = sl;
            } else {
                goto local_ls;
            }
        } else {
            /* /devtest → node=devtest, prefix=/ */
            snprintf(node, sizeof(node), "%.63s", fseg);
            remote_prefix = "/";
        }

        /* Try remote ls */
        char rpath[PORTAL_MAX_PATH_LEN];
        snprintf(rpath, sizeof(rpath), "/%s/core/ls", node);
        portal_msg_set_path(msg, rpath);
        portal_msg_set_method(msg, PORTAL_METHOD_GET);
        portal_msg_add_header(msg, "prefix", remote_prefix);
        int rc = g_core->send(g_core, msg, resp);
        if (rc == 0 && resp->body && resp->body_len > 1) {
            goto parse_results;
        }
        /* Remote failed — fall through to local */
        portal_msg_free(msg); portal_resp_free(resp);
        msg = portal_msg_alloc(); resp = portal_resp_alloc();
        if (!msg || !resp) return;
    }

local_ls:
    portal_msg_set_path(msg, "/core/ls");
    portal_msg_set_method(msg, PORTAL_METHOD_GET);
    portal_msg_add_header(msg, "prefix", parent);
    g_core->send(g_core, msg, resp);

parse_results:
    if (!resp->body) {
        portal_msg_free(msg); portal_resp_free(resp);
        return;
    }

    /* Parse response: extract child names, filter by partial */
    char matches[TAB_MAX_MATCHES][128];
    int is_dir[TAB_MAX_MATCHES];
    int match_count = 0;
    size_t partial_len = strlen(partial);

    char *body = resp->body;
    char *bline = body;
    while (*bline && match_count < TAB_MAX_MATCHES) {
        char *nl = strchr(bline, '\n');
        if (nl) *nl = '\0';

        /* Parse "  name    [module]" or "  name/" */
        char *s = bline;
        while (*s == ' ') s++;
        if (*s && *s != '(') {
            char name[128];
            int n = 0;
            while (s[n] && s[n] != ' ' && s[n] != '/' && s[n] != '[' && n < 127)
                n++;
            memcpy(name, s, (size_t)n);
            name[n] = '\0';

            int dir = (s[n] == '/');

            /* Filter by partial */
            if (partial_len == 0 || strncmp(name, partial, partial_len) == 0) {
                snprintf(matches[match_count], 128, "%s", name);
                is_dir[match_count] = dir;
                match_count++;
            }
        }

        if (!nl) break;
        *nl = '\n';
        bline = nl + 1;
    }

    portal_msg_free(msg);
    portal_resp_free(resp);

    if (match_count == 0) return;

    if (match_count == 1) {
        /* Single match — complete it */
        const char *rest = matches[0] + partial_len;
        size_t rlen = strlen(rest);
        for (size_t i = 0; i < rlen && ed->len < CLI_MAX_LINE - 2; i++)
            editor_insert_char(fd, c, rest[i]);
        /* Add / for directories so user can keep navigating */
        if (is_dir[0])
            editor_insert_char(fd, c, '/');
    } else {
        /* Find common prefix among all matches */
        size_t common = strlen(matches[0]);
        for (int i = 1; i < match_count; i++) {
            size_t j = 0;
            while (j < common && matches[0][j] == matches[i][j]) j++;
            common = j;
        }
        /* Complete common prefix if longer than partial */
        if (common > partial_len) {
            for (size_t i = partial_len; i < common && ed->len < CLI_MAX_LINE - 2; i++)
                editor_insert_char(fd, c, matches[0][i]);
        }

        if (ed->tab_count >= 1) {
            /* Double tab — show all options */
            write(fd, "\r\n", 2);
            for (int i = 0; i < match_count; i++) {
                char buf[140];
                int n = snprintf(buf, sizeof(buf), "  %s%s\n",
                                  matches[i], is_dir[i] ? "/" : "");
                write(fd, buf, (size_t)n);
            }
            editor_redraw(fd, c);
        }
    }
}

/* Process one byte from client through the line editor */
static void editor_feed(int fd, cli_client_t *c, unsigned char ch)
{
    cli_line_editor_t *ed = &c->editor;

    /* Interactive `top` intercepts all keys while active */
    if (c->top_active) {
        switch (ch) {
        case 'q': case 'Q':
        case 3:   /* Ctrl-C */
        case 27:  /* ESC */
            cmd_top_exit(c);
            return;
        default:
            return;  /* swallow anything else */
        }
    }

    /* Escape sequence state machine */
    if (ed->esc_state == 1) {
        if (ch == '[') { ed->esc_state = 2; return; }
        ed->esc_state = 0;
        return;
    }
    if (ed->esc_state == 2) {
        ed->esc_state = 0;
        switch (ch) {
        case 'A': editor_history_up(fd, c); return;    /* Up */
        case 'B': editor_history_down(fd, c); return;  /* Down */
        case 'C': editor_right(fd, c); return;         /* Right */
        case 'D': editor_left(fd, c); return;          /* Left */
        case 'H': ed->pos = 0; editor_redraw(fd, c); return;       /* Home */
        case 'F': ed->pos = ed->len; editor_redraw(fd, c); return; /* End */
        }
        return;
    }

    switch (ch) {
    case 27:  /* ESC */
        ed->esc_state = 1;
        return;
    case '\t':  /* Tab = autocomplete */
        ed->tab_count++;
        editor_tab_complete(fd, c);
        return;
    case '\r':
    case '\n':
        /* Submit line */
        ed->line[ed->len] = '\0';
        write(fd, "\r\n", 2);
        editor_history_add(ed, ed->line);
        handle_command(fd, ed->line);
        /* Reset editor for next line */
        ed->line[0] = '\0';
        ed->pos = 0;
        ed->len = 0;
        ed->hist_pos = -1;
        return;
    case 127:   /* DEL */
    case 8:     /* Backspace */
        editor_backspace(fd, c);
        return;
    case 1:     /* Ctrl+A = Home */
        ed->pos = 0;
        editor_redraw(fd, c);
        return;
    case 5:     /* Ctrl+E = End */
        ed->pos = ed->len;
        editor_redraw(fd, c);
        return;
    case 21:    /* Ctrl+U = clear line */
        ed->line[0] = '\0';
        ed->pos = 0;
        ed->len = 0;
        editor_redraw(fd, c);
        return;
    case 12:    /* Ctrl+L = clear screen */
        write(fd, "\033[2J\033[H", 7);
        editor_redraw(fd, c);
        return;
    }

    /* Reset tab count on any non-tab key */
    ed->tab_count = 0;

    /* Regular printable character */
    if (ch >= 32 && ch < 127)
        editor_insert_char(fd, c, (char)ch);
}

static void on_client_data(int fd, uint32_t events, void *userdata)
{
    (void)userdata;

    if (events & EV_ERROR) {
        remove_client(fd);
        return;
    }

    cli_client_t *c = find_client(fd);
    if (!c) { remove_client(fd); return; }

    unsigned char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n <= 0) {
        remove_client(fd);
        return;
    }

    /* Feed each byte through the line editor */
    for (ssize_t i = 0; i < n; i++)
        editor_feed(fd, c, buf[i]);
}

static void on_new_connection(int fd, uint32_t events, void *userdata)
{
    (void)events;
    (void)userdata;

    int client_fd = accept(fd, NULL, NULL);
    if (client_fd < 0) return;

    if (g_client_count >= CLI_MAX_CLIENTS) {
        send_str(client_fd, "Too many connections\n");
        close(client_fd);
        return;
    }

    /* Find a free slot */
    cli_client_t *c = NULL;
    for (int i = 0; i < CLI_MAX_CLIENTS; i++) {
        if (!g_clients[i].active) {
            c = &g_clients[i];
            break;
        }
    }
    if (!c) {
        send_str(client_fd, "Too many connections\n");
        close(client_fd);
        return;
    }

    c->fd = client_fd;
    snprintf(c->cwd, sizeof(c->cwd), "/");
    c->active = 1;
    c->top_active = 0;
    c->top_sort = 'c';
    c->top_threads = 0;
    g_client_count++;

    g_core->fd_add(g_core, client_fd, EV_READ, on_client_data, NULL);

    send_str(client_fd, "Portal v" PORTAL_VERSION_STR " CLI\n");
    send_str(client_fd, "Type 'help' for available commands.\n");
    send_prompt(client_fd);

    g_core->log(g_core, PORTAL_LOG_DEBUG, "cli", "New CLI client connected (fd=%d)", client_fd);
}

/* --- Module lifecycle --- */

int portal_module_load(portal_core_t *core)
{
    g_core = core;

    /* Get socket path from a header or use default */
    /* Read socket path from config, or use default */
    const char *sock = core->config_get(core, "cli", "socket_path");
    if (!sock) sock = core->config_get(core, "core", "socket_path");
    if (!sock) sock = PORTAL_DEFAULT_SOCKET;
    snprintf(g_socket_path, sizeof(g_socket_path), "%s", sock);

    /* Create UNIX socket */
    g_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_sock_fd < 0) {
        core->log(core, PORTAL_LOG_ERROR, "cli", "socket() failed: %s", strerror(errno));
        return PORTAL_MODULE_FAIL;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", g_socket_path);

    unlink(g_socket_path);

    if (bind(g_sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        core->log(core, PORTAL_LOG_ERROR, "cli", "bind(%s) failed: %s",
                  g_socket_path, strerror(errno));
        close(g_sock_fd);
        g_sock_fd = -1;
        return PORTAL_MODULE_FAIL;
    }

    if (listen(g_sock_fd, 5) < 0) {
        core->log(core, PORTAL_LOG_ERROR, "cli", "listen() failed: %s", strerror(errno));
        close(g_sock_fd);
        g_sock_fd = -1;
        return PORTAL_MODULE_FAIL;
    }

    /* Register with event loop */
    core->fd_add(core, g_sock_fd, EV_READ, on_new_connection, NULL);

    /* 1 Hz timer for interactive `top` view (renders active clients only) */
    core->timer_add(core, 1.0, top_timer_cb, NULL);

    /* Register our path */
    core->path_register(core, "/cli/command", "cli");
    core->path_set_access(core, "/cli/command", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "cli", "Listening on %s", g_socket_path);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    /* Close all clients */
    for (int i = 0; i < CLI_MAX_CLIENTS; i++) {
        if (g_clients[i].active) {
            send_str(g_clients[i].fd, "CLI module unloading. Goodbye.\n");
            core->fd_del(core, g_clients[i].fd);
            close(g_clients[i].fd);
            g_clients[i].active = 0;
        }
    }
    g_client_count = 0;

    /* Close listener */
    if (g_sock_fd >= 0) {
        core->fd_del(core, g_sock_fd);
        close(g_sock_fd);
        g_sock_fd = -1;
    }

    unlink(g_socket_path);

    core->path_unregister(core, "/cli/command");
    core->log(core, PORTAL_LOG_INFO, "cli", "CLI module unloaded");

    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;
    (void)msg;
    resp->status = PORTAL_OK;
    return 0;
}
