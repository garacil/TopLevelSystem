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
 * mod_logic_python — Python Scripting Engine for Portal
 *
 * Runs Python in a **forked subprocess** to avoid CPython's signal
 * handler conflicts with libev. Communication via pipes.
 *
 * The subprocess runs a Python bridge script that:
 *   - Loads user scripts from the logic directory
 *   - Provides the portal.* API
 *   - Receives requests via stdin (JSON lines)
 *   - Sends responses via stdout (JSON lines)
 *
 * Scripts in: /var/lib/portal/<instance>/logic/<appname>/main.py
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include "portal/portal.h"

#define PY_MAX_ROUTES   128
#define PY_BUF_SIZE     65536

typedef struct {
    char path[PORTAL_MAX_PATH_LEN];
    int  active;
} py_route_t;

static portal_core_t *g_core = NULL;
static char           g_script_dir[PORTAL_MAX_PATH_LEN] = "";
static pid_t          g_py_pid = -1;
static int            g_to_py = -1;    /* pipe: parent writes → child reads */
static int            g_from_py = -1;  /* pipe: child writes → parent reads */
static py_route_t     g_routes[PY_MAX_ROUTES];
static int            g_route_count = 0;
/* g_scripts_loaded tracked by subprocess */

static portal_module_info_t info = {
    .name = "logic_python", .version = "1.1.0",
    .description = "Python scripting engine (subprocess)",
    .soft_deps = (const char *[]){"logic", NULL}
};
portal_module_info_t *portal_module_info(void) { return &info; }

/* --- Python bridge script (embedded) --- */

static const char *PYTHON_BRIDGE_V2 =
"import sys, os, json\n"
"\n"
"class PortalAPI:\n"
"    _routes = {}\n"
"    def get(self, path): return ''  # During loading, get() returns empty\n"
"    def call(self, path, headers=None, body=None): return ('', 200)\n"
"    def log(self, level, message):\n"
"        sys.stderr.write(f'LOG:{level}:{message}\\n')\n"
"        sys.stderr.flush()\n"
"    def route(self, method, path, handler):\n"
"        self._routes[path] = handler\n"
"        sys.stderr.write(f'ROUTE:{method}:{path}\\n')\n"
"        sys.stderr.flush()\n"
"\n"
"portal = PortalAPI()\n"
"\n"
"# Make 'import portal' work in user scripts\n"
"import types\n"
"portal_mod = types.ModuleType('portal')\n"
"portal_mod.get = portal.get\n"
"portal_mod.call = portal.call\n"
"portal_mod.log = portal.log\n"
"portal_mod.route = portal.route\n"
"sys.modules['portal'] = portal_mod\n"
"\n"
"script_dir = sys.argv[1] if len(sys.argv) > 1 else '.'\n"
"loaded = 0\n"
"\n"
"if os.path.isdir(script_dir):\n"
"    for name in sorted(os.listdir(script_dir)):\n"
"        app_dir = os.path.join(script_dir, name)\n"
"        main_py = os.path.join(app_dir, 'main.py')\n"
"        if os.path.isdir(app_dir) and os.path.isfile(main_py):\n"
"            sys.path.insert(0, app_dir)\n"
"            try:\n"
"                exec(open(main_py).read(), {'portal': portal, '__name__': name})\n"
"                loaded += 1\n"
"            except Exception as e:\n"
"                portal.log('error', f'{name}: {e}')\n"
"\n"
"sys.stderr.write(f'READY:{loaded}\\n')\n"
"sys.stderr.flush()\n"
"\n"
"while True:\n"
"    line = ''\n"
"    while True:\n"
"        c = os.read(0, 1)\n"
"        if not c: break\n"
"        c = c.decode()\n"
"        if c == '\\n': break\n"
"        line += c\n"
"    if not line: break\n"
"    try:\n"
"        req = json.loads(line.strip())\n"
"        path = req.get('path', '')\n"
"        handler = portal._routes.get(path)\n"
"        if handler:\n"
"            result = handler(req)\n"
"            resp = json.dumps({'s': 200, 'b': str(result) if result else ''})\n"
"        else:\n"
"            resp = json.dumps({'s': 404, 'b': 'Not found'})\n"
"        print(resp, flush=True)\n"
"    except Exception as e:\n"
"        print(json.dumps({'s': 500, 'b': str(e)}), flush=True)\n"
;

/* --- Pipe communication --- */

static int send_to_python(const char *json_line)
{
    if (g_to_py < 0) {
        if (g_core) g_core->log(g_core, PORTAL_LOG_ERROR, "python",
                                 "g_to_py is -1!");
        return -1;
    }
    size_t len = strlen(json_line);
    ssize_t w = write(g_to_py, json_line, len);
    if (w < 0) {
        if (g_core) g_core->log(g_core, PORTAL_LOG_ERROR, "python",
                                 "write to python failed: %s", strerror(errno));
        return -1;
    }
    if (json_line[len-1] != '\n')
        write(g_to_py, "\n", 1);
    if (g_core) g_core->log(g_core, PORTAL_LOG_DEBUG, "python",
                             "Sent %zd bytes to python (fd=%d)", w, g_to_py);
    return 0;
}

static int read_from_python(char *buf, size_t buf_size)
{
    if (g_from_py < 0) return -1;

    fd_set rfds;
    struct timeval tv;
    size_t pos = 0;

    if (g_core) g_core->log(g_core, PORTAL_LOG_DEBUG, "python",
                             "Reading from python fd=%d", g_from_py);

    while (pos < buf_size - 1) {
        FD_ZERO(&rfds);
        FD_SET(g_from_py, &rfds);
        tv.tv_sec = 5; tv.tv_usec = 0;
        int sel = select(g_from_py + 1, &rfds, NULL, NULL, &tv);
        if (sel <= 0) {
            if (g_core) g_core->log(g_core, PORTAL_LOG_WARN, "python",
                                     "select timeout/error (sel=%d, errno=%d)", sel, errno);
            break;
        }
        ssize_t n = read(g_from_py, buf + pos, 1);
        if (n <= 0) return -1;
        if (buf[pos] == '\n') break;
        pos++;
    }
    buf[pos] = '\0';
    return (int)pos;
}

/* (API requests now handled via stderr protocol during startup) */

#if 0  /* Old API handler — kept for reference */
static void handle_python_api_request_old(const char *json_req, int resp_fd)
{
    /* Parse minimal JSON: {"cmd":"get","path":"/users"} */
    char cmd[32] = "", path[PORTAL_MAX_PATH_LEN] = "";
    char level[16] = "", message[1024] = "";
    char method[16] = "";

    /* Quick JSON parse for known fields */
    const char *p;
    if ((p = strstr(json_req, "\"cmd\":\"")))
        sscanf(p + 7, "%31[^\"]", cmd);
    if ((p = strstr(json_req, "\"path\":\"")))
        sscanf(p + 8, "%1023[^\"]", path);
    if ((p = strstr(json_req, "\"level\":\"")))
        sscanf(p + 9, "%15[^\"]", level);
    if ((p = strstr(json_req, "\"message\":\"")))
        sscanf(p + 11, "%1023[^\"]", message);
    if ((p = strstr(json_req, "\"method\":\"")))
        sscanf(p + 10, "%15[^\"]", method);

    if (strcmp(cmd, "get") == 0 || strcmp(cmd, "call") == 0) {
        portal_msg_t *msg = portal_msg_alloc();
        portal_resp_t *resp = portal_resp_alloc();
        if (msg && resp) {
            portal_msg_set_path(msg, path);
            portal_msg_set_method(msg, strcmp(cmd, "call") == 0 ?
                                  PORTAL_METHOD_CALL : PORTAL_METHOD_GET);
            g_core->send(g_core, msg, resp);

            char json_resp[PY_BUF_SIZE];
            /* Escape body for JSON */
            char escaped[PY_BUF_SIZE];
            size_t elen = 0;
            if (resp->body) {
                const char *b = resp->body;
                size_t blen = resp->body_len;
                if (blen > 0 && b[blen-1] == '\0') blen--;
                for (size_t i = 0; i < blen && elen < sizeof(escaped) - 4; i++) {
                    if (b[i] == '"') { escaped[elen++] = '\\'; escaped[elen++] = '"'; }
                    else if (b[i] == '\n') { escaped[elen++] = '\\'; escaped[elen++] = 'n'; }
                    else if (b[i] == '\\') { escaped[elen++] = '\\'; escaped[elen++] = '\\'; }
                    else if ((unsigned char)b[i] >= 32) escaped[elen++] = b[i];
                }
            }
            escaped[elen] = '\0';

            int n = snprintf(json_resp, sizeof(json_resp),
                "{\"status\":%d,\"body\":\"%s\"}\n", resp->status, escaped);
            write(resp_fd, json_resp, (size_t)n);

            portal_msg_free(msg);
            portal_resp_free(resp);
        }
    } else if (strcmp(cmd, "log") == 0) {
        int lv = PORTAL_LOG_INFO;
        if (strcmp(level, "error") == 0) lv = PORTAL_LOG_ERROR;
        else if (strcmp(level, "warn") == 0) lv = PORTAL_LOG_WARN;
        else if (strcmp(level, "debug") == 0) lv = PORTAL_LOG_DEBUG;
        g_core->log(g_core, lv, "python", "%s", message);
        write(resp_fd, "{\"status\":200}\n", 15);
    } else if (strcmp(cmd, "route") == 0) {
        if (g_route_count < PY_MAX_ROUTES && path[0]) {
            snprintf(g_routes[g_route_count].path, PORTAL_MAX_PATH_LEN, "%s", path);
            g_routes[g_route_count].active = 1;
            g_core->path_register(g_core, path, "logic_python");
            g_route_count++;
            g_core->log(g_core, PORTAL_LOG_INFO, "python",
                        "Route: %s %s", method, path);
        }
        write(resp_fd, "{\"status\":200}\n", 15);
    }
}
#endif

/* --- Start Python subprocess --- */

static int start_python_process(void)
{
    /* 3 pipes: stdin(parent→child), stdout(child→parent), stderr(child→parent for control) */
    int pipe_to[2], pipe_from[2], pipe_err[2];
    if (pipe(pipe_to) < 0 || pipe(pipe_from) < 0 || pipe(pipe_err) < 0)
        return -1;

    g_core->log(g_core, PORTAL_LOG_DEBUG, "python",
                "Pipes: to[%d,%d] from[%d,%d] err[%d,%d]",
                pipe_to[0], pipe_to[1], pipe_from[0], pipe_from[1],
                pipe_err[0], pipe_err[1]);

    g_py_pid = fork();
    if (g_py_pid < 0) return -1;

    if (g_py_pid == 0) {
        /* Child */
        close(pipe_to[1]);
        close(pipe_from[0]);
        close(pipe_err[0]);

        dup2(pipe_to[0], STDIN_FILENO);
        dup2(pipe_from[1], STDOUT_FILENO);
        dup2(pipe_err[1], STDERR_FILENO);

        close(pipe_to[0]);
        close(pipe_from[1]);
        close(pipe_err[1]);

        char tmp[256];
        snprintf(tmp, sizeof(tmp), "/tmp/portal_py_%d.py", getpid());
        FILE *f = fopen(tmp, "w");
        if (f) { fputs(PYTHON_BRIDGE_V2, f); fclose(f); }

        execl("/usr/bin/python3", "python3", "-u", tmp, g_script_dir, NULL);
        _exit(1);
    }

    /* Parent */
    close(pipe_to[0]);
    close(pipe_from[1]);
    close(pipe_err[1]);

    /* Move pipe fds to high numbers to avoid conflicts with event loop */
    g_to_py = fcntl(pipe_to[1], F_DUPFD_CLOEXEC, 200);
    g_from_py = fcntl(pipe_from[0], F_DUPFD_CLOEXEC, 201);
    close(pipe_to[1]);
    close(pipe_from[0]);
    g_core->log(g_core, PORTAL_LOG_DEBUG, "python",
                "g_to_py=%d g_from_py=%d (moved to high fds)", g_to_py, g_from_py);

    /* Read stderr for route registrations and READY signal */
    int err_fd = pipe_err[0];
    char buf[4096];
    fd_set rfds;
    struct timeval tv;
    int ready = 0;

    while (!ready) {
        FD_ZERO(&rfds);
        FD_SET(err_fd, &rfds);
        tv.tv_sec = 5; tv.tv_usec = 0;
        if (select(err_fd + 1, &rfds, NULL, NULL, &tv) <= 0) break;

        ssize_t n = read(err_fd, buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = '\0';

        /* Process each line */
        char *line = buf;
        while (line && *line) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = '\0';

            if (strncmp(line, "ROUTE:", 6) == 0) {
                /* ROUTE:GET:/app/pyapp/hello */
                char method[16], path[PORTAL_MAX_PATH_LEN];
                if (sscanf(line + 6, "%15[^:]:%1023s", method, path) == 2) {
                    if (g_route_count < PY_MAX_ROUTES) {
                        snprintf(g_routes[g_route_count].path, PORTAL_MAX_PATH_LEN, "%s", path);
                        g_routes[g_route_count].active = 1;
                        g_core->path_register(g_core, path, "logic_python");
                        g_core->path_set_access(g_core, path, PORTAL_ACCESS_RW);
                        g_route_count++;
                        g_core->log(g_core, PORTAL_LOG_INFO, "python",
                                    "Route: %s %s", method, path);
                    }
                }
            } else if (strncmp(line, "LOG:", 4) == 0) {
                char level[16], message[1024];
                if (sscanf(line + 4, "%15[^:]:%1023[^\n]", level, message) == 2) {
                    int lv = PORTAL_LOG_INFO;
                    if (strcmp(level, "error") == 0) lv = PORTAL_LOG_ERROR;
                    g_core->log(g_core, lv, "python", "%s", message);
                }
            } else if (strncmp(line, "READY:", 6) == 0) {
                ready = 1;
            }

            if (!nl) break;
            line = nl + 1;
        }
    }

    close(err_fd);

    g_core->log(g_core, PORTAL_LOG_INFO, "python",
                "Python subprocess ready (pid: %d, routes: %d)",
                g_py_pid, g_route_count);
    return 0;
}

/* --- Module lifecycle --- */

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_route_count = 0;
    memset(g_routes, 0, sizeof(g_routes));

    const char *app_dir = core->config_get(core, "core", "app_dir");
    if (app_dir)
        snprintf(g_script_dir, sizeof(g_script_dir), "%s/logic", app_dir);
    else {
        const char *data_dir = core->config_get(core, "core", "data_dir");
        if (data_dir)
            snprintf(g_script_dir, sizeof(g_script_dir), "%s/logic", data_dir);
    }

    core->path_register(core, "/logic_python/resources/status", "logic_python");
    core->path_set_access(core, "/logic_python/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/logic_python/resources/status", "Python engine: subprocess pid, routes");
    core->path_register(core, "/logic_python/functions/reload", "logic_python");
    core->path_set_access(core, "/logic_python/functions/reload", PORTAL_ACCESS_RW);

    if (start_python_process() < 0) {
        core->log(core, PORTAL_LOG_ERROR, "python", "Failed to start Python process");
        return PORTAL_MODULE_FAIL;
    }

    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    /* Kill Python subprocess */
    if (g_py_pid > 0) {
        kill(g_py_pid, SIGTERM);
        waitpid(g_py_pid, NULL, WNOHANG);
        g_py_pid = -1;
    }
    if (g_to_py >= 0) { close(g_to_py); g_to_py = -1; }
    if (g_from_py >= 0) { close(g_from_py); g_from_py = -1; }

    for (int i = 0; i < g_route_count; i++)
        if (g_routes[i].active)
            core->path_unregister(core, g_routes[i].path);
    g_route_count = 0;

    core->path_unregister(core, "/logic_python/resources/status");
    core->path_unregister(core, "/logic_python/functions/reload");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;
    char buf[PY_BUF_SIZE];
    int n;

    if (strcmp(msg->path, "/logic_python/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "Python Scripting Engine (subprocess)\n"
            "PID: %d\n"
            "Routes: %d\n"
            "Dir: %s\n",
            g_py_pid, g_route_count, g_script_dir);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* Check if path is a Python route */
    for (int i = 0; i < g_route_count; i++) {
        if (g_routes[i].active && strcmp(g_routes[i].path, msg->path) == 0) {
            /* Send request to Python subprocess */
            char json_req[4096];
            n = snprintf(json_req, sizeof(json_req),
                "{\"path\":\"%s\",\"method\":%d}\n",
                msg->path, msg->method);
            if (send_to_python(json_req) < 0) {
                portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
                return -1;
            }

            /* Read response */
            char json_resp[PY_BUF_SIZE];
            int rlen = read_from_python(json_resp, sizeof(json_resp));
            g_core->log(g_core, PORTAL_LOG_DEBUG, "python",
                        "Got response: len=%d data='%.100s'", rlen, json_resp);
            if (rlen < 0) {
                portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
                return -1;
            }

            /* Parse response: {"s": 200, "b": "..."} */
            int status = 200;
            const char *sp = strstr(json_resp, "\"s\":");
            /* Find "b": with or without space after colon */
            const char *bp = strstr(json_resp, "\"b\": \"");
            if (bp) bp += 6;
            else { bp = strstr(json_resp, "\"b\":\""); if (bp) bp += 5; }
            if (sp) {
                sp += 4;
                while (*sp == ' ') sp++;
                status = atoi(sp);
            }

            if (bp) {
                char body[PY_BUF_SIZE];
                size_t blen = 0;
                while (*bp && *bp != '"' && blen < sizeof(body) - 1) {
                    if (*bp == '\\' && *(bp+1) == 'n') { body[blen++] = '\n'; bp += 2; }
                    else if (*bp == '\\' && *(bp+1) == '"') { body[blen++] = '"'; bp += 2; }
                    else if (*bp == '\\' && *(bp+1) == '\\') { body[blen++] = '\\'; bp += 2; }
                    else { body[blen++] = *bp++; }
                }
                body[blen] = '\0';
                portal_resp_set_status(resp, (uint16_t)status);
                portal_resp_set_body(resp, body, blen);
            } else {
                portal_resp_set_status(resp, (uint16_t)status);
            }
            return 0;
        }
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
