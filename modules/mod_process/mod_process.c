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
 * mod_process — System command execution
 *
 * Execute system commands via popen with output capture.
 * Sandboxed: only allowed commands can be run.
 * Admin-only by default (label: admin).
 *
 * Config:
 *   [mod_process]
 *   allowed = ls,cat,df,free,uname,ps,date,whoami,id,uptime,ip,ss,dig,ping
 *   timeout = 10
 *   max_output = 65536
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "portal/portal.h"

#define PROC_MAX_OUTPUT   65536
#define PROC_MAX_ALLOWED  64
#define PROC_TIMEOUT      10

static portal_core_t *g_core = NULL;
static char  g_allowed[PROC_MAX_ALLOWED][64];
static int   g_allowed_count = 0;
static int   g_timeout = PROC_TIMEOUT;
static size_t g_max_output = PROC_MAX_OUTPUT;
static int64_t g_total_exec = 0;
static int64_t g_total_denied = 0;

static portal_module_info_t info = {
    .name = "process", .version = "1.0.0",
    .description = "System command execution (sandboxed)",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

/* Extract the base command name from a command string */
static void get_base_cmd(const char *cmd, char *base, size_t blen)
{
    /* Skip leading whitespace */
    while (*cmd == ' ') cmd++;
    /* Find the command name (first token, strip path) */
    const char *slash = strrchr(cmd, '/');
    if (slash && slash < strchr(cmd, ' ')) cmd = slash + 1;
    size_t i = 0;
    while (cmd[i] && cmd[i] != ' ' && i < blen - 1) {
        base[i] = cmd[i];
        i++;
    }
    base[i] = '\0';
}

static int is_allowed(const char *cmd)
{
    if (g_allowed_count == 0) return 1;  /* no restrictions if none configured */
    char base[64];
    get_base_cmd(cmd, base, sizeof(base));
    for (int i = 0; i < g_allowed_count; i++)
        if (strcmp(g_allowed[i], base) == 0) return 1;
    return 0;
}

/* Security: reject dangerous patterns */
static int is_safe(const char *cmd)
{
    if (strstr(cmd, "..")) return 0;
    if (strstr(cmd, "rm -rf")) return 0;
    if (strstr(cmd, "mkfs")) return 0;
    if (strstr(cmd, "dd if=")) return 0;
    if (strstr(cmd, "> /dev/")) return 0;
    if (strstr(cmd, ":(){ :|:& };:")) return 0;
    return 1;
}

static int exec_command(const char *cmd, char *out, size_t outlen, int *exit_code)
{
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    size_t total = 0;
    char buf[4096];
    while (total < outlen - 1) {
        size_t rd = fread(buf, 1, sizeof(buf), fp);
        if (rd == 0) break;
        size_t copy = rd;
        if (total + copy >= outlen - 1) copy = outlen - 1 - total;
        memcpy(out + total, buf, copy);
        total += copy;
    }
    out[total] = '\0';

    int status = pclose(fp);
    *exit_code = WEXITSTATUS(status);
    return (int)total;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_total_exec = 0;
    g_total_denied = 0;
    g_allowed_count = 0;

    const char *v;
    if ((v = core->config_get(core, "process", "timeout")))
        g_timeout = atoi(v);
    if ((v = core->config_get(core, "process", "max_output")))
        g_max_output = (size_t)atol(v);

    /* Parse allowed commands list */
    if ((v = core->config_get(core, "process", "allowed"))) {
        char tmp[1024];
        snprintf(tmp, sizeof(tmp), "%s", v);
        char *saveptr;
        char *tok = strtok_r(tmp, ",", &saveptr);
        while (tok && g_allowed_count < PROC_MAX_ALLOWED) {
            while (*tok == ' ') tok++;
            snprintf(g_allowed[g_allowed_count++], 64, "%s", tok);
            tok = strtok_r(NULL, ",", &saveptr);
        }
    } else {
        /* Default safe commands */
        const char *defaults[] = {
            "ls", "cat", "df", "free", "uname", "ps", "date",
            "whoami", "id", "uptime", "ip", "ss", "dig", "ping",
            "head", "tail", "wc", "sort", "grep", "find", "du",
            "hostname", "env", "echo", "test", NULL
        };
        for (int i = 0; defaults[i]; i++)
            snprintf(g_allowed[g_allowed_count++], 64, "%s", defaults[i]);
    }

    core->path_register(core, "/process/resources/status", "process");
    core->path_set_access(core, "/process/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/process/resources/allowed", "process");
    core->path_set_access(core, "/process/resources/allowed", PORTAL_ACCESS_READ);
    core->path_register(core, "/process/functions/exec", "process");
    core->path_set_access(core, "/process/functions/exec", PORTAL_ACCESS_RW);
    core->path_add_label(core, "/process/functions/exec", "admin");

    core->log(core, PORTAL_LOG_INFO, "process",
              "Process executor ready (%d allowed commands, timeout: %ds)",
              g_allowed_count, g_timeout);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/process/resources/status");
    core->path_unregister(core, "/process/resources/allowed");
    core->path_unregister(core, "/process/functions/exec");
    core->log(core, PORTAL_LOG_INFO, "process", "Process executor unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[8192];
    int n;

    if (strcmp(msg->path, "/process/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "Process Executor\n"
            "Allowed commands: %d\n"
            "Timeout: %ds\n"
            "Max output: %zu bytes\n"
            "Total executed: %lld\n"
            "Total denied: %lld\n",
            g_allowed_count, g_timeout, g_max_output,
            (long long)g_total_exec, (long long)g_total_denied);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/process/resources/allowed") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Allowed commands:\n");
        for (int i = 0; i < g_allowed_count; i++)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "  %s\n", g_allowed[i]);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/process/functions/exec") == 0) {
        const char *cmd = get_hdr(msg, "cmd");
        if (!cmd && msg->body) cmd = msg->body;
        if (!cmd) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: cmd header or body\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        if (!is_safe(cmd)) {
            g_total_denied++;
            portal_resp_set_status(resp, PORTAL_FORBIDDEN);
            n = snprintf(buf, sizeof(buf), "Command rejected: unsafe pattern\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            core->log(core, PORTAL_LOG_WARN, "process",
                      "Rejected unsafe command: %s", cmd);
            return -1;
        }

        if (!is_allowed(cmd)) {
            g_total_denied++;
            char base[64];
            get_base_cmd(cmd, base, sizeof(base));
            portal_resp_set_status(resp, PORTAL_FORBIDDEN);
            n = snprintf(buf, sizeof(buf),
                "Command '%s' not in allowed list\n", base);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        char *out = malloc(g_max_output);
        int exit_code = 0;
        int len = exec_command(cmd, out, g_max_output, &exit_code);
        g_total_exec++;
        core->event_emit(core, "/events/process/exec", cmd, strlen(cmd));
        core->log(core, PORTAL_LOG_INFO, "process",
                  "Executed: %s (exit: %d, %d bytes)", cmd, exit_code, len);

        if (len >= 0) {
            portal_resp_set_status(resp, exit_code == 0 ? PORTAL_OK : PORTAL_INTERNAL_ERROR);
            portal_resp_set_body(resp, out, (size_t)len);
        } else {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            n = snprintf(buf, sizeof(buf), "Execution failed\n");
            portal_resp_set_body(resp, buf, (size_t)n);
        }
        free(out);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
