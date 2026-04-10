/*
 * mod_shell — Remote interactive shell via federation
 *
 * Executes system commands on the local machine. When combined with
 * mod_node federation, allows remote shell access to any peer:
 *
 *   portal:/> shell ssip841
 *   root@ssip841:~# uptime
 *   root@ssip841:~# asterisk -rx "sip show peers"
 *   root@ssip841:~# exit
 *
 * Security: path requires label "admin". Every execution is emitted
 * as an event for audit trail.
 *
 * Paths:
 *   /shell/functions/exec   RW (admin)  Execute a command
 *
 * Events:
 *   /events/shell/exec      Every command executed (cmd, exit_code, user)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>

#include "portal/portal.h"

/* ── Configuration ── */

static struct {
    int  timeout;          /* max seconds per command (default 10) */
    char shell[64];        /* shell binary (default /bin/sh) */
    int  allow_exec;       /* safety switch (default 1) */
    int  max_output;       /* max bytes of output captured (default 64KB) */
} g_cfg;

static portal_core_t *g_core;

/* ── Module descriptor ── */

static portal_module_info_t info = {
    .name        = "shell",
    .version     = "1.0.0",
    .description = "Remote interactive shell via federation",
    .soft_deps   = NULL
};

portal_module_info_t *portal_module_info(void) { return &info; }

/* ── Command execution with timeout ── */

static int exec_command(const char *cmd, const char *shell, int timeout_sec,
                        char **output, size_t *output_len, int *exit_code)
{
    *output = NULL;
    *output_len = 0;
    *exit_code = -1;

    /* Build: /bin/sh -c "cmd 2>&1" */
    size_t cmdlen = strlen(cmd) + strlen(shell) + 32;
    char *full_cmd = malloc(cmdlen);
    if (!full_cmd) return -1;
    snprintf(full_cmd, cmdlen, "%s -c '%s' 2>&1", shell, cmd);

    FILE *p = popen(full_cmd, "r");
    free(full_cmd);
    if (!p) return -1;

    /* Read output with size limit */
    size_t cap = 4096;
    size_t pos = 0;
    char *buf = malloc(cap);
    if (!buf) { pclose(p); return -1; }

    /* Simple timeout: alarm signal */
    alarm((unsigned)timeout_sec);

    while (pos < (size_t)g_cfg.max_output) {
        size_t n = fread(buf + pos, 1, cap - pos - 1, p);
        if (n == 0) break;
        pos += n;
        if (pos + 256 >= cap) {
            cap *= 2;
            if (cap > (size_t)g_cfg.max_output) cap = (size_t)g_cfg.max_output + 1;
            char *nb = realloc(buf, cap);
            if (!nb) break;
            buf = nb;
        }
    }

    alarm(0); /* cancel alarm */

    int status = pclose(p);
    if (WIFEXITED(status))
        *exit_code = WEXITSTATUS(status);
    else
        *exit_code = -1;

    buf[pos] = '\0';
    *output = buf;
    *output_len = pos;
    return 0;
}

/* ── Handler ── */

static int handle_exec(portal_core_t *core, const portal_msg_t *msg,
                       portal_resp_t *resp)
{
    if (!g_cfg.allow_exec) {
        portal_resp_set_status(resp, PORTAL_FORBIDDEN);
        portal_resp_set_body(resp, "shell execution disabled in config\n", 35);
        return -1;
    }

    /* Read headers */
    const char *cmd = NULL;
    const char *cwd = NULL;
    int timeout = g_cfg.timeout;

    for (uint16_t i = 0; i < msg->header_count; i++) {
        if (strcmp(msg->headers[i].key, "cmd") == 0) cmd = msg->headers[i].value;
        if (strcmp(msg->headers[i].key, "cwd") == 0) cwd = msg->headers[i].value;
        if (strcmp(msg->headers[i].key, "timeout") == 0) {
            int t = atoi(msg->headers[i].value);
            if (t > 0 && t <= 300) timeout = t;
        }
    }

    if (!cmd || !cmd[0]) {
        portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
        portal_resp_set_body(resp, "missing header: cmd\n", 20);
        return -1;
    }

    /* Build command with optional cwd prefix */
    char full[4096];
    if (cwd && cwd[0] && strcmp(cwd, "/") != 0)
        snprintf(full, sizeof(full), "cd %s 2>/dev/null && %s", cwd, cmd);
    else
        snprintf(full, sizeof(full), "%s", cmd);

    /* Execute */
    char *output = NULL;
    size_t output_len = 0;
    int exit_code = -1;

    int rc = exec_command(full, g_cfg.shell, timeout, &output, &output_len, &exit_code);

    if (rc != 0) {
        portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
        portal_resp_set_body(resp, "execution failed\n", 17);
        return -1;
    }

    /* Emit audit event */
    char evt[512];
    const char *user = msg->ctx ? msg->ctx->auth.user : "?";
    int elen = snprintf(evt, sizeof(evt), "cmd=%s exit=%d user=%s",
                        cmd, exit_code, user);
    core->event_emit(core, "/events/shell/exec", evt, (size_t)elen);

    core->log(core, PORTAL_LOG_INFO, "shell", "[%s] %s (exit %d, %zu bytes)",
              user, cmd, exit_code, output_len);

    /* Response */
    portal_resp_set_status(resp, PORTAL_OK);
    if (output && output_len > 0)
        portal_resp_set_body(resp, output, output_len);
    else
        portal_resp_set_body(resp, "(no output)\n", 12);

    free(output);
    return 0;
}

/* ── Lifecycle ── */

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(&g_cfg, 0, sizeof(g_cfg));

    const char *v;
    v = core->config_get(core, "shell", "timeout");
    g_cfg.timeout = v ? atoi(v) : 10;
    if (g_cfg.timeout < 1) g_cfg.timeout = 1;
    if (g_cfg.timeout > 300) g_cfg.timeout = 300;

    v = core->config_get(core, "shell", "shell");
    snprintf(g_cfg.shell, sizeof(g_cfg.shell), "%s", v ? v : "/bin/sh");

    v = core->config_get(core, "shell", "allow_exec");
    g_cfg.allow_exec = v ? (strcmp(v, "true") == 0 || strcmp(v, "1") == 0 || strcmp(v, "yes") == 0) : 1;

    v = core->config_get(core, "shell", "max_output");
    g_cfg.max_output = v ? atoi(v) : 65536;
    if (g_cfg.max_output < 1024) g_cfg.max_output = 1024;

    /* Register path */
    core->path_register(core, "/shell/functions/exec", "shell");
    core->path_set_access(core, "/shell/functions/exec", PORTAL_ACCESS_RW);
    core->path_add_label(core, "/shell/functions/exec", "admin");

    /* Register event */
    portal_labels_t labels = {0};
    core->event_register(core, "/events/shell/exec",
                         "Shell command executed", &labels);

    core->log(core, PORTAL_LOG_INFO, "shell",
              "Shell ready (timeout: %ds, shell: %s, max: %d bytes, exec: %s)",
              g_cfg.timeout, g_cfg.shell, g_cfg.max_output,
              g_cfg.allow_exec ? "enabled" : "DISABLED");

    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/shell/functions/exec");
    core->event_unregister(core, "/events/shell/exec");
    core->log(core, PORTAL_LOG_INFO, "shell", "Shell unloaded");
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    if (strcmp(msg->path, "/shell/functions/exec") == 0)
        return handle_exec(core, msg, resp);

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
