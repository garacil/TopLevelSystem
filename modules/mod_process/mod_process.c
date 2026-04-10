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
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include "portal/portal.h"

#define PROC_MAX_OUTPUT   65536
#define PROC_MAX_ALLOWED  64
#define PROC_TIMEOUT      10
#define PROC_MAX_SAMPLES  4096
#define PROC_LINE_LEN     160

static portal_core_t *g_core = NULL;
static char  g_allowed[PROC_MAX_ALLOWED][64];
static int   g_allowed_count = 0;
static int   g_timeout = PROC_TIMEOUT;
static size_t g_max_output = PROC_MAX_OUTPUT;
static int64_t g_total_exec = 0;
static int64_t g_total_denied = 0;

/* --- /proc process introspection --- */

typedef struct {
    int           pid;
    int           ppid;
    char          state;
    unsigned long utime;        /* jiffies */
    unsigned long stime;        /* jiffies */
    unsigned long vsize;        /* bytes */
    long          rss_pages;
    double        cpu_pct;      /* computed from prev sample */
    double        mem_pct;      /* computed from MemTotal */
    char          comm[64];
} proc_sample_t;

/* Previous sample set, keyed by PID via linear scan (N<500 typical). */
static proc_sample_t       g_prev[PROC_MAX_SAMPLES];
static int                 g_prev_count = 0;
static unsigned long long  g_prev_total_jiffies = 0;
static long                g_page_kb = 4;     /* /proc/<pid>/stat rss is in pages */
static long                g_mem_total_kb = 0;

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

/* --- /proc helpers --- */

static unsigned long long read_total_jiffies(void)
{
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return 0;
    char line[512];
    unsigned long long total = 0;
    if (fgets(line, sizeof(line), f)) {
        unsigned long long u, ni, sys, idle, io, irq, sirq, steal;
        int n = sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
                       &u, &ni, &sys, &idle, &io, &irq, &sirq, &steal);
        if (n >= 7) total = u + ni + sys + idle + io + irq + sirq;
        if (n >= 8) total += steal;
    }
    fclose(f);
    return total;
}

static long read_mem_total_kb(void)
{
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return 0;
    char line[256];
    long kb = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "MemTotal: %ld kB", &kb) == 1) break;
    }
    fclose(f);
    return kb;
}

/* Parse /proc/<pid>/stat. Handles comm with spaces/parens via strrchr(')'). */
static int read_pid_stat(int pid, proc_sample_t *s)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[1024];
    size_t rd = fread(line, 1, sizeof(line) - 1, f);
    fclose(f);
    if (rd == 0) return -1;
    line[rd] = '\0';

    char *lp = strchr(line, '(');
    char *rp = strrchr(line, ')');
    if (!lp || !rp || rp <= lp) return -1;

    size_t clen = (size_t)(rp - lp - 1);
    if (clen >= sizeof(s->comm)) clen = sizeof(s->comm) - 1;
    memcpy(s->comm, lp + 1, clen);
    s->comm[clen] = '\0';

    /* Fields 3..: state ppid pgrp session tty tpgid flags minflt cminflt
       majflt cmajflt utime stime cutime cstime priority nice num_threads
       itrealvalue starttime vsize rss */
    char state = '?';
    int ppid = 0;
    unsigned long utime = 0, stime = 0, vsize = 0;
    long rss = 0;
    int n = sscanf(rp + 2,
        "%c %d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu "
        "%*d %*d %*d %*d %*d %*d %*u %lu %ld",
        &state, &ppid, &utime, &stime, &vsize, &rss);
    if (n < 6) return -1;

    s->pid        = pid;
    s->ppid       = ppid;
    s->state      = state;
    s->utime      = utime;
    s->stime      = stime;
    s->vsize      = vsize;
    s->rss_pages  = rss;
    s->cpu_pct    = 0.0;
    s->mem_pct    = 0.0;
    return 0;
}

/* Iterate /proc and fill samples[]. Returns count. */
static int enumerate_pids(proc_sample_t *samples, int max)
{
    DIR *d = opendir("/proc");
    if (!d) return 0;
    int count = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && count < max) {
        if (!isdigit((unsigned char)e->d_name[0])) continue;
        int pid = atoi(e->d_name);
        if (pid <= 0) continue;
        if (read_pid_stat(pid, &samples[count]) == 0) count++;
    }
    closedir(d);
    return count;
}

/* Iterate /proc/<pid>/task and fill samples[] with per-thread stats. */
static int enumerate_threads(int pid, proc_sample_t *samples, int max)
{
    char dirp[64];
    snprintf(dirp, sizeof(dirp), "/proc/%d/task", pid);
    DIR *d = opendir(dirp);
    if (!d) return 0;
    int count = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && count < max) {
        if (!isdigit((unsigned char)e->d_name[0])) continue;
        int tid = atoi(e->d_name);
        if (tid <= 0) continue;
        /* read /proc/<pid>/task/<tid>/stat directly */
        char path[96];
        snprintf(path, sizeof(path), "/proc/%d/task/%d/stat", pid, tid);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        char line[1024];
        size_t rd = fread(line, 1, sizeof(line) - 1, f);
        fclose(f);
        if (rd == 0) continue;
        line[rd] = '\0';
        char *lp = strchr(line, '('), *rp = strrchr(line, ')');
        if (!lp || !rp || rp <= lp) continue;
        proc_sample_t *s = &samples[count];
        size_t clen = (size_t)(rp - lp - 1);
        if (clen >= sizeof(s->comm)) clen = sizeof(s->comm) - 1;
        memcpy(s->comm, lp + 1, clen);
        s->comm[clen] = '\0';
        char state = '?';
        int ppid = 0;
        unsigned long utime = 0, stime = 0;
        sscanf(rp + 2,
            "%c %d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
            &state, &ppid, &utime, &stime);
        s->pid       = tid;          /* show TID as "pid" for threads */
        s->ppid      = pid;          /* owning process */
        s->state     = state;
        s->utime     = utime;
        s->stime     = stime;
        s->vsize     = 0;
        s->rss_pages = 0;
        s->cpu_pct   = 0.0;
        s->mem_pct   = 0.0;
        count++;
    }
    closedir(d);
    return count;
}

/* Compute cpu% against previous sample set + update prev. */
static void compute_cpu_pct(proc_sample_t *cur, int n, unsigned long long total_jiffies)
{
    unsigned long long total_delta = 0;
    if (g_prev_total_jiffies > 0 && total_jiffies > g_prev_total_jiffies)
        total_delta = total_jiffies - g_prev_total_jiffies;

    for (int i = 0; i < n; i++) {
        proc_sample_t *c = &cur[i];
        if (g_mem_total_kb > 0) {
            long rss_kb = c->rss_pages * g_page_kb;
            c->mem_pct = 100.0 * (double)rss_kb / (double)g_mem_total_kb;
        }
        if (total_delta == 0) { c->cpu_pct = 0.0; continue; }
        /* Linear scan prev for same pid */
        for (int j = 0; j < g_prev_count; j++) {
            if (g_prev[j].pid == c->pid) {
                unsigned long du = c->utime - g_prev[j].utime;
                unsigned long ds = c->stime - g_prev[j].stime;
                c->cpu_pct = 100.0 * (double)(du + ds) / (double)total_delta;
                break;
            }
        }
    }
    /* Update prev snapshot */
    int keep = n < PROC_MAX_SAMPLES ? n : PROC_MAX_SAMPLES;
    memcpy(g_prev, cur, (size_t)keep * sizeof(proc_sample_t));
    g_prev_count = keep;
    g_prev_total_jiffies = total_jiffies;
}

static int cmp_cpu(const void *a, const void *b)
{
    double da = ((const proc_sample_t *)a)->cpu_pct;
    double db = ((const proc_sample_t *)b)->cpu_pct;
    if (da < db) return 1;
    if (da > db) return -1;
    return 0;
}
static int cmp_mem(const void *a, const void *b)
{
    double da = ((const proc_sample_t *)a)->mem_pct;
    double db = ((const proc_sample_t *)b)->mem_pct;
    if (da < db) return 1;
    if (da > db) return -1;
    return 0;
}
static int cmp_pid(const void *a, const void *b)
{
    int pa = ((const proc_sample_t *)a)->pid;
    int pb = ((const proc_sample_t *)b)->pid;
    return pa - pb;
}

/* Format a single sample row (fixed width). */
static size_t format_row(char *buf, size_t buflen, const proc_sample_t *s)
{
    long rss_kb = s->rss_pages * g_page_kb;
    return (size_t)snprintf(buf, buflen,
        "%6d %6d %c %6.1f %5.1f %8ld %s\n",
        s->pid, s->ppid, s->state,
        s->cpu_pct, s->mem_pct, rss_kb, s->comm);
}

static const char *row_header(void)
{
    return "   PID   PPID S    CPU%  MEM%    RSS_kB COMMAND\n";
}

/* --- Portal-internal top: thread + module view of /this/ process --- */

/* Read /proc/self/task/<tid>/comm — actual thread name (set via prctl) */
static void read_thread_name(int tid, char *out, size_t outlen)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/task/%d/comm", tid);
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(out, outlen, "?"); return; }
    if (!fgets(out, (int)outlen, f)) { snprintf(out, outlen, "?"); }
    else {
        size_t l = strlen(out);
        while (l > 0 && (out[l-1] == '\n' || out[l-1] == '\r')) out[--l] = '\0';
    }
    fclose(f);
}

/* Per-thread CPU% sample state (portal's own threads) */
static proc_sample_t      g_thr_prev[256];
static int                g_thr_prev_count = 0;
static unsigned long long g_thr_prev_total = 0;
static unsigned long      g_portal_prev_utime = 0;
static unsigned long      g_portal_prev_stime = 0;

/* Per-module msg/min sample state — keyed by module name (linear scan, N<60) */
typedef struct {
    char     name[32];
    uint64_t prev_count;
    time_t   prev_time;
    double   per_min;
} mod_rate_sample_t;
static mod_rate_sample_t g_mod_rate[64];
static int               g_mod_rate_count = 0;

static double compute_mod_rate(const char *name, uint64_t cur)
{
    time_t now = time(NULL);
    for (int i = 0; i < g_mod_rate_count; i++) {
        if (strcmp(g_mod_rate[i].name, name) == 0) {
            time_t dt = now - g_mod_rate[i].prev_time;
            uint64_t dc = cur - g_mod_rate[i].prev_count;
            if (dt > 0) g_mod_rate[i].per_min = (double)dc * 60.0 / (double)dt;
            g_mod_rate[i].prev_count = cur;
            g_mod_rate[i].prev_time  = now;
            return g_mod_rate[i].per_min;
        }
    }
    if (g_mod_rate_count < 64) {
        snprintf(g_mod_rate[g_mod_rate_count].name, 32, "%s", name);
        g_mod_rate[g_mod_rate_count].prev_count = cur;
        g_mod_rate[g_mod_rate_count].prev_time  = now;
        g_mod_rate[g_mod_rate_count].per_min    = 0.0;
        g_mod_rate_count++;
    }
    return 0.0;
}

/* Per-module path counter — fed via path_iter callback */
typedef struct {
    char name[32];
    int  count;
} mod_path_count_t;

typedef struct {
    mod_path_count_t entries[64];
    int              n;
} path_count_ctx_t;

static void path_count_cb(const char *path, const char *module_name, void *ud)
{
    (void)path;
    path_count_ctx_t *c = ud;
    for (int i = 0; i < c->n; i++) {
        if (strcmp(c->entries[i].name, module_name) == 0) {
            c->entries[i].count++;
            return;
        }
    }
    if (c->n < 64) {
        snprintf(c->entries[c->n].name, 32, "%s", module_name);
        c->entries[c->n].count = 1;
        c->n++;
    }
}

static int find_path_count(const path_count_ctx_t *c, const char *name)
{
    for (int i = 0; i < c->n; i++)
        if (strcmp(c->entries[i].name, name) == 0)
            return c->entries[i].count;
    return 0;
}

/* Iter callback that writes module rows */
typedef struct {
    char        *buf;
    size_t       cap;
    size_t      *off;
    path_count_ctx_t *paths;
} mod_render_ctx_t;

static void mod_render_cb(const char *name, const char *version, int loaded,
                          uint64_t msg_count, uint64_t last_msg_us, void *ud)
{
    mod_render_ctx_t *c = ud;
    if (msg_count == 0) return;  /* Only show active modules */
    double rate = compute_mod_rate(name, msg_count);
    int paths = find_path_count(c->paths, name);
    char ago[16] = "-";
    if (last_msg_us > 0) {
        uint64_t now_us = (uint64_t)time(NULL) * 1000000ULL;
        long long age_s = ((long long)now_us - (long long)last_msg_us) / 1000000;
        if (age_s < 0) age_s = 0;
        if (age_s < 60) snprintf(ago, sizeof(ago), "%llds", (long long)age_s);
        else if (age_s < 3600) snprintf(ago, sizeof(ago), "%lldm", (long long)age_s / 60);
        else snprintf(ago, sizeof(ago), "%lldh", (long long)age_s / 3600);
    }
    *c->off += (size_t)snprintf(c->buf + *c->off, c->cap - *c->off,
        "  %-16s %-8s %s %5d %10llu %9.1f  %s\n",
        name, version[0] ? version : "-",
        loaded ? "OK " : "off",
        paths, (unsigned long long)msg_count, rate, ago);
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
    core->path_set_description(core, "/process/resources/status", "Process executor: allowed commands, timeout");
    core->path_register(core, "/process/resources/allowed", "process");
    core->path_set_access(core, "/process/resources/allowed", PORTAL_ACCESS_READ);
    core->path_register(core, "/process/resources/list", "process");
    core->path_set_access(core, "/process/resources/list", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/process/resources/list", "List running system processes");
    core->path_register(core, "/process/resources/top", "process");
    core->path_set_access(core, "/process/resources/top", PORTAL_ACCESS_READ);
    core->path_register(core, "/process/resources/threads", "process");
    core->path_set_access(core, "/process/resources/threads", PORTAL_ACCESS_READ);
    core->path_register(core, "/process/resources/self", "process");
    core->path_set_access(core, "/process/resources/self", PORTAL_ACCESS_READ);
    core->path_register(core, "/process/resources/portal_top", "process");
    core->path_set_access(core, "/process/resources/portal_top", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/process/resources/portal_top", "Portal-internal process viewer: modules, threads, msg rate");
    core->path_register(core, "/process/functions/exec", "process");
    core->path_set_access(core, "/process/functions/exec", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/process/functions/exec", "Execute system command (sandboxed). Header: cmd");
    core->path_add_label(core, "/process/functions/exec", "admin");

    /* Init /proc introspection state */
    long pgsz = sysconf(_SC_PAGESIZE);
    g_page_kb = pgsz > 0 ? pgsz / 1024 : 4;
    g_mem_total_kb = read_mem_total_kb();
    g_prev_count = 0;
    g_prev_total_jiffies = 0;

    core->log(core, PORTAL_LOG_INFO, "process",
              "Process executor ready (%d allowed commands, timeout: %ds)",
              g_allowed_count, g_timeout);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/process/resources/status");
    core->path_unregister(core, "/process/resources/allowed");
    core->path_unregister(core, "/process/resources/list");
    core->path_unregister(core, "/process/resources/top");
    core->path_unregister(core, "/process/resources/threads");
    core->path_unregister(core, "/process/resources/self");
    core->path_unregister(core, "/process/resources/portal_top");
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

    /* --- /process/resources/portal_top — Portal-internal view --- */
    if (strcmp(msg->path, "/process/resources/portal_top") == 0) {
        size_t outcap = 32 * 1024;
        char *out = malloc(outcap);
        if (!out) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            return -1;
        }
        size_t off = 0;

        /* --- Portal process header --- */
        int self_pid = (int)getpid();
        proc_sample_t me;
        memset(&me, 0, sizeof(me));
        read_pid_stat(self_pid, &me);

        /* CPU% for portal as a whole */
        unsigned long long total_j = read_total_jiffies();
        double portal_cpu = 0.0;
        if (g_thr_prev_total > 0 && total_j > g_thr_prev_total &&
            me.utime >= g_portal_prev_utime && me.stime >= g_portal_prev_stime) {
            unsigned long long total_d = total_j - g_thr_prev_total;
            unsigned long du = me.utime - g_portal_prev_utime;
            unsigned long ds = me.stime - g_portal_prev_stime;
            if (total_d > 0)
                portal_cpu = 100.0 * (double)(du + ds) / (double)total_d;
        }

        long rss_kb = me.rss_pages * g_page_kb;
        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);

        off += (size_t)snprintf(out + off, outcap - off,
            "Portal  pid=%d  rss=%ld kB  vsz=%lu kB  cpu=%.1f%%  state=%c  %02d:%02d:%02d\n\n",
            me.pid, rss_kb, me.vsize / 1024, portal_cpu, me.state,
            tm.tm_hour, tm.tm_min, tm.tm_sec);

        /* --- Modules table --- */
        path_count_ctx_t pc;
        pc.n = 0;
        if (core->path_iter)
            core->path_iter(core, path_count_cb, &pc);

        off += (size_t)snprintf(out + off, outcap - off,
            "MODULES\n"
            "  %-16s %-8s %-3s %5s %10s %9s  %s\n",
            "NAME", "VER", "ST", "PATHS", "MSGS", "MSG/MIN", "LAST");

        if (core->module_iter) {
            mod_render_ctx_t mctx = { out, outcap, &off, &pc };
            core->module_iter(core, mod_render_cb, &mctx);
        }

        /* --- Threads of portal --- */
        proc_sample_t thr[256];
        int tn = enumerate_threads(self_pid, thr, 256);

        /* CPU% per thread vs g_thr_prev */
        unsigned long long total_d = (g_thr_prev_total > 0 && total_j > g_thr_prev_total)
                                     ? (total_j - g_thr_prev_total) : 0;
        for (int i = 0; i < tn; i++) {
            thr[i].cpu_pct = 0.0;
            if (total_d == 0) continue;
            for (int j = 0; j < g_thr_prev_count; j++) {
                if (g_thr_prev[j].pid == thr[i].pid) {
                    if (thr[i].utime >= g_thr_prev[j].utime &&
                        thr[i].stime >= g_thr_prev[j].stime) {
                        unsigned long du = thr[i].utime - g_thr_prev[j].utime;
                        unsigned long ds = thr[i].stime - g_thr_prev[j].stime;
                        thr[i].cpu_pct = 100.0 * (double)(du + ds) / (double)total_d;
                    }
                    break;
                }
            }
            /* Replace comm with /proc/self/task/<tid>/comm — actual thread name */
            read_thread_name(thr[i].pid, thr[i].comm, sizeof(thr[i].comm));
        }

        /* Save snapshot for next call */
        int keep = tn < 256 ? tn : 256;
        memcpy(g_thr_prev, thr, (size_t)keep * sizeof(proc_sample_t));
        g_thr_prev_count = keep;
        g_thr_prev_total = total_j;
        g_portal_prev_utime = me.utime;
        g_portal_prev_stime = me.stime;

        off += (size_t)snprintf(out + off, outcap - off,
            "\nTHREADS  (%d)\n"
            "    TID  S    CPU%%  NAME\n", tn);
        for (int i = 0; i < tn && off < outcap - 128; i++)
            off += (size_t)snprintf(out + off, outcap - off,
                "  %5d  %c  %6.1f  %s\n",
                thr[i].pid, thr[i].state, thr[i].cpu_pct, thr[i].comm);

        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, out, off);
        free(out);
        return 0;
    }

    /* --- /process/resources/list | top | threads | self --- */
    if (strcmp(msg->path, "/process/resources/list") == 0 ||
        strcmp(msg->path, "/process/resources/top")  == 0 ||
        strcmp(msg->path, "/process/resources/threads") == 0 ||
        strcmp(msg->path, "/process/resources/self") == 0) {

        int is_top     = (strcmp(msg->path, "/process/resources/top") == 0);
        int is_threads = (strcmp(msg->path, "/process/resources/threads") == 0);
        int is_self    = (strcmp(msg->path, "/process/resources/self") == 0);

        const char *sort_h = get_hdr(msg, "sort");
        const char *n_h    = get_hdr(msg, "n");
        const char *pid_h  = get_hdr(msg, "pid");
        int limit = is_top ? 20 : PROC_MAX_SAMPLES;
        if (n_h) { int v = atoi(n_h); if (v > 0 && v < PROC_MAX_SAMPLES) limit = v; }

        proc_sample_t *cur = calloc(PROC_MAX_SAMPLES, sizeof(proc_sample_t));
        if (!cur) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            return -1;
        }
        int count;
        if (is_threads) {
            int target = pid_h ? atoi(pid_h) : (int)getpid();
            count = enumerate_threads(target, cur, PROC_MAX_SAMPLES);
        } else if (is_self) {
            count = enumerate_threads((int)getpid(), cur, PROC_MAX_SAMPLES);
        } else {
            count = enumerate_pids(cur, PROC_MAX_SAMPLES);
        }

        unsigned long long total_j = read_total_jiffies();
        if (!is_threads && !is_self)
            compute_cpu_pct(cur, count, total_j);

        /* Sort */
        int (*cmp)(const void *, const void *) = cmp_cpu;
        if (sort_h) {
            if (strcmp(sort_h, "mem") == 0) cmp = cmp_mem;
            else if (strcmp(sort_h, "pid") == 0) cmp = cmp_pid;
        }
        if (is_top) qsort(cur, (size_t)count, sizeof(proc_sample_t), cmp);

        size_t outcap = 64 * 1024;
        char *out = malloc(outcap);
        if (!out) { free(cur); portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR); return -1; }
        size_t off = 0;

        if (is_self) {
            int self_pid = (int)getpid();
            proc_sample_t me;
            memset(&me, 0, sizeof(me));
            read_pid_stat(self_pid, &me);
            long rss_kb = me.rss_pages * g_page_kb;
            off += (size_t)snprintf(out + off, outcap - off,
                "Portal self:\n"
                "  PID:        %d\n"
                "  PPID:       %d\n"
                "  State:      %c\n"
                "  RSS:        %ld kB\n"
                "  VSize:      %lu kB\n"
                "  Comm:       %s\n"
                "  Threads:    %d\n\n",
                me.pid, me.ppid, me.state, rss_kb,
                me.vsize / 1024, me.comm, count);
        }

        off += (size_t)snprintf(out + off, outcap - off, "%s", row_header());
        int shown = count < limit ? count : limit;
        for (int i = 0; i < shown && off < outcap - PROC_LINE_LEN; i++)
            off += format_row(out + off, outcap - off, &cur[i]);

        if (shown < count)
            off += (size_t)snprintf(out + off, outcap - off,
                "... (%d more)\n", count - shown);

        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, out, off);
        free(cur);
        free(out);
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
