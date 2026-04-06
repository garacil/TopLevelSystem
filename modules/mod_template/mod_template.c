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
 * mod_template — Template rendering engine
 *
 * Load templates from files, render with variable substitution.
 * Syntax: {{variable}} gets replaced with provided values.
 * Templates are cached in memory after first load.
 *
 * Config:
 *   [mod_template]
 *   template_dir = /var/lib/portal/templates
 *   max_templates = 256
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include "portal/portal.h"

#define TPL_MAX       256
#define TPL_MAX_SIZE  (64 * 1024)  /* 64 KB per template */
#define TPL_OUT_SIZE  (128 * 1024) /* 128 KB max output */
#define TPL_MAX_VARS  64

typedef struct {
    char  name[128];
    char *content;
    size_t len;
    int   active;
} template_t;

static portal_core_t *g_core = NULL;
static template_t     g_templates[TPL_MAX];
static int            g_count = 0;
static int            g_max = TPL_MAX;
static char           g_dir[512] = "/var/lib/portal/templates";
static int64_t        g_renders = 0;

static portal_module_info_t info = {
    .name = "template", .version = "1.0.0",
    .description = "Template rendering engine ({{var}} syntax)",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

static template_t *find_template(const char *name)
{
    for (int i = 0; i < g_count; i++)
        if (g_templates[i].active && strcmp(g_templates[i].name, name) == 0)
            return &g_templates[i];
    return NULL;
}

static template_t *load_template(const char *name)
{
    template_t *t = find_template(name);
    if (t) return t;

    if (g_count >= g_max) return NULL;

    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", g_dir, name);

    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || (size_t)sz > TPL_MAX_SIZE) { fclose(f); return NULL; }

    t = &g_templates[g_count++];
    snprintf(t->name, sizeof(t->name), "%s", name);
    t->content = malloc((size_t)sz + 1);
    t->len = fread(t->content, 1, (size_t)sz, f);
    t->content[t->len] = '\0';
    t->active = 1;
    fclose(f);
    return t;
}

/* Render template: replace {{key}} with value from headers */
static size_t render_template(const template_t *t, const portal_msg_t *msg,
                               char *out, size_t outlen)
{
    size_t opos = 0;
    const char *src = t->content;
    size_t slen = t->len;

    for (size_t i = 0; i < slen && opos < outlen - 1; ) {
        if (i + 3 < slen && src[i] == '{' && src[i + 1] == '{') {
            /* Find closing }} */
            const char *end = strstr(src + i + 2, "}}");
            if (end) {
                size_t klen = (size_t)(end - (src + i + 2));
                char key[256];
                if (klen < sizeof(key)) {
                    memcpy(key, src + i + 2, klen);
                    key[klen] = '\0';
                    /* Trim whitespace */
                    char *k = key;
                    while (*k == ' ') k++;
                    char *ke = k + strlen(k) - 1;
                    while (ke > k && *ke == ' ') *ke-- = '\0';

                    const char *val = get_hdr(msg, k);
                    if (val) {
                        size_t vlen = strlen(val);
                        if (opos + vlen < outlen - 1) {
                            memcpy(out + opos, val, vlen);
                            opos += vlen;
                        }
                    } else {
                        /* Keep original if no value */
                        size_t orig = klen + 4;
                        if (opos + orig < outlen - 1) {
                            memcpy(out + opos, src + i, orig);
                            opos += orig;
                        }
                    }
                    i = (size_t)(end - src) + 2;
                    continue;
                }
            }
        }
        out[opos++] = src[i++];
    }
    out[opos] = '\0';
    return opos;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_templates, 0, sizeof(g_templates));
    g_count = 0;
    g_renders = 0;

    const char *v;
    if ((v = core->config_get(core, "template", "template_dir")))
        snprintf(g_dir, sizeof(g_dir), "%s", v);
    if ((v = core->config_get(core, "template", "max_templates")))
        g_max = atoi(v);

    mkdir(g_dir, 0755);

    core->path_register(core, "/template/resources/status", "template");
    core->path_set_access(core, "/template/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/template/resources/list", "template");
    core->path_set_access(core, "/template/resources/list", PORTAL_ACCESS_READ);
    core->path_register(core, "/template/functions/render", "template");
    core->path_set_access(core, "/template/functions/render", PORTAL_ACCESS_RW);
    core->path_register(core, "/template/functions/reload", "template");
    core->path_set_access(core, "/template/functions/reload", PORTAL_ACCESS_RW);
    core->path_register(core, "/template/functions/store", "template");
    core->path_set_access(core, "/template/functions/store", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "template",
              "Template engine ready (dir: %s, max: %d)", g_dir, g_max);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    for (int i = 0; i < g_count; i++)
        if (g_templates[i].active) free(g_templates[i].content);

    core->path_unregister(core, "/template/resources/status");
    core->path_unregister(core, "/template/resources/list");
    core->path_unregister(core, "/template/functions/render");
    core->path_unregister(core, "/template/functions/reload");
    core->path_unregister(core, "/template/functions/store");
    core->log(core, PORTAL_LOG_INFO, "template", "Template engine unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[8192];
    int n;

    if (strcmp(msg->path, "/template/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "Template Engine\n"
            "Directory: %s\n"
            "Cached: %d / %d\n"
            "Renders: %lld\n",
            g_dir, g_count, g_max, (long long)g_renders);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/template/resources/list") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Templates:\n");

        /* List files in template dir */
        DIR *d = opendir(g_dir);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL && off < sizeof(buf) - 128) {
                if (ent->d_name[0] == '.') continue;
                int cached = find_template(ent->d_name) ? 1 : 0;
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "  %-30s %s\n", ent->d_name,
                    cached ? "(cached)" : "");
            }
            closedir(d);
        }
        /* Also show cached-only */
        for (int i = 0; i < g_count; i++) {
            if (g_templates[i].active)
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "  %-30s (cached, %zu bytes)\n",
                    g_templates[i].name, g_templates[i].len);
        }
        if (off < 20)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/template/functions/render") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) {
            /* Try inline template from body */
            if (msg->body && msg->body_len > 0) {
                template_t inline_tpl = {.content = msg->body, .len = msg->body_len};
                char *out = malloc(TPL_OUT_SIZE);
                size_t olen = render_template(&inline_tpl, msg, out, TPL_OUT_SIZE);
                g_renders++;
                portal_resp_set_status(resp, PORTAL_OK);
                portal_resp_set_body(resp, out, olen);
                free(out);
                return 0;
            }
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: name header or template in body\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        /* Reject path traversal */
        if (strstr(name, "..") || name[0] == '/') {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }

        template_t *t = load_template(name);
        if (!t) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            n = snprintf(buf, sizeof(buf), "Template not found: %s\n", name);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        char *out = malloc(TPL_OUT_SIZE);
        size_t olen = render_template(t, msg, out, TPL_OUT_SIZE);
        g_renders++;
        core->event_emit(core, "/events/template/render", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, out, olen);
        free(out);
        return 0;
    }

    if (strcmp(msg->path, "/template/functions/store") == 0) {
        const char *name = get_hdr(msg, "name");
        const char *content = msg->body;
        size_t clen = msg->body_len;
        if (!content) { content = get_hdr(msg, "content"); clen = content ? strlen(content) : 0; }
        if (!name || !content) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: name header + body or content header\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (strstr(name, "..") || name[0] == '/') {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", g_dir, name);
        FILE *f = fopen(path, "w");
        if (!f) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            return -1;
        }
        fwrite(content, 1, clen, f);
        fclose(f);

        /* Invalidate cache if exists */
        template_t *t = find_template(name);
        if (t) { free(t->content); t->active = 0; }

        core->event_emit(core, "/events/template/store", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_CREATED);
        n = snprintf(buf, sizeof(buf), "Template '%s' stored (%zu bytes)\n", name, clen);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/template/functions/reload") == 0) {
        for (int i = 0; i < g_count; i++) {
            if (g_templates[i].active) free(g_templates[i].content);
        }
        memset(g_templates, 0, sizeof(g_templates));
        g_count = 0;
        core->event_emit(core, "/events/template/reload", "all", 3);
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Template cache cleared\n");
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
