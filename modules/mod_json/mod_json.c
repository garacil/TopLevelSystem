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
 * mod_json — JSON response formatter
 *
 * Provides JSON building and parsing via paths.
 * When loaded, HTTP API can return JSON with ?format=json.
 *
 * Config:
 *   [mod_json]
 *   pretty = true
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "portal/portal.h"

static portal_core_t *g_core = NULL;
static int g_pretty = 0;

static portal_module_info_t info = {
    .name = "json", .version = "1.0.0",
    .description = "JSON response formatter",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

/* --- JSON builder helpers --- */

/* Escape a string for JSON (handle \n, \t, \", \\) */
static size_t json_escape(const char *in, size_t in_len, char *out, size_t out_len)
{
    size_t o = 0;
    for (size_t i = 0; i < in_len && o < out_len - 2; i++) {
        switch (in[i]) {
        case '"':  out[o++] = '\\'; out[o++] = '"'; break;
        case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
        case '\n': out[o++] = '\\'; out[o++] = 'n'; break;
        case '\r': out[o++] = '\\'; out[o++] = 'r'; break;
        case '\t': out[o++] = '\\'; out[o++] = 't'; break;
        case '\0': goto done;
        default:
            if ((unsigned char)in[i] >= 32)
                out[o++] = in[i];
            break;
        }
    }
done:
    out[o] = '\0';
    return o;
}

/* Build a JSON response wrapping portal data */
static int json_wrap(const char *path, int status, const char *data,
                      size_t data_len, char *out, size_t out_len)
{
    char escaped[16384];
    size_t dlen = data_len;
    /* Strip null terminator */
    if (dlen > 0 && data[dlen - 1] == '\0') dlen--;
    json_escape(data, dlen, escaped, sizeof(escaped));

    int64_t ts = (int64_t)time(NULL);

    if (g_pretty) {
        return snprintf(out, out_len,
            "{\n"
            "  \"status\": %d,\n"
            "  \"path\": \"%s\",\n"
            "  \"timestamp\": %lld,\n"
            "  \"data\": \"%s\"\n"
            "}\n",
            status, path, (long long)ts, escaped);
    }
    return snprintf(out, out_len,
        "{\"status\":%d,\"path\":\"%s\",\"timestamp\":%lld,\"data\":\"%s\"}\n",
        status, path, (long long)ts, escaped);
}

/* --- Module lifecycle --- */

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    const char *v = core->config_get(core, "json", "pretty");
    if (v && (strcmp(v, "true") == 0 || strcmp(v, "1") == 0))
        g_pretty = 1;

    core->path_register(core, "/json/resources/status", "json");
    core->path_set_access(core, "/json/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/json/resources/status", "JSON formatter status");
    core->path_register(core, "/json/functions/format", "json");
    core->path_set_access(core, "/json/functions/format", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/json/functions/format", "Format path response as JSON. Header: path");
    core->path_register(core, "/json/functions/wrap", "json");
    core->path_set_access(core, "/json/functions/wrap", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "json",
              "JSON formatter ready (pretty: %s)", g_pretty ? "on" : "off");
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/json/resources/status");
    core->path_unregister(core, "/json/functions/format");
    core->path_unregister(core, "/json/functions/wrap");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0)
            return msg->headers[i].value;
    return NULL;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[32768];
    int n;

    if (strcmp(msg->path, "/json/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "JSON Formatter\nPretty: %s\n", g_pretty ? "on" : "off");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* /json/functions/format — wrap raw text as JSON */
    if (strcmp(msg->path, "/json/functions/format") == 0) {
        const char *data = msg->body ? msg->body : "";
        size_t dlen = msg->body_len;
        n = json_wrap("/json/functions/format", 200, data, dlen, buf, sizeof(buf));
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* /json/functions/wrap — query a path and return its response as JSON */
    if (strcmp(msg->path, "/json/functions/wrap") == 0) {
        const char *path = get_hdr(msg, "path");
        if (!path) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "{\"error\":\"need path header\"}\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }

        /* Query the target path */
        portal_msg_t *qm = portal_msg_alloc();
        portal_resp_t *qr = portal_resp_alloc();
        if (qm && qr) {
            portal_msg_set_path(qm, path);
            portal_msg_set_method(qm, PORTAL_METHOD_GET);
            core->send(core, qm, qr);

            const char *data = qr->body ? qr->body : "";
            n = json_wrap(path, qr->status, data, qr->body_len, buf, sizeof(buf));
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, buf, (size_t)n);

            portal_msg_free(qm);
            portal_resp_free(qr);
        }
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
