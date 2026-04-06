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
 * mod_validator — Input validation utilities
 *
 * Validate common input formats: email, IP, URL, JSON,
 * number ranges, string patterns, regex matching.
 *
 * Config:
 *   [mod_validator]
 *   (none required)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <regex.h>
#include "portal/portal.h"

static portal_core_t *g_core = NULL;
static int64_t g_validations = 0;
static int64_t g_passed = 0;
static int64_t g_failed = 0;

static portal_module_info_t info = {
    .name = "validator", .version = "1.0.0",
    .description = "Input validation utilities",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

static int validate_email(const char *email)
{
    const char *at = strchr(email, '@');
    if (!at || at == email) return 0;
    const char *dot = strchr(at, '.');
    if (!dot || dot == at + 1 || *(dot + 1) == '\0') return 0;
    /* No spaces */
    for (const char *p = email; *p; p++)
        if (*p == ' ') return 0;
    return 1;
}

static int validate_ipv4(const char *ip)
{
    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr) == 1;
}

static int validate_ipv6(const char *ip)
{
    struct in6_addr addr;
    return inet_pton(AF_INET6, ip, &addr) == 1;
}

static int validate_url(const char *url)
{
    if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0)
        return 0;
    const char *host = strchr(url + 8, '/');
    /* At least have a host part */
    if (url[7] == '/' && url[8] == '\0') return 0;
    (void)host;
    return strlen(url) > 10;
}

static int validate_json(const char *json)
{
    if (!json || json[0] == '\0') return 0;
    /* Skip whitespace */
    while (*json == ' ' || *json == '\t' || *json == '\n') json++;
    /* Must start with { or [ */
    if (*json != '{' && *json != '[') return 0;
    /* Must end with } or ] */
    const char *end = json + strlen(json) - 1;
    while (end > json && (*end == ' ' || *end == '\t' || *end == '\n')) end--;
    if ((*json == '{' && *end != '}') || (*json == '[' && *end != ']'))
        return 0;
    /* Check balanced braces/brackets */
    int brace = 0, bracket = 0;
    int in_string = 0;
    for (const char *p = json; *p; p++) {
        if (*p == '"' && (p == json || *(p-1) != '\\')) in_string = !in_string;
        if (in_string) continue;
        if (*p == '{') brace++;
        if (*p == '}') brace--;
        if (*p == '[') bracket++;
        if (*p == ']') bracket--;
        if (brace < 0 || bracket < 0) return 0;
    }
    return brace == 0 && bracket == 0;
}

static int validate_number(const char *val, const char *min_s, const char *max_s)
{
    char *end;
    double num = strtod(val, &end);
    if (*end != '\0') return 0;
    if (min_s) { double mn = strtod(min_s, NULL); if (num < mn) return 0; }
    if (max_s) { double mx = strtod(max_s, NULL); if (num > mx) return 0; }
    return 1;
}

static int validate_regex(const char *data, const char *pattern)
{
    regex_t re;
    if (regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB) != 0) return -1;
    int rc = regexec(&re, data, 0, NULL, 0);
    regfree(&re);
    return rc == 0 ? 1 : 0;
}

static int validate_hostname(const char *host)
{
    size_t len = strlen(host);
    if (len == 0 || len > 253) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = host[i];
        if (!isalnum((unsigned char)c) && c != '-' && c != '.') return 0;
    }
    if (host[0] == '-' || host[len-1] == '-') return 0;
    return 1;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_validations = g_passed = g_failed = 0;

    core->path_register(core, "/validator/resources/status", "validator");
    core->path_set_access(core, "/validator/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/validator/functions/email", "validator");
    core->path_set_access(core, "/validator/functions/email", PORTAL_ACCESS_RW);
    core->path_register(core, "/validator/functions/ip", "validator");
    core->path_set_access(core, "/validator/functions/ip", PORTAL_ACCESS_RW);
    core->path_register(core, "/validator/functions/url", "validator");
    core->path_set_access(core, "/validator/functions/url", PORTAL_ACCESS_RW);
    core->path_register(core, "/validator/functions/json", "validator");
    core->path_set_access(core, "/validator/functions/json", PORTAL_ACCESS_RW);
    core->path_register(core, "/validator/functions/number", "validator");
    core->path_set_access(core, "/validator/functions/number", PORTAL_ACCESS_RW);
    core->path_register(core, "/validator/functions/regex", "validator");
    core->path_set_access(core, "/validator/functions/regex", PORTAL_ACCESS_RW);
    core->path_register(core, "/validator/functions/hostname", "validator");
    core->path_set_access(core, "/validator/functions/hostname", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "validator", "Input validator ready");
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/validator/resources/status");
    core->path_unregister(core, "/validator/functions/email");
    core->path_unregister(core, "/validator/functions/ip");
    core->path_unregister(core, "/validator/functions/url");
    core->path_unregister(core, "/validator/functions/json");
    core->path_unregister(core, "/validator/functions/number");
    core->path_unregister(core, "/validator/functions/regex");
    core->path_unregister(core, "/validator/functions/hostname");
    core->log(core, PORTAL_LOG_INFO, "validator", "Validator unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

#define RESULT(ok, fmt, ...) do { \
    g_validations++; \
    if (ok) { g_passed++; portal_resp_set_status(resp, PORTAL_OK); } \
    else { g_failed++; portal_resp_set_status(resp, PORTAL_BAD_REQUEST); } \
    n = snprintf(buf, sizeof(buf), fmt, ##__VA_ARGS__); \
    portal_resp_set_body(resp, buf, (size_t)n); \
    return 0; \
} while(0)

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;
    char buf[4096];
    int n;

    if (strcmp(msg->path, "/validator/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "Input Validator\n"
            "Types: email, ip, url, json, number, regex, hostname\n"
            "Validations: %lld (passed: %lld, failed: %lld)\n",
            (long long)g_validations, (long long)g_passed, (long long)g_failed);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/validator/functions/email") == 0) {
        const char *val = get_hdr(msg, "value");
        if (!val) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        int ok = validate_email(val);
        RESULT(ok, "%s: %s\n", ok ? "valid" : "invalid", val);
    }

    if (strcmp(msg->path, "/validator/functions/ip") == 0) {
        const char *val = get_hdr(msg, "value");
        if (!val) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        int v4 = validate_ipv4(val);
        int v6 = validate_ipv6(val);
        if (v4) RESULT(1, "valid IPv4: %s\n", val);
        if (v6) RESULT(1, "valid IPv6: %s\n", val);
        RESULT(0, "invalid IP: %s\n", val);
    }

    if (strcmp(msg->path, "/validator/functions/url") == 0) {
        const char *val = get_hdr(msg, "value");
        if (!val) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        int ok = validate_url(val);
        RESULT(ok, "%s: %s\n", ok ? "valid URL" : "invalid URL", val);
    }

    if (strcmp(msg->path, "/validator/functions/json") == 0) {
        const char *val = msg->body ? msg->body : get_hdr(msg, "value");
        if (!val) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        int ok = validate_json(val);
        RESULT(ok, "%s JSON\n", ok ? "valid" : "invalid");
    }

    if (strcmp(msg->path, "/validator/functions/number") == 0) {
        const char *val = get_hdr(msg, "value");
        const char *min = get_hdr(msg, "min");
        const char *max = get_hdr(msg, "max");
        if (!val) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        int ok = validate_number(val, min, max);
        RESULT(ok, "%s: %s%s%s%s%s\n",
               ok ? "valid" : "invalid", val,
               min ? " (min=" : "", min ? min : "",
               max ? " max=" : "", max ? max : "");
    }

    if (strcmp(msg->path, "/validator/functions/regex") == 0) {
        const char *val = get_hdr(msg, "value");
        const char *pattern = get_hdr(msg, "pattern");
        if (!val || !pattern) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: value, pattern headers\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        int rc = validate_regex(val, pattern);
        if (rc < 0) RESULT(0, "invalid regex pattern: %s\n", pattern);
        RESULT(rc, "%s: '%s' vs /%s/\n", rc ? "match" : "no match", val, pattern);
    }

    if (strcmp(msg->path, "/validator/functions/hostname") == 0) {
        const char *val = get_hdr(msg, "value");
        if (!val) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        int ok = validate_hostname(val);
        RESULT(ok, "%s hostname: %s\n", ok ? "valid" : "invalid", val);
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
