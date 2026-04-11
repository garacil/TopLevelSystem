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
 * mod_crypto — Cryptographic utilities
 *
 * Hash functions (SHA-256, MD5), Base64 encode/decode,
 * hex encode/decode. Uses embedded SHA-256, libc for MD5.
 *
 * Config:
 *   [mod_crypto]
 *   (none required)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "portal/portal.h"

/* Embedded SHA-256 from lib/sha256 */
#include "sha256.h"

static portal_core_t *g_core = NULL;
static int64_t g_operations = 0;

static portal_module_info_t info = {
    .name = "crypto", .version = "1.0.0",
    .description = "Cryptographic utilities (hash, base64, hex)",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

/* Hex encode */
static void hex_encode(const unsigned char *in, size_t inlen, char *out)
{
    for (size_t i = 0; i < inlen; i++)
        sprintf(out + i * 2, "%02x", in[i]);
    out[inlen * 2] = '\0';
}

/* Hex decode */
static int hex_decode(const char *in, unsigned char *out, size_t *outlen)
{
    size_t len = strlen(in);
    if (len % 2 != 0) return -1;
    *outlen = len / 2;
    for (size_t i = 0; i < *outlen; i++) {
        unsigned int byte;
        if (sscanf(in + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (unsigned char)byte;
    }
    return 0;
}

/* Base64 tables */
static const char b64_enc[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const unsigned char *in, size_t inlen,
                           char *out, size_t *outlen)
{
    size_t i, j = 0;
    for (i = 0; i + 2 < inlen; i += 3) {
        out[j++] = b64_enc[(in[i] >> 2) & 0x3F];
        out[j++] = b64_enc[((in[i] & 0x3) << 4) | ((in[i+1] >> 4) & 0xF)];
        out[j++] = b64_enc[((in[i+1] & 0xF) << 2) | ((in[i+2] >> 6) & 0x3)];
        out[j++] = b64_enc[in[i+2] & 0x3F];
    }
    if (i < inlen) {
        out[j++] = b64_enc[(in[i] >> 2) & 0x3F];
        if (i + 1 < inlen) {
            out[j++] = b64_enc[((in[i] & 0x3) << 4) | ((in[i+1] >> 4) & 0xF)];
            out[j++] = b64_enc[(in[i+1] & 0xF) << 2];
        } else {
            out[j++] = b64_enc[(in[i] & 0x3) << 4];
            out[j++] = '=';
        }
        out[j++] = '=';
    }
    out[j] = '\0';
    *outlen = j;
}

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int base64_decode(const char *in, size_t inlen,
                          unsigned char *out, size_t *outlen)
{
    if (inlen % 4 != 0) return -1;
    size_t j = 0;
    for (size_t i = 0; i < inlen; i += 4) {
        int a = b64_val(in[i]);
        int b = b64_val(in[i+1]);
        int c = (in[i+2] == '=') ? 0 : b64_val(in[i+2]);
        int d = (in[i+3] == '=') ? 0 : b64_val(in[i+3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) return -1;
        out[j++] = (unsigned char)((a << 2) | (b >> 4));
        if (in[i+2] != '=') out[j++] = (unsigned char)((b << 4) | (c >> 2));
        if (in[i+3] != '=') out[j++] = (unsigned char)((c << 6) | d);
    }
    *outlen = j;
    return 0;
}

/* Simple MD5 (RFC 1321 implementation) */
static void md5_transform(uint32_t state[4], const uint8_t block[64]);

static void md5_hash(const void *data, size_t len, unsigned char hash[16])
{
    uint32_t state[4] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};
    const uint8_t *p = (const uint8_t *)data;
    size_t i;

    for (i = 0; i + 64 <= len; i += 64)
        md5_transform(state, p + i);

    uint8_t buf[128];
    size_t rem = len - i;
    memcpy(buf, p + i, rem);
    buf[rem++] = 0x80;
    while (rem % 64 != 56) buf[rem++] = 0;
    uint64_t bits = (uint64_t)len * 8;
    memcpy(buf + rem, &bits, 8);
    rem += 8;
    for (size_t j = 0; j < rem; j += 64)
        md5_transform(state, buf + j);

    memcpy(hash, state, 16);
}

#define F(x,y,z) (((x)&(y))|((~x)&(z)))
#define G(x,y,z) (((x)&(z))|((y)&(~z)))
#define H(x,y,z) ((x)^(y)^(z))
#define I(x,y,z) ((y)^((x)|(~z)))
#define ROT(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define STEP(f,a,b,c,d,x,t,s) (a)+=f((b),(c),(d))+(x)+(t);(a)=ROT((a),(s));(a)+=(b)

static void md5_transform(uint32_t state[4], const uint8_t block[64])
{
    uint32_t a=state[0], b=state[1], c=state[2], d=state[3];
    uint32_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1]<<8) |
               ((uint32_t)block[i*4+2]<<16) | ((uint32_t)block[i*4+3]<<24);

    STEP(F,a,b,c,d,M[0], 0xd76aa478,7);  STEP(F,d,a,b,c,M[1], 0xe8c7b756,12);
    STEP(F,c,d,a,b,M[2], 0x242070db,17); STEP(F,b,c,d,a,M[3], 0xc1bdceee,22);
    STEP(F,a,b,c,d,M[4], 0xf57c0faf,7);  STEP(F,d,a,b,c,M[5], 0x4787c62a,12);
    STEP(F,c,d,a,b,M[6], 0xa8304613,17); STEP(F,b,c,d,a,M[7], 0xfd469501,22);
    STEP(F,a,b,c,d,M[8], 0x698098d8,7);  STEP(F,d,a,b,c,M[9], 0x8b44f7af,12);
    STEP(F,c,d,a,b,M[10],0xffff5bb1,17); STEP(F,b,c,d,a,M[11],0x895cd7be,22);
    STEP(F,a,b,c,d,M[12],0x6b901122,7);  STEP(F,d,a,b,c,M[13],0xfd987193,12);
    STEP(F,c,d,a,b,M[14],0xa679438e,17); STEP(F,b,c,d,a,M[15],0x49b40821,22);

    STEP(G,a,b,c,d,M[1], 0xf61e2562,5);  STEP(G,d,a,b,c,M[6], 0xc040b340,9);
    STEP(G,c,d,a,b,M[11],0x265e5a51,14); STEP(G,b,c,d,a,M[0], 0xe9b6c7aa,20);
    STEP(G,a,b,c,d,M[5], 0xd62f105d,5);  STEP(G,d,a,b,c,M[10],0x02441453,9);
    STEP(G,c,d,a,b,M[15],0xd8a1e681,14); STEP(G,b,c,d,a,M[4], 0xe7d3fbc8,20);
    STEP(G,a,b,c,d,M[9], 0x21e1cde6,5);  STEP(G,d,a,b,c,M[14],0xc33707d6,9);
    STEP(G,c,d,a,b,M[3], 0xf4d50d87,14); STEP(G,b,c,d,a,M[8], 0x455a14ed,20);
    STEP(G,a,b,c,d,M[13],0xa9e3e905,5);  STEP(G,d,a,b,c,M[2], 0xfcefa3f8,9);
    STEP(G,c,d,a,b,M[7], 0x676f02d9,14); STEP(G,b,c,d,a,M[12],0x8d2a4c8a,20);

    STEP(H,a,b,c,d,M[5], 0xfffa3942,4);  STEP(H,d,a,b,c,M[8], 0x8771f681,11);
    STEP(H,c,d,a,b,M[11],0x6d9d6122,16); STEP(H,b,c,d,a,M[14],0xfde5380c,23);
    STEP(H,a,b,c,d,M[1], 0xa4beea44,4);  STEP(H,d,a,b,c,M[4], 0x4bdecfa9,11);
    STEP(H,c,d,a,b,M[7], 0xf6bb4b60,16); STEP(H,b,c,d,a,M[10],0xbebfbc70,23);
    STEP(H,a,b,c,d,M[13],0x289b7ec6,4);  STEP(H,d,a,b,c,M[0], 0xeaa127fa,11);
    STEP(H,c,d,a,b,M[3], 0xd4ef3085,16); STEP(H,b,c,d,a,M[6], 0x04881d05,23);
    STEP(H,a,b,c,d,M[9], 0xd9d4d039,4);  STEP(H,d,a,b,c,M[12],0xe6db99e5,11);
    STEP(H,c,d,a,b,M[15],0x1fa27cf8,16); STEP(H,b,c,d,a,M[2], 0xc4ac5665,23);

    STEP(I,a,b,c,d,M[0], 0xf4292244,6);  STEP(I,d,a,b,c,M[7], 0x432aff97,10);
    STEP(I,c,d,a,b,M[14],0xab9423a7,15); STEP(I,b,c,d,a,M[5], 0xfc93a039,21);
    STEP(I,a,b,c,d,M[12],0x655b59c3,6);  STEP(I,d,a,b,c,M[3], 0x8f0ccc92,10);
    STEP(I,c,d,a,b,M[10],0xffeff47d,15); STEP(I,b,c,d,a,M[1], 0x85845dd1,21);
    STEP(I,a,b,c,d,M[8], 0x6fa87e4f,6);  STEP(I,d,a,b,c,M[15],0xfe2ce6e0,10);
    STEP(I,c,d,a,b,M[6], 0xa3014314,15); STEP(I,b,c,d,a,M[13],0x4e0811a1,21);
    STEP(I,a,b,c,d,M[4], 0xf7537e82,6);  STEP(I,d,a,b,c,M[11],0xbd3af235,10);
    STEP(I,c,d,a,b,M[2], 0x2ad7d2bb,15); STEP(I,b,c,d,a,M[9], 0xeb86d391,21);

    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_operations = 0;

    core->path_register(core, "/crypto/resources/status", "crypto");
    core->path_set_access(core, "/crypto/resources/status", PORTAL_ACCESS_READ);
    core->path_register(core, "/crypto/functions/sha256", "crypto");
    core->path_set_access(core, "/crypto/functions/sha256", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/crypto/functions/sha256", "SHA-256 hash. Body: data to hash");
    core->path_register(core, "/crypto/functions/md5", "crypto");
    core->path_set_access(core, "/crypto/functions/md5", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/crypto/functions/md5", "MD5 hash. Body: data to hash");
    core->path_register(core, "/crypto/functions/base64enc", "crypto");
    core->path_set_access(core, "/crypto/functions/base64enc", PORTAL_ACCESS_RW);
    core->path_register(core, "/crypto/functions/base64dec", "crypto");
    core->path_set_access(core, "/crypto/functions/base64dec", PORTAL_ACCESS_RW);
    core->path_register(core, "/crypto/functions/hexenc", "crypto");
    core->path_set_access(core, "/crypto/functions/hexenc", PORTAL_ACCESS_RW);
    core->path_register(core, "/crypto/functions/hexdec", "crypto");
    core->path_set_access(core, "/crypto/functions/hexdec", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "crypto",
              "Crypto utilities ready (SHA-256, MD5, Base64, Hex)");
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/crypto/resources/status");
    core->path_unregister(core, "/crypto/functions/sha256");
    core->path_unregister(core, "/crypto/functions/md5");
    core->path_unregister(core, "/crypto/functions/base64enc");
    core->path_unregister(core, "/crypto/functions/base64dec");
    core->path_unregister(core, "/crypto/functions/hexenc");
    core->path_unregister(core, "/crypto/functions/hexdec");
    core->log(core, PORTAL_LOG_INFO, "crypto", "Crypto utilities unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;
    char buf[8192];
    int n;

    if (strcmp(msg->path, "/crypto/resources/status") == 0) {
        n = snprintf(buf, sizeof(buf),
            "Crypto Utilities\n"
            "Algorithms: SHA-256, MD5, Base64, Hex\n"
            "Operations: %lld\n", (long long)g_operations);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/crypto/functions/sha256") == 0) {
        const char *data = get_hdr(msg, "data");
        if (!data && msg->body) data = msg->body;
        if (!data) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: data header or body\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        char hex[65];
        sha256_hex((const uint8_t *)data, strlen(data), hex);
        g_operations++;
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "%s\n", hex);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/crypto/functions/md5") == 0) {
        const char *data = get_hdr(msg, "data");
        if (!data && msg->body) data = msg->body;
        if (!data) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: data header or body\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        unsigned char hash[16];
        md5_hash(data, strlen(data), hash);
        char hex[33];
        hex_encode(hash, 16, hex);
        g_operations++;
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "%s\n", hex);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/crypto/functions/base64enc") == 0) {
        const char *data = get_hdr(msg, "data");
        if (!data && msg->body) data = msg->body;
        if (!data) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
        char out[8192];
        size_t olen;
        base64_encode((const unsigned char *)data, strlen(data), out, &olen);
        g_operations++;
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "%s\n", out);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/crypto/functions/base64dec") == 0) {
        const char *data = get_hdr(msg, "data");
        if (!data && msg->body) data = msg->body;
        if (!data) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
        unsigned char out[8192];
        size_t olen;
        if (base64_decode(data, strlen(data), out, &olen) < 0) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Invalid base64 input\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        out[olen] = '\0';
        g_operations++;
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, out, olen);
        return 0;
    }

    if (strcmp(msg->path, "/crypto/functions/hexenc") == 0) {
        const char *data = get_hdr(msg, "data");
        if (!data && msg->body) data = msg->body;
        if (!data) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
        char hex[8192];
        hex_encode((const unsigned char *)data, strlen(data), hex);
        g_operations++;
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "%s\n", hex);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/crypto/functions/hexdec") == 0) {
        const char *data = get_hdr(msg, "data");
        if (!data && msg->body) data = msg->body;
        if (!data) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            return -1;
        }
        unsigned char out[4096];
        size_t olen;
        if (hex_decode(data, out, &olen) < 0) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Invalid hex input\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        out[olen] = '\0';
        g_operations++;
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, out, olen);
        return 0;
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
