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
 * test_crypto.c — Unit tests for SHA-256, MD5, Base64, Hex
 *
 * Tests verify the embedded crypto implementations produce
 * correct output against known test vectors.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* SHA-256 from lib/sha256 */
#include "sha256.h"

/* ---- Test helpers ---- */

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    printf("test_%s... ", #name); \
    tests_run++; \
} while(0)

#define PASS() do { printf("OK\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

#define ASSERT_STR(a, b) do { \
    if (strcmp(a, b) != 0) { FAIL(b); return; } \
} while(0)

/* ---- Base64 (same impl as mod_crypto) ---- */

static const char b64_enc[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const uint8_t *in, size_t inlen, char *out, size_t *outlen)
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

/* Hex encode */
static void hex_encode(const uint8_t *in, size_t inlen, char *out)
{
    for (size_t i = 0; i < inlen; i++)
        sprintf(out + i * 2, "%02x", in[i]);
    out[inlen * 2] = '\0';
}

/* ---- SHA-256 Tests ---- */

static void test_sha256_empty(void)
{
    TEST(sha256_empty);
    char hex[65];
    sha256_hex((const uint8_t *)"", 0, hex);
    ASSERT_STR(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    PASS();
}

static void test_sha256_hello(void)
{
    TEST(sha256_hello);
    char hex[65];
    sha256_hex((const uint8_t *)"hello", 5, hex);
    ASSERT_STR(hex, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    PASS();
}

static void test_sha256_abc(void)
{
    TEST(sha256_abc);
    char hex[65];
    sha256_hex((const uint8_t *)"abc", 3, hex);
    ASSERT_STR(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    PASS();
}

static void test_sha256_long(void)
{
    TEST(sha256_long);
    char hex[65];
    const char *input = "The quick brown fox jumps over the lazy dog";
    sha256_hex((const uint8_t *)input, strlen(input), hex);
    ASSERT_STR(hex, "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
    PASS();
}

/* ---- Base64 Tests ---- */

static void test_base64_empty(void)
{
    TEST(base64_empty);
    char out[64]; size_t olen;
    base64_encode((const uint8_t *)"", 0, out, &olen);
    ASSERT_STR(out, "");
    PASS();
}

static void test_base64_hello(void)
{
    TEST(base64_hello);
    char out[64]; size_t olen;
    base64_encode((const uint8_t *)"Hello", 5, out, &olen);
    ASSERT_STR(out, "SGVsbG8=");
    PASS();
}

static void test_base64_portal(void)
{
    TEST(base64_portal);
    char out[64]; size_t olen;
    base64_encode((const uint8_t *)"Portal v1.0", 11, out, &olen);
    ASSERT_STR(out, "UG9ydGFsIHYxLjA=");
    PASS();
}

static void test_base64_binary(void)
{
    TEST(base64_binary);
    uint8_t data[] = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD};
    char out[64]; size_t olen;
    base64_encode(data, 6, out, &olen);
    ASSERT_STR(out, "AAEC//79");
    PASS();
}

/* ---- Hex Tests ---- */

static void test_hex_encode(void)
{
    TEST(hex_encode);
    char out[64];
    hex_encode((const uint8_t *)"ABC", 3, out);
    ASSERT_STR(out, "414243");
    PASS();
}

static void test_hex_binary(void)
{
    TEST(hex_binary);
    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    char out[16];
    hex_encode(data, 4, out);
    ASSERT_STR(out, "deadbeef");
    PASS();
}

int main(void)
{
    printf("=== Portal Crypto Tests ===\n\n");

    test_sha256_empty();
    test_sha256_hello();
    test_sha256_abc();
    test_sha256_long();
    test_base64_empty();
    test_base64_hello();
    test_base64_portal();
    test_base64_binary();
    test_hex_encode();
    test_hex_binary();

    printf("\n%d/%d tests passed.\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
