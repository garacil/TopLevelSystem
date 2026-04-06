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
 * test_validator.c — Unit tests for input validation functions
 *
 * Tests email, IPv4, IPv6, URL, hostname, number validation.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { printf("test_%s... ", #name); tests_run++; } while(0)
#define PASS() do { printf("OK\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)
#define ASSERT(cond) do { if (!(cond)) { FAIL(#cond); return; } } while(0)

/* Validation functions (same as mod_validator) */

static int validate_email(const char *email)
{
    const char *at = strchr(email, '@');
    if (!at || at == email) return 0;
    const char *dot = strchr(at, '.');
    if (!dot || dot == at + 1 || *(dot + 1) == '\0') return 0;
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
    return strlen(url) > 10;
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

static int validate_number(const char *val, const char *min_s, const char *max_s)
{
    char *end;
    double num = strtod(val, &end);
    if (*end != '\0') return 0;
    if (min_s) { double mn = strtod(min_s, NULL); if (num < mn) return 0; }
    if (max_s) { double mx = strtod(max_s, NULL); if (num > mx) return 0; }
    return 1;
}

/* Tests */

static void test_email_valid(void)
{
    TEST(email_valid);
    ASSERT(validate_email("user@example.com"));
    ASSERT(validate_email("a@b.co"));
    ASSERT(validate_email("test+tag@domain.org"));
    PASS();
}

static void test_email_invalid(void)
{
    TEST(email_invalid);
    ASSERT(!validate_email("notanemail"));
    ASSERT(!validate_email("@domain.com"));
    ASSERT(!validate_email("user@"));
    ASSERT(!validate_email("user@domain"));
    ASSERT(!validate_email("user @domain.com"));
    PASS();
}

static void test_ipv4_valid(void)
{
    TEST(ipv4_valid);
    ASSERT(validate_ipv4("192.168.1.1"));
    ASSERT(validate_ipv4("10.0.0.0"));
    ASSERT(validate_ipv4("255.255.255.255"));
    ASSERT(validate_ipv4("0.0.0.0"));
    PASS();
}

static void test_ipv4_invalid(void)
{
    TEST(ipv4_invalid);
    ASSERT(!validate_ipv4("256.1.1.1"));
    ASSERT(!validate_ipv4("not.an.ip"));
    ASSERT(!validate_ipv4("192.168.1"));
    ASSERT(!validate_ipv4(""));
    PASS();
}

static void test_ipv6_valid(void)
{
    TEST(ipv6_valid);
    ASSERT(validate_ipv6("::1"));
    ASSERT(validate_ipv6("fe80::1"));
    ASSERT(validate_ipv6("2001:db8::1"));
    PASS();
}

static void test_url_valid(void)
{
    TEST(url_valid);
    ASSERT(validate_url("http://example.com"));
    ASSERT(validate_url("https://portal.local/api"));
    ASSERT(validate_url("http://192.168.1.1:8080/path"));
    PASS();
}

static void test_url_invalid(void)
{
    TEST(url_invalid);
    ASSERT(!validate_url("ftp://server"));
    ASSERT(!validate_url("not-a-url"));
    ASSERT(!validate_url("http://"));
    PASS();
}

static void test_hostname_valid(void)
{
    TEST(hostname_valid);
    ASSERT(validate_hostname("portal.example.com"));
    ASSERT(validate_hostname("my-host"));
    ASSERT(validate_hostname("localhost"));
    PASS();
}

static void test_hostname_invalid(void)
{
    TEST(hostname_invalid);
    ASSERT(!validate_hostname("-badstart"));
    ASSERT(!validate_hostname("bad end-"));
    ASSERT(!validate_hostname("has space"));
    ASSERT(!validate_hostname(""));
    PASS();
}

static void test_number_range(void)
{
    TEST(number_range);
    ASSERT(validate_number("42", "0", "100"));
    ASSERT(validate_number("0", "0", "100"));
    ASSERT(validate_number("100", "0", "100"));
    ASSERT(!validate_number("101", "0", "100"));
    ASSERT(!validate_number("-1", "0", "100"));
    ASSERT(validate_number("3.14", NULL, NULL));
    ASSERT(!validate_number("abc", NULL, NULL));
    PASS();
}

int main(void)
{
    printf("=== Portal Validator Tests ===\n\n");

    test_email_valid();
    test_email_invalid();
    test_ipv4_valid();
    test_ipv4_invalid();
    test_ipv6_valid();
    test_url_valid();
    test_url_invalid();
    test_hostname_valid();
    test_hostname_invalid();
    test_number_range();

    printf("\n%d/%d tests passed.\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
