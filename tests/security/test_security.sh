#!/bin/bash
#
# Author: Germán Luis Aracil Boned <garacilb@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.
#

# =============================================================================
# Portal v1.0.0 — Security Tests
# =============================================================================
#
# Tests: path traversal, injection, auth bypass, oversized inputs,
# null bytes, malformed requests, unauthorized access.
#
# Usage: ./test_security.sh [host:port] [api_key]
# =============================================================================

HOST="${1:-localhost:8084}"
KEY="${2:-auto}"
API="http://$HOST/api"
PASS=0
FAIL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Expect specific HTTP code
expect_code() {
    local name="$1" path="$2" expect="$3" auth="$4"
    local hdr=""
    [ -n "$auth" ] && hdr="-H X-API-Key:$auth" || hdr="-H X-API-Key:$KEY"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" $hdr "$API$path" 2>/dev/null)
    if [ "$code" = "$expect" ]; then
        printf "  ${GREEN}PASS${NC}  %-55s %s\n" "$name" "$code"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC}  %-55s got %s expected %s\n" "$name" "$code" "$expect"
        FAIL=$((FAIL + 1))
    fi
}

# Expect body does NOT contain a string
expect_not_contains() {
    local name="$1" path="$2" bad="$3"
    local resp
    resp=$(curl -s -H "X-API-Key: $KEY" "$API$path" 2>/dev/null)
    if echo "$resp" | grep -q "$bad"; then
        printf "  ${RED}FAIL${NC}  %-55s LEAKED: '%s'\n" "$name" "$bad"
        FAIL=$((FAIL + 1))
    else
        printf "  ${GREEN}PASS${NC}  %-55s safe\n" "$name"
        PASS=$((PASS + 1))
    fi
}

echo "=============================================="
echo "Portal Security Tests"
echo "Target: $API"
echo "=============================================="
echo ""

# --- Path Traversal ---
echo "=== Path Traversal ==="
expect_code "file read ../etc/passwd" "/file/functions/read?name=../etc/passwd" "400"
expect_code "file read ../../etc/shadow" "/file/functions/read?name=../../etc/shadow" "400"
expect_code "file read /etc/passwd (abs)" "/file/functions/read?name=/etc/passwd" "400"
expect_code "kv get ../etc/passwd" "/kv/functions/get?key=../etc/passwd" "400"
expect_code "kv get with slash" "/kv/functions/get?key=sub/key" "400"
expect_code "kv get dot-file" "/kv/functions/get?key=.hidden" "400"
expect_code "template render ../etc/passwd" "/template/functions/render?name=../../../etc/passwd" "400"
expect_code "log tail ../etc/passwd" "/log/resources/tail?file=../../../etc/passwd" "400"
expect_code "backup restore traversal (blocked)" "/backup/functions/restore?name=../../etc/passwd" "403"
echo ""

# --- Injection attempts ---
echo "=== Injection Attempts ==="
expect_code "sql injection in kv key" "/kv/functions/set?key=DROP_TABLE&value=x" "200"
expect_code "command injection in process" "/process/functions/exec?cmd=ls;rm+-rf+/" "403"
expect_code "rm -rf in process" "/process/functions/exec?cmd=rm+-rf+/" "403"
expect_code "dd if= in process" "/process/functions/exec?cmd=dd+if=/dev/zero" "403"
expect_code "mkfs blocked in process" "/process/functions/exec?cmd=mkfs+/dev/sda" "403"
expect_not_contains "no /etc/passwd leak via file" "/file/functions/read?name=../etc/passwd" "root:x:"
expect_not_contains "no /etc/shadow leak via file" "/file/functions/read?name=../etc/shadow" "root:"
echo ""

# --- Auth bypass ---
echo "=== Authentication ==="
expect_code "no auth → core/status (public)" "/core/status" "200" "invalid_key_xxx"
expect_code "bad API key → core/status" "/core/status" "200" "bad"
expect_code "empty key → cache/status (works, no label)" "/cache/resources/status" "200" ""
echo ""

# --- Oversized inputs ---
echo "=== Oversized Inputs ==="
expect_code "very long path (2000 chars)" "/$(python3 -c 'print("a"*2000)')" "404"
expect_code "very long query key (1000)" "/kv/functions/get?key=$(python3 -c 'print("k"*1000)')" "400"
expect_code "very long query value (5000 chars)" "/cache/functions/set?key=x&value=$(python3 -c 'print("v"*5000)')" "400"

# Large body to compress (within 64KB web limit)
printf "  %-55s " "50KB body to gzip (within limit)"
result=$(dd if=/dev/zero bs=1024 count=50 2>/dev/null | curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: $KEY" --data-binary @- "$API/gzip/functions/compress")
if [ "$result" = "200" ]; then
    printf "${GREEN}PASS${NC}  200\n"; PASS=$((PASS + 1))
else
    printf "${RED}FAIL${NC}  $result\n"; FAIL=$((FAIL + 1))
fi
echo ""

# --- Null bytes ---
echo "=== Null Byte Injection ==="
printf "  %-55s " "null byte in path"
code=$(curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: $KEY" "$API/core%00/status")
if [ "$code" = "404" ] || [ "$code" = "400" ]; then
    printf "${GREEN}PASS${NC}  $code\n"; PASS=$((PASS + 1))
else
    printf "${RED}FAIL${NC}  $code\n"; FAIL=$((FAIL + 1))
fi

printf "  %-55s " "null byte in key"
code=$(curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: $KEY" "$API/kv/functions/get?key=test%00evil")
if [ "$code" != "200" ]; then
    printf "${GREEN}PASS${NC}  $code (rejected)\n"; PASS=$((PASS + 1))
else
    printf "${RED}FAIL${NC}  $code (should reject)\n"; FAIL=$((FAIL + 1))
fi
echo ""

# --- Malformed requests ---
echo "=== Malformed Requests ==="
expect_code "missing required param (sha256)" "/crypto/functions/sha256" "400"
expect_code "missing required param (email)" "/validator/functions/email" "400"
expect_code "missing required param (dns)" "/dns/functions/resolve" "400"
expect_code "missing param (kv set, no key)" "/kv/functions/set" "400"
expect_code "missing param (kv set, no value)" "/kv/functions/set?key=x" "400"
expect_code "missing param (file write)" "/file/functions/write" "400"
expect_code "missing param (email send)" "/email/functions/send" "400"
expect_code "missing param (cron add)" "/cron/functions/add" "400"
expect_code "missing param (webhook register)" "/webhook/functions/register" "400"
expect_code "missing param (proxy add)" "/proxy/functions/add" "400"
expect_code "missing param (gateway add)" "/gateway/functions/add" "400"
expect_code "missing param (scheduler)" "/scheduler/functions/schedule" "400"
echo ""

# --- Not found paths ---
echo "=== 404 Not Found ==="
expect_code "completely fake path" "/xxx/yyy/zzz" "404"
expect_code "module exists, bad subpath" "/cache/nonexistent" "404"
expect_code "typo in resources" "/cache/resourc/status" "404"
expect_code "wrong method path" "/file/functions/nonexistent" "404"
echo ""

# --- Summary ---
TOTAL=$((PASS + FAIL))
echo "=============================================="
echo "Security Results: $PASS passed, $FAIL failed ($TOTAL total)"
echo "=============================================="
[ $FAIL -gt 0 ] && exit 1
exit 0
