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
# Portal v1.0.0 — Integration Tests: All Modules
# =============================================================================
#
# Tests every module's status endpoint and key functions via HTTP API.
# Requires a running Portal instance on the specified port.
#
# Usage: ./test_all_modules.sh [host:port] [api_key]
# =============================================================================

HOST="${1:-localhost:8084}"
KEY="${2:-auto}"
API="http://$HOST/api"
PASS=0
FAIL=0
SKIP=0
ERRORS=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

test_get() {
    local name="$1" path="$2" expect="$3"
    local resp
    resp=$(curl -s -w "\n%{http_code}" -H "X-API-Key: $KEY" "$API$path" 2>/dev/null)
    local code=$(echo "$resp" | tail -1)
    local body=$(echo "$resp" | sed '$d')

    if [ "$code" = "$expect" ]; then
        printf "  ${GREEN}PASS${NC}  %-50s %s\n" "$name" "$code"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC}  %-50s got %s expected %s\n" "$name" "$code" "$expect"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $name ($path) → $code (expected $expect)"
    fi
}

test_get_contains() {
    local name="$1" path="$2" needle="$3"
    local resp
    resp=$(curl -s -H "X-API-Key: $KEY" "$API$path" 2>/dev/null)

    if echo "$resp" | grep -q "$needle"; then
        printf "  ${GREEN}PASS${NC}  %-50s contains '$needle'\n" "$name"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}FAIL${NC}  %-50s missing '$needle'\n" "$name"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $name → missing '$needle'"
    fi
}

echo "=============================================="
echo "Portal Integration Tests — All Modules"
echo "Target: $API"
echo "=============================================="
echo ""

# --- Core paths ---
echo "=== Core ==="
test_get "core/status" "/core/status" "200"
test_get "core/paths" "/core/paths" "200"
test_get "core/modules" "/core/modules" "200"
test_get "core/storage" "/core/storage" "200"
test_get "core/config/list" "/core/config/list" "200"
test_get "core/config/get (web.port)" "/core/config/get?module=web&key=port" "200"
test_get "core/config/get (missing)" "/core/config/get?module=xxx&key=yyy" "404"
test_get "events list" "/events" "200"
test_get "auth/whoami" "/auth/whoami" "200"
echo ""

# --- Infrastructure modules ---
echo "=== Infrastructure ==="
test_get "web/status" "/web/resources/status" "200"
test_get "node/status" "/node/resources/status" "200"
test_get "node/peers" "/node/resources/peers" "200"
test_get "ssh/status" "/ssh/resources/status" "200"
test_get "config_sqlite/status" "/core/storage/sqlite/resources/status" "200"
echo ""

# --- Utility modules ---
echo "=== Utility ==="
test_get "cache/status" "/cache/resources/status" "200"
test_get "cache/keys" "/cache/resources/keys" "200"
test_get "health/status" "/health/resources/status" "200"
test_get "cron/status" "/cron/resources/status" "200"
test_get "cron/jobs" "/cron/resources/jobs" "200"
test_get "json/status" "/json/resources/status" "200"
test_get "worker/status" "/worker/resources/status" "200"
test_get "worker/pools" "/worker/resources/pools" "200"
test_get "metrics/status" "/metrics/resources/status" "200"
test_get "metrics/cpu" "/metrics/resources/cpu" "200"
test_get "metrics/memory" "/metrics/resources/memory" "200"
test_get "metrics/disk" "/metrics/resources/disk" "200"
test_get "metrics/load" "/metrics/resources/load" "200"
test_get "metrics/all" "/metrics/resources/all" "200"
test_get "audit/status" "/audit/resources/status" "200"
test_get "audit/log" "/audit/resources/log" "200"
test_get "scheduler/status" "/scheduler/resources/status" "200"
test_get "scheduler/tasks" "/scheduler/resources/tasks" "200"
echo ""

# --- Data modules ---
echo "=== Data ==="
test_get "queue/status" "/queue/resources/status" "200"
test_get "queue/list" "/queue/resources/list" "200"
test_get "email/status" "/email/resources/status" "200"
test_get "file/status" "/file/resources/status" "200"
test_get "kv/status" "/kv/resources/status" "200"
test_get "kv/keys" "/kv/resources/keys" "200"
test_get "serial/status" "/serial/resources/status" "200"
test_get "serial/ports" "/serial/resources/ports" "200"
test_get "shm/status" "/shm/resources/status" "200"
test_get "mqtt/status" "/mqtt/resources/status" "200"
test_get "ws/status" "/ws/resources/status" "200"
echo ""

# --- Security modules ---
echo "=== Security ==="
test_get "firewall/status" "/firewall/resources/status" "200"
test_get "firewall/rules" "/firewall/resources/rules" "200"
test_get "firewall/blocked" "/firewall/resources/blocked" "200"
test_get "crypto/status" "/crypto/resources/status" "200"
test_get "validator/status" "/validator/resources/status" "200"
echo ""

# --- Network modules ---
echo "=== Network ==="
test_get "proxy/status" "/proxy/resources/status" "200"
test_get "proxy/routes" "/proxy/resources/routes" "200"
test_get "dns/status" "/dns/resources/status" "200"
test_get "webhook/status" "/webhook/resources/status" "200"
test_get "webhook/hooks" "/webhook/resources/hooks" "200"
test_get "gateway/status" "/gateway/resources/status" "200"
test_get "gateway/routes" "/gateway/resources/routes" "200"
echo ""

# --- System modules ---
echo "=== System ==="
test_get "sysinfo/status" "/sysinfo/resources/status" "200"
test_get "sysinfo/os" "/sysinfo/resources/os" "200"
test_get "sysinfo/network" "/sysinfo/resources/network" "200"
test_get "sysinfo/all" "/sysinfo/resources/all" "200"
test_get "log/status" "/log/resources/status" "200"
test_get "log/files" "/log/resources/files" "200"
test_get "backup/status" "/backup/resources/status" "200"
test_get "backup/list" "/backup/resources/list" "200"
test_get "acme/status" "/acme/resources/status" "200"
test_get "acme/certs" "/acme/resources/certs" "200"
echo ""

# --- Compression modules ---
echo "=== Compression ==="
test_get "xz/status" "/xz/resources/status" "200"
test_get "gzip/status" "/gzip/resources/status" "200"
echo ""

# --- IoT ---
echo "=== IoT ==="
test_get "gpio/status" "/gpio/resources/status" "200"
test_get "gpio/pins" "/gpio/resources/pins" "200"
echo ""

# --- Rendering ---
echo "=== Rendering ==="
test_get "template/status" "/template/resources/status" "200"
test_get "template/list" "/template/resources/list" "200"
test_get "admin/dashboard" "/admin/dashboard" "200"
test_get "admin/modules" "/admin/modules" "200"
test_get "admin/config" "/admin/config" "200"
test_get "admin/logs" "/admin/logs" "200"
echo ""

# --- Functional tests ---
echo "=== Functional Tests ==="

# Crypto
test_get_contains "sha256(hello)" "/crypto/functions/sha256?data=hello" "2cf24dba5fb0a30e"
test_get_contains "md5(hello)" "/crypto/functions/md5?data=hello" "5d41402abc4b2a76"
test_get_contains "base64enc(ABC)" "/crypto/functions/base64enc?data=ABC" "QUJD"
test_get_contains "hexenc(Hi)" "/crypto/functions/hexenc?data=Hi" "4869"

# Validator
test_get_contains "valid email" "/validator/functions/email?value=a@b.com" "valid"
test_get_contains "invalid email" "/validator/functions/email?value=bad" "invalid"
test_get_contains "valid IPv4" "/validator/functions/ip?value=10.0.0.1" "valid"
test_get_contains "invalid IP" "/validator/functions/ip?value=notip" "invalid"
test_get_contains "valid hostname" "/validator/functions/hostname?value=portal.io" "valid"
test_get_contains "number in range" "/validator/functions/number?value=50&min=0&max=100" "valid"
test_get_contains "number out of range" "/validator/functions/number?value=200&min=0&max=100" "invalid"

# DNS
test_get_contains "dns resolve" "/dns/functions/resolve?host=localhost" "127.0.0.1"

# KV CRUD
curl -s -H "X-API-Key: $KEY" "$API/kv/functions/set?key=_test_k&value=_test_v" > /dev/null
test_get_contains "kv get after set" "/kv/functions/get?key=_test_k" "_test_v"
test_get_contains "kv exists" "/kv/functions/exists?key=_test_k" "true"
curl -s -H "X-API-Key: $KEY" "$API/kv/functions/del?key=_test_k" > /dev/null
test_get_contains "kv deleted" "/kv/functions/exists?key=_test_k" "false"

# Cache CRUD
curl -s -H "X-API-Key: $KEY" "$API/cache/functions/set?key=_tc&value=_tv&ttl=60" > /dev/null
test_get_contains "cache get" "/cache/functions/get?key=_tc" "_tv"
curl -s -H "X-API-Key: $KEY" "$API/cache/functions/del?key=_tc" > /dev/null

# Firewall
curl -s -H "X-API-Key: $KEY" "$API/firewall/functions/deny?source=_test_ip&reason=test" > /dev/null
test_get_contains "firewall blocked" "/firewall/functions/check?source=_test_ip" "BLOCKED"
curl -s -H "X-API-Key: $KEY" "$API/firewall/functions/remove?source=_test_ip" > /dev/null
test_get_contains "firewall unblocked" "/firewall/functions/check?source=_test_ip" "ALLOWED"

# Scheduler
curl -s -H "X-API-Key: $KEY" "$API/scheduler/functions/schedule?name=_test_sched&path=/hello&delay=9999" > /dev/null
test_get_contains "scheduler task created" "/scheduler/resources/tasks" "_test_sched"
curl -s -H "X-API-Key: $KEY" "$API/scheduler/functions/cancel?name=_test_sched" > /dev/null

# Config get/set
curl -s -H "X-API-Key: $KEY" "$API/core/config/set?module=_test&key=_k&value=_v" > /dev/null
test_get_contains "config persisted" "/core/config/get?module=_test&key=_k" "_v"

# Template
mkdir -p /var/lib/portal/devtest/data/templates 2>/dev/null
echo 'Hi {{who}}!' > /var/lib/portal/devtest/data/templates/_test.html 2>/dev/null
test_get_contains "template render" "/template/functions/render?name=_test.html&who=World" "Hi World"
rm -f /var/lib/portal/devtest/data/templates/_test.html 2>/dev/null

# File write/read
curl -s -H "X-API-Key: $KEY" "$API/file/functions/write?name=_test.txt&data=hello_file" > /dev/null
test_get_contains "file read after write" "/file/functions/read?name=_test.txt" "hello_file"
curl -s -H "X-API-Key: $KEY" "$API/file/functions/delete?name=_test.txt" > /dev/null

# Admin dashboard content check
test_get_contains "admin has modules table" "/admin/dashboard" "<table>"
test_get_contains "admin has Portal header" "/admin/dashboard" "Portal"

echo ""

# --- Edge cases ---
echo "=== Edge Cases ==="
test_get "nonexistent path" "/this/does/not/exist" "404"
test_get "root path (API index)" "/" "200"
test_get "double slash" "//core//status" "404"
test_get "missing params" "/crypto/functions/sha256" "400"
test_get "validator no value" "/validator/functions/email" "400"
test_get "kv missing key" "/kv/functions/get" "400"
test_get "kv traversal .." "/kv/functions/get?key=../etc/passwd" "400"
test_get "file traversal .." "/file/functions/read?name=../../../etc/passwd" "400"
echo ""

# --- Summary ---
TOTAL=$((PASS + FAIL + SKIP))
echo "=============================================="
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped ($TOTAL total)"
echo "=============================================="

if [ $FAIL -gt 0 ]; then
    echo ""
    echo -e "Failures:$ERRORS"
    echo ""
    exit 1
fi

exit 0
