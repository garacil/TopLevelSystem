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
# Portal v1.0.0 — Stress Tests
# =============================================================================
#
# Tests: concurrent requests, rapid fire, large payloads, resource exhaustion.
# Requires a running Portal instance.
#
# Usage: ./test_stress.sh [host:port] [api_key]
# =============================================================================

HOST="${1:-localhost:8084}"
KEY="${2:-auto}"
API="http://$HOST/api"
PASS=0
FAIL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

stress_test() {
    local name="$1"
    shift
    printf "  %-50s " "$name"
    if eval "$@" > /dev/null 2>&1; then
        printf "${GREEN}PASS${NC}\n"
        PASS=$((PASS + 1))
    else
        printf "${RED}FAIL${NC}\n"
        FAIL=$((FAIL + 1))
    fi
}

echo "=============================================="
echo "Portal Stress Tests"
echo "Target: $API"
echo "=============================================="
echo ""

# --- Rapid fire: 100 requests to core/status ---
echo "=== Rapid Fire (sequential) ==="
stress_test "100x core/status" '
    for i in $(seq 1 100); do
        curl -sf -H "X-API-Key: '$KEY'" "'$API'/core/status" > /dev/null || exit 1
    done
'

stress_test "100x crypto/sha256" '
    for i in $(seq 1 100); do
        curl -sf -H "X-API-Key: '$KEY'" "'$API'/crypto/functions/sha256?data=test$i" > /dev/null || exit 1
    done
'

stress_test "100x validator/email" '
    for i in $(seq 1 100); do
        curl -sf -H "X-API-Key: '$KEY'" "'$API'/validator/functions/email?value=u$i@test.com" > /dev/null || exit 1
    done
'
echo ""

# --- Concurrent requests ---
echo "=== Concurrent Requests ==="
stress_test "20 parallel core/status" '
    for i in $(seq 1 20); do
        curl -sf -H "X-API-Key: '$KEY'" "'$API'/core/status" > /dev/null &
    done
    wait
'

stress_test "20 parallel crypto+validator" '
    for i in $(seq 1 10); do
        curl -sf -H "X-API-Key: '$KEY'" "'$API'/crypto/functions/sha256?data=p$i" > /dev/null &
        curl -sf -H "X-API-Key: '$KEY'" "'$API'/validator/functions/ip?value=10.0.0.$i" > /dev/null &
    done
    wait
'

stress_test "20 parallel KV set+get" '
    for i in $(seq 1 10); do
        curl -sf -H "X-API-Key: '$KEY'" "'$API'/kv/functions/set?key=stress_$i&value=val_$i" > /dev/null &
        curl -sf -H "X-API-Key: '$KEY'" "'$API'/kv/functions/get?key=stress_$i" > /dev/null &
    done
    wait
    # Cleanup
    for i in $(seq 1 10); do
        curl -sf -H "X-API-Key: '$KEY'" "'$API'/kv/functions/del?key=stress_$i" > /dev/null 2>&1 &
    done
    wait
'

stress_test "50 parallel mixed endpoints" '
    for i in $(seq 1 50); do
        case $((i % 5)) in
            0) curl -sf -H "X-API-Key: '$KEY'" "'$API'/core/status" > /dev/null & ;;
            1) curl -sf -H "X-API-Key: '$KEY'" "'$API'/metrics/resources/load" > /dev/null & ;;
            2) curl -sf -H "X-API-Key: '$KEY'" "'$API'/cache/resources/status" > /dev/null & ;;
            3) curl -sf -H "X-API-Key: '$KEY'" "'$API'/crypto/functions/md5?data=s$i" > /dev/null & ;;
            4) curl -sf -H "X-API-Key: '$KEY'" "'$API'/validator/functions/email?value=u$i@x.com" > /dev/null & ;;
        esac
    done
    wait
'
echo ""

# --- Large payloads ---
echo "=== Large Payloads ==="
stress_test "1KB body to gzip compress" '
    dd if=/dev/urandom bs=1024 count=1 2>/dev/null | \
        curl -sf -H "X-API-Key: '$KEY'" --data-binary @- "'$API'/gzip/functions/compress" > /dev/null
'

stress_test "10KB body to gzip compress" '
    dd if=/dev/urandom bs=1024 count=10 2>/dev/null | \
        curl -sf -H "X-API-Key: '$KEY'" --data-binary @- "'$API'/gzip/functions/compress" > /dev/null
'

stress_test "100KB body to gzip compress" '
    dd if=/dev/urandom bs=1024 count=100 2>/dev/null | \
        curl -sf -H "X-API-Key: '$KEY'" --data-binary @- "'$API'/gzip/functions/compress" > /dev/null
'

stress_test "1KB body to xz compress" '
    dd if=/dev/urandom bs=1024 count=1 2>/dev/null | \
        curl -sf -H "X-API-Key: '$KEY'" --data-binary @- "'$API'/xz/functions/compress" > /dev/null
'

stress_test "Long key name (200 chars) to KV" '
    KEY200=$(python3 -c "print(\"k\" * 200)")
    curl -sf -H "X-API-Key: '$KEY'" "'$API'/kv/functions/set?key=$KEY200&value=test" > /dev/null
    curl -sf -H "X-API-Key: '$KEY'" "'$API'/kv/functions/del?key=$KEY200" > /dev/null
'

stress_test "Long value (10KB) to KV" '
    VAL=$(python3 -c "print(\"x\" * 10240)")
    curl -sf -H "X-API-Key: '$KEY'" "'$API'/kv/functions/set?key=_stress_big&value=$VAL" > /dev/null
    curl -sf -H "X-API-Key: '$KEY'" "'$API'/kv/functions/del?key=_stress_big" > /dev/null
'
echo ""

# --- Cache stress ---
echo "=== Cache Stress ==="
stress_test "100 cache set+get+del cycles" '
    for i in $(seq 1 100); do
        curl -sf -H "X-API-Key: '$KEY'" "'$API'/cache/functions/set?key=cs_$i&value=v_$i&ttl=5" > /dev/null
        curl -sf -H "X-API-Key: '$KEY'" "'$API'/cache/functions/get?key=cs_$i" > /dev/null
    done
    curl -sf -H "X-API-Key: '$KEY'" "'$API'/cache/functions/flush" > /dev/null
'
echo ""

# --- Queue stress ---
echo "=== Queue Stress ==="
stress_test "create+push+pop+destroy queue" '
    curl -sf -H "X-API-Key: '$KEY'" "'$API'/queue/functions/create?name=_stressq" > /dev/null
    for i in $(seq 1 50); do
        curl -sf -H "X-API-Key: '$KEY'" "'$API'/queue/functions/push?name=_stressq&data=item_$i" > /dev/null
    done
    for i in $(seq 1 50); do
        curl -sf -H "X-API-Key: '$KEY'" "'$API'/queue/functions/pop?name=_stressq" > /dev/null
    done
    curl -sf -H "X-API-Key: '$KEY'" "'$API'/queue/functions/destroy?name=_stressq" > /dev/null
'
echo ""

# --- Firewall stress ---
echo "=== Firewall Stress ==="
stress_test "50 deny+check+remove cycles" '
    for i in $(seq 1 50); do
        curl -sf -H "X-API-Key: '$KEY'" "'$API'/firewall/functions/deny?source=stress_$i" > /dev/null
        curl -sf -H "X-API-Key: '$KEY'" "'$API'/firewall/functions/check?source=stress_$i" > /dev/null
        curl -sf -H "X-API-Key: '$KEY'" "'$API'/firewall/functions/remove?source=stress_$i" > /dev/null
    done
'
echo ""

# --- Admin dashboard under load ---
echo "=== Admin Dashboard Load ==="
stress_test "20x admin/dashboard render" '
    for i in $(seq 1 20); do
        curl -sf -H "X-API-Key: '$KEY'" "'$API'/admin/dashboard" > /dev/null || exit 1
    done
'
echo ""

# --- Verify instance still healthy ---
echo "=== Post-Stress Health Check ==="
stress_test "core/status still responds" '
    curl -sf -H "X-API-Key: '$KEY'" "'$API'/core/status" > /dev/null
'
stress_test "metrics still responds" '
    curl -sf -H "X-API-Key: '$KEY'" "'$API'/metrics/resources/all" > /dev/null
'
stress_test "cache still works" '
    curl -sf -H "X-API-Key: '$KEY'" "'$API'/cache/functions/set?key=_alive&value=yes" > /dev/null
    result=$(curl -sf -H "X-API-Key: '$KEY'" "'$API'/cache/functions/get?key=_alive")
    [ "$result" = "yes" ] || exit 1
    curl -sf -H "X-API-Key: '$KEY'" "'$API'/cache/functions/del?key=_alive" > /dev/null
'
echo ""

# --- Summary ---
TOTAL=$((PASS + FAIL))
echo "=============================================="
echo "Stress Results: $PASS passed, $FAIL failed ($TOTAL total)"
echo "=============================================="
[ $FAIL -gt 0 ] && exit 1
exit 0
