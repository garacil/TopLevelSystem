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
# Portal v1.0.0 — Master Test Runner
# =============================================================================
#
# Runs ALL test suites in order:
#   1. Unit tests (C, compiled)
#   2. Integration tests (HTTP API, requires running instance)
#   3. Security tests (injection, traversal, auth)
#   4. Stress tests (load, concurrency)
#
# Usage:
#   ./tests/run_all.sh                    # Run all (starts instance if needed)
#   ./tests/run_all.sh unit               # Unit tests only
#   ./tests/run_all.sh integration        # Integration only
#   ./tests/run_all.sh security           # Security only
#   ./tests/run_all.sh stress             # Stress only
# =============================================================================

set -e
cd "$(dirname "$0")/.."  # project root

SUITE="${1:-all}"
HOST="localhost:8084"
KEY="auto"
INSTANCE="devtest"
TOTAL_PASS=0
TOTAL_FAIL=0
STARTED_INSTANCE=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════${NC}"
    echo ""
}

# Ensure instance is running for integration/security/stress tests
ensure_instance() {
    if ! curl -sf "http://$HOST/api/core/status" > /dev/null 2>&1; then
        echo -e "${YELLOW}Starting $INSTANCE instance...${NC}"
        make install > /dev/null 2>&1
        nohup portal -n $INSTANCE -f -d > /tmp/portal_test.log 2>&1 &
        sleep 4
        STARTED_INSTANCE=1
        if ! curl -sf "http://$HOST/api/core/status" > /dev/null 2>&1; then
            echo -e "${RED}ERROR: Cannot start instance. Check /tmp/portal_test.log${NC}"
            exit 1
        fi
        echo -e "${GREEN}Instance running.${NC}"
    else
        echo -e "${GREEN}Instance already running at $HOST${NC}"
    fi
}

cleanup() {
    if [ $STARTED_INSTANCE -eq 1 ]; then
        echo ""
        echo -e "${YELLOW}Stopping test instance...${NC}"
        pkill -f "portal.*$INSTANCE" 2>/dev/null || true
        sleep 1
    fi
}
trap cleanup EXIT

# --- Unit Tests ---
run_unit() {
    banner "UNIT TESTS (compiled C)"
    make tests 2>&1
    echo ""
}

# --- Integration Tests ---
run_integration() {
    banner "INTEGRATION TESTS (HTTP API)"
    ensure_instance
    chmod +x tests/integration/modules/test_all_modules.sh
    bash tests/integration/modules/test_all_modules.sh "$HOST" "$KEY"
}

# --- Security Tests ---
run_security() {
    banner "SECURITY TESTS (injection, traversal, auth)"
    ensure_instance
    chmod +x tests/security/test_security.sh
    bash tests/security/test_security.sh "$HOST" "$KEY"
}

# --- Stress Tests ---
run_stress() {
    banner "STRESS TESTS (load, concurrency)"
    ensure_instance
    chmod +x tests/stress/test_stress.sh
    bash tests/stress/test_stress.sh "$HOST" "$KEY"
}

# --- Main ---
echo ""
echo -e "${BOLD}Portal v1.0.0 — Complete Test Suite${NC}"
echo "$(date)"
echo ""

case "$SUITE" in
    unit)         run_unit ;;
    integration)  run_integration ;;
    security)     run_security ;;
    stress)       run_stress ;;
    all)
        run_unit
        run_integration
        run_security
        run_stress
        banner "ALL TESTS COMPLETE"
        echo -e "Run 'make tests' for unit tests only."
        echo -e "Run './tests/run_all.sh <suite>' for individual suites."
        ;;
    *)
        echo "Usage: $0 [unit|integration|security|stress|all]"
        exit 1
        ;;
esac
