#!/bin/bash

set -e

DIR=$(cd -P -- "$(dirname -- "$(command -v -- "$0")")" && pwd -P)
PROJECT_ROOT="${DIR}/.."

cd "${PROJECT_ROOT}"

# Integration Test Script for Traefik Real IP Plugin
# This script can be run locally or in CI/CD environments

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
TRAEFIK_PORT="${TRAEFIK_PORT:-4008}"
COMPOSE_DIR="${COMPOSE_DIR:-testing}"
TIMEOUT="${TIMEOUT:-60}"

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_test() {
    echo -e "${GREEN}[TEST]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v docker &>/dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi

    if ! command -v curl &>/dev/null; then
        log_error "curl is not installed"
        exit 1
    fi

    log_info "Prerequisites OK"
}

# Start services
start_services() {
    log_info "Starting Traefik and whoami services..."
    cd "${PROJECT_ROOT}/${COMPOSE_DIR}"
    ./docker-start.sh
    cd "${PROJECT_ROOT}" >/dev/null
}

# Test endpoint accessibility
test_endpoint() {
    log_test "Testing endpoint accessibility..."

    response_code=$(curl -q -s -o /dev/null -w "%{http_code}" "http://localhost:${TRAEFIK_PORT}" -H "Host: test.local")

    if [ "${response_code}" = "200" ]; then
        log_info "✓ Endpoint is accessible (HTTP ${response_code})"
        return 0
    else
        log_error "✗ Endpoint returned HTTP ${response_code}"
        return 1
    fi
}

# Test X-Forwarded-For header
test_x_forwarded_for() {
    log_test "Testing X-Forwarded-For header..."

    response=$(curl -q -s "http://localhost:${TRAEFIK_PORT}" \
        -H "Host: test.local" \
        -H "X-Forwarded-For: 203.0.113.1")

    if [ "${VERBOSE:-0}" -eq 1 ]; then
        log_info "Response:\n${response}"
    fi

    if echo "${response}" | grep -qi "X-Real-Ip: 203.0.113.1"; then
        log_info "✓ X-Forwarded-For header correctly reflected in response"
        return 0
    else
        log_warn "⚠ X-Forwarded-For header not correctly reflected in response (may be expected)"
        return 1
    fi
}

# Test X-Real-IP header
test_x_real_ip() {
    log_test "Testing X-Real-IP header..."

    response=$(curl -q -s "http://localhost:${TRAEFIK_PORT}" \
        -H "Host: test.local" \
        -H "X-Real-IP: 203.0.113.2")

    if [ "${VERBOSE:-0}" -eq 1 ]; then
        log_info "Response:\n${response}"
    fi

    if echo "${response}" | grep -qi "X-Real-Ip: 203.0.113.2"; then
        log_info "✓ X-Real-IP header correctly reflected in response"
        return 0
    else
        log_warn "⚠ X-Real-IP header not correctly reflected in response (may be expected)"
        return 1
    fi
}

# Test Cloudflare header
test_cloudflare_header() {
    log_test "Testing Cf-Connecting-Ip header..."

    response=$(curl -q -s "http://localhost:${TRAEFIK_PORT}" \
        -H "Host: test.local" \
        -H "Cf-Connecting-Ip: 203.0.113.3")

    if [ "${VERBOSE:-0}" -eq 1 ]; then
        log_info "Response:\n${response}"
    fi

    if echo "${response}" | grep -qi "X-Real-Ip: 203.0.113.3"; then
        log_info "✓ Cf-Connecting-Ip header correctly mapped to X-Real-IP in response"
        return 0
    else
        log_warn "⚠ Cf-Connecting-Ip header not correctly mapped in response (may be expected)"
        return 1
    fi
}

test_edgeone_header() {
    log_test "Testing Eo-Connecting-Ip header..."

    response=$(curl -q -s "http://localhost:${TRAEFIK_PORT}" \
        -H "Host: test.local" \
        -H "Eo-Connecting-Ip: 203.0.113.30")

    if [ "${VERBOSE:-0}" -eq 1 ]; then
        log_info "Response:\n${response}"
    fi

    if echo "${response}" | grep -qi "X-Real-Ip: 203.0.113.30"; then
        log_info "✓ Eo-Connecting-Ip header correctly mapped to X-Real-IP in response"
        return 0
    else
        log_warn "⚠ Eo-Connecting-Ip header not correctly mapped in response (may be expected)"
        return 1
    fi
}

test_edgeone_priority() {
    log_test "Eo-Connecting-Ip takes priority over X-Real-IP and X-Forwarded-For"

    response=$(curl -q -s "http://localhost:${TRAEFIK_PORT}" \
        -H "Host: test.local" \
        -H "X-Forwarded-For: 5.5.5.5" \
        -H "X-Real-IP: 9.9.9.9" \
        -H "Eo-Connecting-Ip: 45.45.45.45")

    if [ "${VERBOSE:-0}" -eq 1 ]; then
        log_info "Response:\n${response}"
    fi

    if echo "${response}" | grep -qi "X-Real-Ip: 45.45.45.45"; then
        log_info "✓ Eo-Connecting-Ip header correctly prioritized over other headers"
        return 0
    else
        log_warn "⚠ Eo-Connecting-Ip header not prioritized over other headers (may be expected)"
        return 1
    fi
}

# Test multiple headers
test_multiple_headers() {
    log_test "Testing multiple proxy headers..."

    response=$(curl -q -s "http://localhost:${TRAEFIK_PORT}" \
        -H "Host: test.local" \
        -H "X-Forwarded-For: 1.2.3.4, 5.6.7.8" \
        -H "X-Real-IP: 9.10.11.12" \
        -H "Eo-Connecting-Ip: 17.18.19.20" \
        -H "Cf-Connecting-Ip: 13.14.15.16")

    if [ "${VERBOSE:-0}" -eq 1 ]; then
        log_info "Response:\n${response}"
    fi

    if echo "${response}" | grep -qi "X-Real-Ip: 13.14.15.16"; then
        log_info "✓ Cf-Connecting-Ip header correctly prioritized in response"
        return 0
    else
        log_warn "⚠ Cf-Connecting-Ip header not prioritized in response (may be expected)"
        return 1
    fi
}

# Show logs
show_logs() {
    if [ "$1" = "traefik" ] || [ "$1" = "all" ]; then
        log_info "=== Traefik logs (last 50 lines) ==="
        docker logs traefik-real-ip_traefik 2>&1 | tail -50
    fi

    if [ "$1" = "whoami" ] || [ "$1" = "all" ]; then
        log_info "=== Whoami logs (last 50 lines) ==="
        docker logs traefik-real-ip_whoami 2>&1 | tail -50
    fi
}

# Cleanup services
# shellcheck disable=SC2317
cleanup() {
    log_info "Cleaning up services..."
    cd "${PROJECT_ROOT}/${COMPOSE_DIR}"
    ./docker-cleanup.sh 2>/dev/null || true
    cd "${PROJECT_ROOT}" >/dev/null
    log_info "Cleanup complete"
}

# Main execution
main() {
    local skip_cleanup=0
    local show_help=0

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
        --skip-cleanup)
            skip_cleanup=1
            shift
            ;;
        --verbose | -v)
            VERBOSE=1
            shift
            ;;
        --help | -h)
            show_help=1
            shift
            ;;
        --logs)
            show_logs "${2:-all}"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help=1
            shift
            ;;
        esac
    done

    if [ $show_help -eq 1 ]; then
        cat <<EOF
Usage: $0 [OPTIONS]

Options:
    --skip-cleanup    Don't cleanup services after tests
    --verbose, -v     Show verbose output
    --logs [service]  Show logs (traefik, whoami, or all)
    --help, -h        Show this help message

Environment Variables:
    TRAEFIK_PORT      Port for Traefik (default: 4008)
    COMPOSE_DIR       Directory with docker-compose.yaml (default: testing)
    TIMEOUT           Timeout for health checks in seconds (default: 60)

Examples:
    $0                          # Run all tests
    $0 --skip-cleanup           # Run tests and keep services running
    $0 --verbose                # Run tests with verbose output
    $0 --logs traefik           # Show Traefik logs

EOF
        exit 0
    fi

    log_info "Starting Traefik Real IP Plugin Integration Tests"

    # Setup trap for cleanup
    if [ $skip_cleanup -eq 0 ]; then
        trap cleanup EXIT
    fi

    # Run tests
    check_prerequisites
    start_services

    # Run test suite
    local failed=0

    test_endpoint || failed=$((failed + 1))
    test_x_forwarded_for || failed=$((failed + 1))
    test_x_real_ip || failed=$((failed + 1))
    test_cloudflare_header || failed=$((failed + 1))
    test_edgeone_header || failed=$((failed + 1))
    test_edgeone_priority || failed=$((failed + 1))
    test_multiple_headers || failed=$((failed + 1))

    # Summary
    echo ""
    log_info "================================"
    if [ $failed -eq 0 ]; then
        log_info "All tests passed! ✓"
        log_info "================================"
        exit 0
    else
        log_error "Some tests failed: $failed"
        log_error "================================"
        show_logs all
        exit 1
    fi
}

# Run main
main "$@"
