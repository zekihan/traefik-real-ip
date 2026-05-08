#!/bin/sh

set -e

# Integration Test Script for Traefik Real IP Plugin
# This script is intended to run inside the scripts Docker container.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TRAEFIK_URL="${TRAEFIK_URL:-http://traefik-real-ip_traefik}"
TEST_HOST_HEADER="${TEST_HOST_HEADER:-test.local}"
VERBOSE="${VERBOSE:-0}"

log_info() {
    printf "%b\n" "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    printf "%b\n" "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    printf "%b\n" "${RED}[ERROR]${NC} $1"
}

log_test() {
    printf "%b\n" "${GREEN}[TEST]${NC} $1"
}

check_prerequisites() {
    log_info "Checking in-container prerequisites..."

    if ! command -v curl >/dev/null 2>&1; then
        log_error "curl is not installed in the scripts container"
        exit 1
    fi

    log_info "Prerequisites OK"
}

request_status() {
    curl -q -s -o /dev/null -w "%{http_code}" "$1" -H "Host: ${TEST_HOST_HEADER}"
}

request_body() {
    url="$1"
    shift
    curl -q -s "$url" -H "Host: ${TEST_HOST_HEADER}" "$@"
}

print_response_if_verbose() {
    if [ "${VERBOSE}" -eq 1 ]; then
        log_info "Response:\n$1"
    fi
}

assert_contains() {
    response="$1"
    expected="$2"
    success_message="$3"
    failure_message="$4"

    if printf "%s" "${response}" | grep -qi "${expected}"; then
        log_info "✓ ${success_message}"
        return 0
    fi

    log_warn "⚠ ${failure_message}"
    return 1
}

test_endpoint() {
    log_test "Testing endpoint accessibility..."

    response_code=$(request_status "${TRAEFIK_URL}")
    if [ "${response_code}" = "200" ]; then
        log_info "✓ Endpoint is accessible (HTTP ${response_code})"
        return 0
    fi

    log_error "✗ Endpoint returned HTTP ${response_code}"
    return 1
}

test_x_forwarded_for() {
    log_test "Testing X-Forwarded-For header..."

    response=$(request_body "${TRAEFIK_URL}" -H "X-Forwarded-For: 203.0.113.1")
    print_response_if_verbose "${response}"

    assert_contains \
        "${response}" \
        "X-Real-Ip: 203.0.113.1" \
        "X-Forwarded-For header correctly reflected in response" \
        "X-Forwarded-For header not correctly reflected in response (may be expected)"
}

test_x_real_ip() {
    log_test "Testing X-Real-IP header..."

    response=$(request_body "${TRAEFIK_URL}" -H "X-Real-IP: 203.0.113.2")
    print_response_if_verbose "${response}"

    assert_contains \
        "${response}" \
        "X-Real-Ip: 203.0.113.2" \
        "X-Real-IP header correctly reflected in response" \
        "X-Real-IP header not correctly reflected in response (may be expected)"
}

test_cloudflare_header() {
    log_test "Testing Cf-Connecting-Ip header..."

    response=$(request_body "${TRAEFIK_URL}" -H "Cf-Connecting-Ip: 203.0.113.3")
    print_response_if_verbose "${response}"

    assert_contains \
        "${response}" \
        "X-Real-Ip: 203.0.113.3" \
        "Cf-Connecting-Ip header correctly mapped to X-Real-IP in response" \
        "Cf-Connecting-Ip header not correctly mapped in response (may be expected)"
}

test_edgeone_header() {
    log_test "Testing Eo-Connecting-Ip header..."

    response=$(request_body "${TRAEFIK_URL}" -H "Eo-Connecting-Ip: 203.0.113.30")
    print_response_if_verbose "${response}"

    assert_contains \
        "${response}" \
        "X-Real-Ip: 203.0.113.30" \
        "Eo-Connecting-Ip header correctly mapped to X-Real-IP in response" \
        "Eo-Connecting-Ip header not correctly mapped in response (may be expected)"
}

test_edgeone_priority() {
    log_test "Eo-Connecting-Ip takes priority over X-Real-IP and X-Forwarded-For"

    response=$(request_body "${TRAEFIK_URL}" \
        -H "X-Forwarded-For: 5.5.5.5" \
        -H "X-Real-IP: 9.9.9.9" \
        -H "Eo-Connecting-Ip: 45.45.45.45")
    print_response_if_verbose "${response}"

    assert_contains \
        "${response}" \
        "X-Real-Ip: 45.45.45.45" \
        "Eo-Connecting-Ip header correctly prioritized over other headers" \
        "Eo-Connecting-Ip header not prioritized over other headers (may be expected)"
}

test_multiple_headers() {
    log_test "Testing multiple proxy headers..."

    response=$(request_body "${TRAEFIK_URL}" \
        -H "X-Forwarded-For: 1.2.3.4, 5.6.7.8" \
        -H "X-Real-IP: 9.10.11.12" \
        -H "Eo-Connecting-Ip: 17.18.19.20" \
        -H "Cf-Connecting-Ip: 13.14.15.16")
    print_response_if_verbose "${response}"

    assert_contains \
        "${response}" \
        "X-Real-Ip: 13.14.15.16" \
        "Cf-Connecting-Ip header correctly prioritized in response" \
        "Cf-Connecting-Ip header not prioritized in response (may be expected)"
}

show_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Run Traefik integration checks from inside the scripts container.

Options:
    --verbose, -v     Show verbose output
    --help, -h        Show this help message

Environment Variables:
    TRAEFIK_URL       Traefik URL visible from the container (default: http://traefik-real-ip_traefik)
    TEST_HOST_HEADER  Host header used for requests (default: test.local)
    VERBOSE           Set to 1 for verbose output
EOF
}

main() {
    show_usage=0

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --verbose|-v)
                VERBOSE=1
                shift
                ;;
            --help|-h)
                show_usage=1
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage=1
                shift
                ;;
        esac
    done

    if [ "${show_usage}" -eq 1 ]; then
        show_help
        exit 0
    fi

    log_info "Running Traefik Real IP integration tests inside Docker"
    check_prerequisites

    failed=0
    test_endpoint || failed=$((failed + 1))
    test_x_forwarded_for || failed=$((failed + 1))
    test_x_real_ip || failed=$((failed + 1))
    test_cloudflare_header || failed=$((failed + 1))
    test_edgeone_header || failed=$((failed + 1))
    test_edgeone_priority || failed=$((failed + 1))
    test_multiple_headers || failed=$((failed + 1))

    printf "\n"
    log_info "================================"
    if [ "${failed}" -eq 0 ]; then
        log_info "All tests passed! ✓"
        log_info "================================"
        exit 0
    fi

    log_error "Some tests failed: ${failed}"
    log_error "================================"
    exit 1
}

main "$@"
