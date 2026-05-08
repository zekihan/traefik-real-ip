#!/bin/bash

set -e

DIR=$(cd -P -- "$(dirname -- "$(command -v -- "$0")")" && pwd -P)
PROJECT_ROOT="${DIR}/.."

cd "${PROJECT_ROOT}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

COMPOSE_DIR="${COMPOSE_DIR:-testing}"
SCRIPTS_CONTAINER_NAME="${SCRIPTS_CONTAINER_NAME:-traefik-real-ip_scripts}"
INNER_TEST_SCRIPT="${INNER_TEST_SCRIPT:-/scripts/integration_test.sh}"
INNER_TRAEFIK_URL="${INNER_TRAEFIK_URL:-http://traefik-real-ip_traefik}"
TEST_HOST_HEADER="${TEST_HOST_HEADER:-test.local}"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking host prerequisites..."

    if ! command -v docker &>/dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi

    log_info "Prerequisites OK"
}

start_services() {
    log_info "Starting Traefik, scripts, and whoami services..."
    cd "${PROJECT_ROOT}/${COMPOSE_DIR}"
    ./docker-start.sh
    cd "${PROJECT_ROOT}" >/dev/null
}

show_logs() {
    if [ "$1" = "traefik" ] || [ "$1" = "all" ]; then
        log_info "=== Traefik logs (last 50 lines) ==="
        docker logs traefik-real-ip_traefik 2>&1 | tail -50
    fi

    if [ "$1" = "whoami" ] || [ "$1" = "all" ]; then
        log_info "=== Whoami logs (last 50 lines) ==="
        docker logs traefik-real-ip_whoami 2>&1 | tail -50
    fi

    if [ "$1" = "scripts" ] || [ "$1" = "all" ]; then
        log_info "=== Scripts container logs (last 50 lines) ==="
        docker logs "${SCRIPTS_CONTAINER_NAME}" 2>&1 | tail -50
    fi
}

cleanup() {
    log_info "Cleaning up services..."
    cd "${PROJECT_ROOT}/${COMPOSE_DIR}"
    ./docker-cleanup.sh 2>/dev/null || true
    cd "${PROJECT_ROOT}" >/dev/null
    log_info "Cleanup complete"
}

ensure_scripts_container_running() {
    running=$(docker inspect --format '{{.State.Running}}' "${SCRIPTS_CONTAINER_NAME}" 2>/dev/null || true)
    if [ "${running}" != "true" ]; then
        log_error "Scripts container '${SCRIPTS_CONTAINER_NAME}' is not running"
        exit 1
    fi
}

run_inner_tests() {
    local docker_env=()

    docker_env+=( -e "TRAEFIK_URL=${INNER_TRAEFIK_URL}" )
    docker_env+=( -e "TEST_HOST_HEADER=${TEST_HOST_HEADER}" )

    if [ "${VERBOSE:-0}" -eq 1 ]; then
        docker_env+=( -e "VERBOSE=1" )
    fi

    log_info "Running integration tests inside ${SCRIPTS_CONTAINER_NAME}..."
    docker exec "${docker_env[@]}" "${SCRIPTS_CONTAINER_NAME}" sh "${INNER_TEST_SCRIPT}"
}

show_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Host-side wrapper that starts the Docker test environment and runs
\`${INNER_TEST_SCRIPT}\` inside the scripts container.

Options:
    --skip-cleanup    Don't cleanup services after tests
    --verbose, -v     Show verbose output
    --logs [service]  Show logs (traefik, whoami, scripts, or all)
    --help, -h        Show this help message

Environment Variables:
    COMPOSE_DIR            Directory with docker scripts (default: testing)
    SCRIPTS_CONTAINER_NAME Scripts container name (default: traefik-real-ip_scripts)
    INNER_TEST_SCRIPT      Path inside the container (default: /scripts/integration_test.sh)
    INNER_TRAEFIK_URL      Traefik URL visible from the container (default: http://traefik-real-ip_traefik)
    TEST_HOST_HEADER       Host header for test requests (default: test.local)

Examples:
    $0
    $0 --verbose
    $0 --skip-cleanup
    $0 --logs scripts
EOF
}

main() {
    local skip_cleanup=0
    local show_usage=0
    local logs_target=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-cleanup)
                skip_cleanup=1
                shift
                ;;
            --verbose|-v)
                VERBOSE=1
                shift
                ;;
            --help|-h)
                show_usage=1
                shift
                ;;
            --logs)
                logs_target="${2:-all}"
                if [[ $# -gt 1 ]]; then
                    shift 2
                else
                    shift
                fi
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage=1
                shift
                ;;
        esac
    done

    if [[ "${show_usage}" -eq 1 ]]; then
        show_help
        exit 0
    fi

    if [[ -n "${logs_target}" ]]; then
        show_logs "${logs_target}"
        exit 0
    fi

    log_info "Starting Traefik Real IP integration test wrapper"

    if [[ "${skip_cleanup}" -eq 0 ]]; then
        trap cleanup EXIT
    else
        log_warn "Skipping cleanup after tests"
    fi

    check_prerequisites
    start_services
    ensure_scripts_container_running
    run_inner_tests
}

main "$@"
