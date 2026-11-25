#!/bin/bash

set -e

DIR=$(cd -P -- "$(dirname -- "$(command -v -- "$0")")" && pwd -P)
PROJECT_ROOT="${DIR}/.."

cd "${PROJECT_ROOT}"
PROJECT_ROOT="$(pwd)"

# Configuration
TRAEFIK_PORT="${TRAEFIK_PORT:-4008}"
COMPOSE_DIR="${COMPOSE_DIR:-testing}"
TIMEOUT="${TIMEOUT:-60}"
SCRIPTS_CONTAINER_NAME="${SCRIPTS_CONTAINER_NAME:-traefik-real-ip_scripts}"

cd "${PROJECT_ROOT}/${COMPOSE_DIR}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

# Cleanup services
# shellcheck disable=SC2317
cleanup() {
    log_info "Cleaning up services..."
    cd "${PROJECT_ROOT}/${COMPOSE_DIR}"
    ./docker-cleanup.sh 2>/dev/null || true
    cd "${PROJECT_ROOT}" >/dev/null
    log_info "Cleanup complete"
}

#trap cleanup EXIT

# Wait for services to be healthy
wait_for_services() {
    service="$1"
    log_info "Waiting for ${service} to be healthy (timeout: ${TIMEOUT}s)..."

    local elapsed=0
    while ((elapsed < TIMEOUT)); do
        status=$(docker inspect --format "{{.State.Health.Status}}" "${service}" 2>/dev/null || true)
        if [[ -n "$status" && "$status" != "<no value>" ]]; then
            if echo "$status" | grep -q "healthy"; then
                log_info "${service} is healthy!"
                return
            fi
        else
            # No healthcheck configured; fall back to running state
            running=$(docker inspect --format "{{.State.Running}}" "${service}" 2>/dev/null || true)
            if [[ "$running" == "true" ]]; then
                log_info "${service} is running (no healthcheck)"
                return
            fi
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done

    log_error "${service} did not become healthy/running within ${TIMEOUT} seconds"
    docker logs "${service}" 2>&1 | tail -50
    exit 1
}

# Wait for services to be healthy
wait_for_response() {
    log_info "Waiting for http response"

    local elapsed=0
    while ((elapsed < TIMEOUT)); do
        response_code=$(curl -q -s -o /dev/null -w "%{http_code}" "http://localhost:${TRAEFIK_PORT}" -H "Host: test.local")
        if [ "${response_code}" = "200" ]; then
            log_info "✓ Endpoint is accessible (HTTP ${response_code})"
            return
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done

    log_error "Service did not respond within ${TIMEOUT} seconds"
    exit 1
}

cleanup || true
cd "${PROJECT_ROOT}/${COMPOSE_DIR}"

docker compose -f docker-compose.yaml up -d traefik whoami

wait_for_services "traefik-real-ip_traefik"

docker run -d \
    --name "${SCRIPTS_CONTAINER_NAME}" \
    --network traefik-real-ip_proxy \
    -v "${PROJECT_ROOT}/scripts":/scripts:ro \
    -v /etc/localtime:/etc/localtime:ro \
    -w /scripts \
    docker.io/curlimages/curl:8.8.0 \
    sh -c "sleep infinity"

docker network connect traefik-real-ip_default "${SCRIPTS_CONTAINER_NAME}" || true

wait_for_services "${SCRIPTS_CONTAINER_NAME}"

wait_for_services "traefik-real-ip_whoami"

wait_for_response
