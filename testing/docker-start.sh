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

docker network create traefik-real-ip_proxy || true
docker network create traefik-real-ip_default || true

docker run -d \
    --name traefik-real-ip_traefik \
    --network traefik-real-ip_proxy \
    --network traefik-real-ip_default \
    -p 4008:80 \
    -v "${PROJECT_ROOT}/${COMPOSE_DIR}"/traefik.yaml:/etc/traefik/traefik.yaml \
    -v "${PROJECT_ROOT}/${COMPOSE_DIR}"/config:/etc/traefik/mconfig \
    -v "${PROJECT_ROOT}":/plugins-local/src/github.com/zekihan/traefik-real-ip:ro \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -v /etc/localtime:/etc/localtime:ro \
    --health-cmd="traefik healthcheck | grep OK" \
    --health-interval=1s \
    --health-timeout=3s \
    --health-retries=5 \
    docker.io/traefik:v3.6.5@sha256:4ec25d36f3203240bc1631bb43954c61e872331ab693e741398f1dde6974c145

wait_for_services "traefik-real-ip_traefik"

docker run -d \
    --name traefik-real-ip_whoami \
    --network traefik-real-ip_proxy \
    -v /etc/localtime:/etc/localtime:ro \
    --label "traefik.http.services.traefik-real-ip_whoami.loadbalancer.server.port=80" \
    --label "traefik.http.services.traefik-real-ip_whoami.loadbalancer.server.scheme=http" \
    --label "traefik.http.services.traefik-real-ip_whoami.loadbalancer.passhostheader=true" \
    --label "traefik.http.routers.traefik-real-ip_whoami.service=traefik-real-ip_whoami" \
    --label "traefik.http.routers.traefik-real-ip_whoami.middlewares=standard@file" \
    --label "traefik.http.routers.traefik-real-ip_whoami.rule=Method(\`GET\`)" \
    --label "traefik.http.routers.traefik-real-ip_whoami.entrypoints=web" \
    --label "traefik.enable=true" \
    --label "traefik-real-ip.enable=true" \
    docker.io/traefik/whoami:v1.11.0@sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab

wait_for_services "traefik-real-ip_whoami"

wait_for_response
