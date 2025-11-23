#!/bin/sh

set -e

docker rm -f traefik-real-ip_traefik || true
docker rm -f traefik-real-ip_whoami || true

docker network rm traefik-real-ip_proxy || true
docker network rm traefik-real-ip_default || true
