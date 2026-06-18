# AGENTS.md

This file provides guidance to AI Agents when working with code in this repository.

## What This Is

A Traefik middleware plugin that extracts and validates the real client IP from HTTP headers (`Cf-Connecting-Ip`, `Eo-Connecting-Ip`, `X-Real-IP`, `X-Forwarded-For`). It trusts headers only from configured trusted IP ranges (local, Cloudflare, EdgeOne, or custom CIDRs).

The plugin must be compatible with [yaegi](https://github.com/traefik/yaegi), Traefik's Go interpreter. This means no generics, no `strings.SplitSeq`, and other modern Go features may be unavailable — check existing `//nolint:modernize` comments for examples.

## Commands

```bash
# Format and tidy
make tidy

# Run linter (requires golangci-lint)
make lint

# Run all tests
make test

# Run a single test
go test -run TestName ./...

# Run tests with coverage
make test/cover

# Integration tests (requires Docker)
make test/integration

# Start local Docker test environment
make docker
```

## Architecture

**Entry point:** `traefikrealip.go` — implements the Traefik plugin interface (`CreateConfig`, `New`, `ServeHTTP`). On init, it concurrently fetches trusted IP ranges (local, Cloudflare, EdgeOne) and stores them as `[]*net.IPNet`.

**Request flow** (`ServeHTTP`):
1. Extract source IP from `req.RemoteAddr`
2. Check if source IP is trusted
3. If `denyUntrusted` is set and source is not trusted → 403
4. Resolve real IP via `getRealIP` (in `ip_resolver.go`): checks headers in order `Cf-Connecting-Ip` → `Eo-Connecting-Ip` → `X-Real-IP` → `X-Forwarded-For`; only checks headers if source is trusted
5. Set `X-Real-IP`, `X-Forwarded-For`, and `X-Is-Trusted` headers on the request

**IP provider pattern:** `cloudflareIp.go` and `edgeoneIp.go` each define a `remoteIPProvider` struct with a `sync.Once` and a cache pointer. Fetching is handled by `remote_provider.go` which does HTTP with retries. Local IPs are hardcoded RFC1918/loopback ranges in `localIp.go`.

**Key constraint:** The `sync.Once` instances for Cloudflare and EdgeOne are package-level globals, so IP ranges are fetched once per process lifetime and cached. Tests that need to reset this state use the `remote_ips/` directory for fixture data.

**Logger:** `logger.go` wraps `log/slog` as `PluginLogger`, bridging Traefik's logging interface. Log level is configurable per-instance.
