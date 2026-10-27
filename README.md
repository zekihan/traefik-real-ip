# Traefik Real IP

A Traefik middleware plugin that extracts the real client IP address from various HTTP headers.

[![Traefik Plugin](https://img.shields.io/badge/Traefik%20Plugin-Traefik%20Real%20IP-blue)](https://plugins.traefik.io/plugins/67eb72e756c7ea30f22dd6be/traefik-real-ip)
[![Version](https://img.shields.io/badge/version-0.2.0-green)](https://github.com/zekihan/traefik-real-ip/releases/tag/v0.2.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/zekihan/traefik-real-ip/blob/main/LICENSE)

## Overview

Traefik Real IP extracts and validates the actual client IP address from commonly used headers such as
`X-Forwarded-For`, `X-Real-IP`, and `Cf-Connecting-Ip`. This plugin is particularly useful when Traefik is behind a CDN,
proxy, or load balancer like Cloudflare.

## Features

- Extracts real IP from `Cf-Connecting-Ip`, `Eo-Connecting-Ip`, `X-Real-IP`, and `X-Forwarded-For` headers
- Validates whether the source IP is trusted before accepting header values
- Built-in support for Cloudflare IP ranges
- Optional support for EdgeOne IP ranges
- Supports local/private IP ranges
- Custom trusted IP configuration
- Configurable logging level

## Installation

### From Traefik Pilot

The easiest way to install this plugin is through
the [Traefik Plugin Catalog](https://plugins.traefik.io/plugins/67eb72e756c7ea30f22dd6be/traefik-real-ip).

### Manual Installation

Add the plugin to your Traefik static configuration:

```yaml
experimental:
  plugins:
    traefik-real-ip:
      moduleName: github.com/zekihan/traefik-real-ip
      version: v0.2.0
```

## Configuration

### Static Configuration Example

```yaml
# Static configuration
experimental:
  plugins:
    traefik-real-ip:
      moduleName: github.com/zekihan/traefik-real-ip
      version: v0.2.0
```

### Middleware Configuration

```yaml
# Dynamic configuration
http:
  middlewares:
    traefik-real-ip:
      plugin:
        traefik-real-ip:
          thrustLocal: true
          thrustCloudFlare: true
          thrustEdgeOne: false
          trustedIPs:
            - "1.2.3.4/32"
            - "10.0.0.0/8"
          logLevel: info
          denyUntrusted: false
          xForwardedForMode: append
```

### Configuration Options

| Option              | Type             | Default  | Description                                                                                                 |
|---------------------|------------------|----------|-------------------------------------------------------------------------------------------------------------|
| `thrustLocal`       | boolean          | `true`   | Trust local and private IP ranges                                                                           |
| `thrustCloudFlare`  | boolean          | `true`   | Trust Cloudflare IP ranges                                                                                  |
| `thrustEdgeOne`     | boolean          | `false`  | Trust EdgeOne IP ranges                                                                                     |
| `trustedIPs`        | array of strings | `[]`     | Additional IP ranges to trust in CIDR notation                                                              |
| `logLevel`          | string           | `info`   | Log level (debug, info, warn, error)                                                                        |
| `denyUntrusted`     | boolean          | `false`  | Deny requests from untrusted IPs with 403 Forbidden                                                         |
| `panicPolicy`       | string           | `legacy-retry` | Panic handling: `legacy-retry` preserves retries; `propagate` prevents middleware replay (see below) |
| `xForwardedForMode` | string           | `append` | How to write `X-Forwarded-For`: `append` preserves proxy hops; `replace` writes only the resolved client IP |

Remote providers must return valid, nonempty CIDR lists from every required URL before the plugin can initialize.
If an enabled provider fails, `New` returns an error, even when local or custom trusted ranges are configured.
Failed loads do not populate the process cache: a later middleware initialization can retry without a process restart.
Successful lists are cached for the process lifetime; there is no periodic refresh or persisted fallback.

Each remote response is limited to 1 MiB after HTTP decompression, lines shorter than 4 KiB, and 4,096 CIDR entries
(counting duplicates). Canonical duplicate ranges are removed within and across provider URLs, and a provider snapshot
can contain at most 4,096 unique ranges. Empty, malformed, oversized, or default-route (`0.0.0.0/0`, `::/0`) lists are
rejected in full. These validation limits apply to remote providers; custom `trustedIPs` retain their existing behavior.

## How It Works

1. The plugin extracts the source IP from the incoming request
2. It checks if the source IP is in the trusted IPs list
3. If `denyUntrusted` is enabled and the source IP is not trusted, it returns a 403 Forbidden response
4. If trusted, it looks for real IP in headers in this order: `Cf-Connecting-Ip`, `Eo-Connecting-Ip`, `X-Real-IP`, then
   `X-Forwarded-For`.
5. It updates the request headers with the discovered real IP
6. Adds an `X-Is-Trusted: yes|no` header indicating if the source was trusted

## Panic Handling

Set `panicPolicy: propagate` to prevent this middleware from invoking downstream again after a panic:

```yaml
http:
  middlewares:
    traefik-real-ip:
      plugin:
        traefik-real-ip:
          panicPolicy: propagate
```

This policy rethrows the original panic to the enclosing HTTP server or recovery middleware. It does not
rewind request bodies, retry canceled requests, append a replacement response, or manufacture a success response.
`http.ErrAbortHandler` remains an abort signal. Already committed downstream actions and response bytes cannot
be undone. An outer recovery middleware can still choose a different response or retry policy.

The default, `legacy-retry` (also selected by an omitted or empty value), preserves the existing behavior,
including possible duplicate downstream actions and retries with consumed bodies. Unknown values fail initialization.
**The default still permits downstream replay; OPS-16 is not fully resolved by adding this opt-in.** Preserving
compatibility avoids silently removing existing abort retries, at the cost of retaining that risk until a policy is agreed.
Changing the default or removing deliberate abort retries requires maintainer agreement under
[OPS-16](https://noqer.atlassian.net/browse/OPS-16). This opt-in does not establish that agreement or change a live configuration.
See [synthetic replay results and the operator migration checklist](docs/panic-replay.md) for response semantics,
the proposed policy, and remaining acceptance work.

## Forwarded Identity Trust Boundary

`X-Forwarded-For` resolution starts at the socket peer (`RemoteAddr`). Headers from an untrusted
peer are ignored. For a trusted peer, the plugin validates the entire XFF field, then walks from
right to left through the contiguous suffix of addresses in the configured trusted ranges. The
first untrusted hop is the client boundary, even when that address is private. It never skips an
untrusted hop to select a public address further left.

For example, with only `192.0.2.0/24` trusted, a peer at `192.0.2.1` and XFF
`198.51.100.66, 203.0.113.10, 192.0.2.2` resolve to `203.0.113.10`. The leftmost address
cannot override that boundary. A trusted socket peer is sufficient when there are no additional
trusted proxies in the header: `198.51.100.66, 203.0.113.10` still resolves to `203.0.113.10`.

When XFF is selected, repeated header fields, empty or malformed entries, more than 32 hops,
and values over 4,096 bytes return HTTP 400. If every parsed address is trusted, the plugin
selects the first (leftmost) address after validating the complete chain. This supports home
networks where clients and proxies all use trusted local addresses. Mixed chains still select
the first untrusted hop from the right. Malformed entries are never silently dropped.

Trust only proxy ranges controlled by your deployment. Every trusted proxy must remove or
sanitize client-supplied identity headers and accurately append its observed upstream peer to
XFF (or replace the chain with a verified client address). The existing `thrustLocal` default
trusts broad private ranges; operators must review whether those ranges contain untrusted
clients. No trust configuration is changed automatically.

Header priority remains `Cf-Connecting-Ip`, `Eo-Connecting-Ip`, `X-Real-IP`, then XFF; a valid
higher-priority header bypasses XFF resolution. Trusted proxies must strip or overwrite those
headers as well. `xForwardedForMode` only controls the outgoing header. `append` retains
incoming entries, including an untrusted prefix; downstream consumers must not treat every
retained entry as authoritative. Use `replace` when a downstream consumer requires a single
resolved client address.

Malformed identity headers return a fixed response without echoing their values. Validation
diagnostics are emitted only at debug level, contain header lengths rather than raw values,
and do not include stack traces. Single-address identity headers are limited to 45 bytes.

### Private-network trust and migration

A trusted address means **authorized to assert another host's identity**, not simply permitted
to connect. The plugin cannot distinguish a private client from a private proxy by address
syntax. `thrustLocal: true` includes RFC1918, loopback, IPv6 unique-local and link-local
ranges. The defaults are unchanged: trusting these networks intentionally allows hosts within
them to assert client identity.

An existing middleware configuration illustrates this private-network preference:

```yaml
thrustLocal: true
thrustCloudFlare: true
trustedIPs: []
xForwardedForMode: append
```

For a synthetic example, peer `10.0.0.1` with XFF `10.20.0.10, 10.0.0.2` resolves to
`10.20.0.10` under broad local trust. A single trusted hop `10.20.0.10` also resolves to
that address. IPv6 works the same way: peer `fd00::1` with `fd20::10, fd00::2` resolves
to `fd20::10`. An all-trusted chain is not rejected solely for lacking an untrusted hop.

The leftmost address does **not** independently prove the actual origin. For example, a
trusted host can prepend `10.99.0.66` to the IPv4 chain above, and the resulting all-trusted
chain resolves to that asserted address. A trusted host can also forward a fabricated public
address: `203.0.113.66, 10.20.0.10, 10.0.0.2` resolves to `203.0.113.66` as the first
untrusted hop from the right. This is the authority granted by broad private-network trust.
By contrast, `10.99.0.66, 203.0.113.10, 10.0.0.2` resolves to `203.0.113.10`; the
untrusted boundary prevents a further-left prefix from overriding it.

Operators who prefer to separate clients from proxies can evaluate `thrustLocal: false` and
trust only verified proxy hosts or dedicated proxy subnets in an isolated environment. With
only `10.0.0.1/32` and `10.0.0.2/32` trusted, the chain
`203.0.113.66, 10.20.0.10, 10.0.0.2` resolves to private client `10.20.0.10`. The equivalent
IPv6 fixture trusts `fd00::1/128`, `fd00::2/128` with client `fd20::10`. These are synthetic
examples, not selected deployment ranges. Any operator policy change affects all identity
headers and can affect `denyUntrusted`; review enabled provider ranges and test both direct
and proxied traffic. No default or live trust settings are changed by this PR.

`xForwardedForMode` only changes the outgoing header; it does not change identity selection.
Trusted proxies must sanitize identity headers according to the authority their operators
intend to grant. Synthetic tests cover the existing broad-trust configuration, precise proxy
ranges, accepted all-trusted assertions, and mixed-chain boundaries with offline fixtures.

## Protecting Against Direct Access

If your server has a public IP but uses a WAF/CDN like Cloudflare, you may want to ensure that traffic can only reach
your server through the WAF/CDN. Enable the `denyUntrusted` option to reject any traffic that doesn't come from trusted
IP ranges (such as Cloudflare IPs).

```yaml
http:
  middlewares:
    traefik-real-ip:
      plugin:
        traefik-real-ip:
          thrustCloudFlare: true
          denyUntrusted: true
```

With this configuration, requests that bypass Cloudflare and reach your server directly will receive a `403 Forbidden`
response.

## Development

### Testing Locally

A Docker Compose setup is provided in the `testing` folder to test the plugin locally:

```bash
cd testing
docker-compose up -d
```

### Running Tests

```bash
make test
```

Tests serve checked-in provider snapshots and use loopback HTTP fixtures; external service
requests are blocked. Run `make lint` and `go build ./...` for the other local checks. Actual
proxy append/sanitization behavior and Traefik/Yaegi integration still require an isolated
acceptance environment before deployment.

## License

This project is licensed under the MIT License - see
the [LICENSE](https://github.com/zekihan/traefik-real-ip/blob/main/LICENSE) file for details.
