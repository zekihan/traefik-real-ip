# Traefik Real IP

A Traefik middleware plugin that extracts the real client IP address from various HTTP headers.

[![Traefik Plugin](https://img.shields.io/badge/Traefik%20Plugin-Traefik%20Real%20IP-blue)](https://plugins.traefik.io/plugins/67eb72e756c7ea30f22dd6be/traefik-real-ip)
[![Version](https://img.shields.io/badge/version-0.1.25-green)](https://github.com/zekihan/traefik-real-ip/releases/tag/v0.1.25)
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
      version: v0.1.25
```

## Configuration

### Static Configuration Example

```yaml
# Static configuration
experimental:
  plugins:
    traefik-real-ip:
      moduleName: github.com/zekihan/traefik-real-ip
      version: v0.1.25
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
Changing the default or removing deliberate abort retries requires maintainer agreement under
[OPS-16](https://noqer.atlassian.net/browse/OPS-16). This opt-in does not establish that agreement or change a live configuration.
See [synthetic replay results and the proposed policy](docs/panic-replay.md) for response semantics and remaining acceptance work.

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
go test ./...
```

## License

This project is licensed under the MIT License - see
the [LICENSE](https://github.com/zekihan/traefik-real-ip/blob/main/LICENSE) file for details.
