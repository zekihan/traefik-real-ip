# Traefik Real IP

A Traefik middleware plugin that extracts the real client IP address from various HTTP headers.

[![Traefik Plugin](https://img.shields.io/badge/Traefik%20Plugin-Traefik%20Real%20IP-blue)](https://plugins.traefik.io/plugins/67eb72e756c7ea30f22dd6be/traefik-real-ip)
[![Version](https://img.shields.io/badge/version-0.1.11-green)](https://github.com/zekihan/traefik-real-ip/releases/tag/v0.1.11)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/zekihan/traefik-real-ip/blob/main/LICENSE)

## Overview

Traefik Real IP extracts and validates the actual client IP address from commonly used headers such as `X-Forwarded-For`, `X-Real-IP`, and `CF-Connecting-IP`. This plugin is particularly useful when Traefik is behind a CDN, proxy, or load balancer like Cloudflare.

## Features

- Extracts real IP from `CF-Connecting-IP`, `X-Real-IP`, and `X-Forwarded-For` headers
- Validates whether the source IP is trusted before accepting header values
- Built-in support for Cloudflare IP ranges
- Supports local/private IP ranges
- Custom trusted IP configuration
- Configurable logging level

## Installation

### From Traefik Pilot

The easiest way to install this plugin is through the [Traefik Plugin Catalog](https://plugins.traefik.io/plugins/67eb72e756c7ea30f22dd6be/traefik-real-ip).

### Manual Installation

Add the plugin to your Traefik static configuration:

```yaml
experimental:
  plugins:
    traefik-real-ip:
      moduleName: github.com/zekihan/traefik-real-ip
      version: v0.1.11
```

## Configuration

### Static Configuration Example

```yaml
# Static configuration
experimental:
  plugins:
    traefik-real-ip:
      moduleName: github.com/zekihan/traefik-real-ip
      version: v0.1.11
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
          trustedIPs: 
            - "1.2.3.4/32"
            - "10.0.0.0/8"
          logLevel: info
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `thrustLocal` | boolean | `true` | Trust local and private IP ranges |
| `thrustCloudFlare` | boolean | `true` | Trust Cloudflare IP ranges |
| `trustedIPs` | array of strings | `[]` | Additional IP ranges to trust in CIDR notation |
| `logLevel` | string | `info` | Log level (debug, info, warn, error) |

## How It Works

1. The plugin extracts the source IP from the incoming request
2. It checks if the source IP is in the trusted IPs list
3. If trusted, it looks for real IP in headers:
   - First checks `CF-Connecting-IP`
   - Then checks `X-Real-IP`
   - Finally checks `X-Forwarded-For`
4. It updates the request headers with the discovered real IP
5. Adds an `X-Is-Trusted: yes|no` header indicating if the source was trusted

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

This project is licensed under the MIT License - see the [LICENSE](https://github.com/zekihan/traefik-real-ip/blob/main/LICENSE) file for details.
