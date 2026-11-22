package traefik_real_ip

import (
	"context"
	"log/slog"
	"net"
)

func (resolver *IPResolver) isTrustedIP(ctx context.Context, ip net.IP) bool {
	for _, ipNet := range resolver.trustedIPNets {
		if ipNet.Contains(ip) {
			return true
		}
	}

	resolver.logger.DebugContext(ctx, "IP is not trusted", slog.String("ip", ip.String()))

	return false
}

// isPrivateIP reports addresses X-Real-IP must not assert. It is wider than the
// thrustLocal ranges: loopback, RFC 1918, IPv6 unique-local, and link-local unicast
// and multicast, including IPv4-mapped forms. 100.64.0.0/10 is not included.
func (resolver *IPResolver) isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return true
	}

	return false
}
