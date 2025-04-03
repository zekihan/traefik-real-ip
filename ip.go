package traefik_real_ip

import (
	"log/slog"
	"net"
)

func (a *IPResolver) isTrustedIP(ip net.IP) bool {
	for _, ipNet := range a.trustedIPNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	a.logger.Debug("IP is not trusted", slog.String("ip", ip.String()))
	return false
}

func (a *IPResolver) isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return true
	}
	return false
}
