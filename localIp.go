package traefik_real_ip

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
)

var (
	localIPsInstance []*net.IPNet
	localIPsOnce     sync.Once
)

func (resolver *IPResolver) getLocalIPs(ctx context.Context) []*net.IPNet {
	localIPsOnce.Do(func() {
		localIPsInstance = make([]*net.IPNet, 0)

		ips, err := resolver.getLocalIPsHardcoded(ctx)
		if err != nil {
			resolver.logger.ErrorContext(ctx, "Error fetching local IPs", slog.Any("error", err))
			panic(err)
		}

		localIPsInstance = append(localIPsInstance, ips...)
	})

	return localIPsInstance
}

func (resolver *IPResolver) getLocalIPsHardcoded(ctx context.Context) ([]*net.IPNet, error) {
	ips := make([]*net.IPNet, 0)

	localIPRanges := []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local addr
		"fe80::/10",      // IPv6 link-local addr
	}
	for _, cidr := range localIPRanges {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			resolver.logger.ErrorContext(
				ctx,
				"Error parsing CIDR",
				slog.String("cidr", cidr),
				slog.Any("error", err),
			)

			return ips, fmt.Errorf("error parsing CIDR %s: %w", cidr, err)
		}

		ips = append(ips, block)
	}

	return ips, nil
}
