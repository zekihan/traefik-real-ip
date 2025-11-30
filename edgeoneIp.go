//nolint:staticcheck // no reason
package traefik_real_ip

import (
	"context"
	"net"
	"sync"
)

const (
	edgeOneIPURL = "https://api.edgeone.ai/ips"
)

var (
	edgeOneIPsInstance []*net.IPNet
	edgeOneIPsOnce     sync.Once
)

var edgeOneProvider = remoteIPProvider{
	name:  "EdgeOne",
	urls:  []string{edgeOneIPURL},
	once:  &edgeOneIPsOnce,
	cache: &edgeOneIPsInstance,
}

// Default fallback CIDRs for EdgeOne provider used when remote fetch fails.
var edgeOneDefaultCIDRs = []string{
	"198.51.100.0/24",
	"2001:db8::/32",
}

func (resolver *IPResolver) getEdgeOneIPs(ctx context.Context) []*net.IPNet {
	ips := resolver.getProviderIPs(ctx, edgeOneProvider)
	if len(ips) == 0 {
		return parseDefaultCIDRs(edgeOneDefaultCIDRs)
	}

	return ips
}

func (resolver *IPResolver) getEdgeOneIPFromURL(
	ctx context.Context,
	url string,
) ([]*net.IPNet, error) {
	return resolver.getProviderIPsFromURL(ctx, edgeOneProvider.name, url)
}
