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

func (resolver *IPResolver) getEdgeOneIPs(ctx context.Context) []*net.IPNet {
	return resolver.getProviderIPs(ctx, edgeOneProvider)
}

func (resolver *IPResolver) getEdgeOneIPFromURL(
	ctx context.Context,
	url string,
) ([]*net.IPNet, error) {
	return resolver.getProviderIPsFromURL(ctx, edgeOneProvider.name, url)
}
