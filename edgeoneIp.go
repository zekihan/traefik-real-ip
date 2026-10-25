package traefik_real_ip

import (
	"context"
	"net"
)

const (
	edgeOneIPURL = "https://raw.githubusercontent.com/zekihan/traefik-real-ip/refs/heads/main/remote_ips/edgeone"
)

var edgeOneProvider = remoteIPProvider{
	name:  "EdgeOne",
	urls:  []string{edgeOneIPURL},
	cache: new(remoteIPCache),
}

func (resolver *IPResolver) getEdgeOneIPs(ctx context.Context) ([]*net.IPNet, error) {
	return resolver.getProviderIPs(ctx, edgeOneProvider)
}

func (resolver *IPResolver) getEdgeOneIPFromURL(
	ctx context.Context,
	url string,
) ([]*net.IPNet, error) {
	return resolver.getProviderIPsFromURL(ctx, edgeOneProvider.name, url)
}
