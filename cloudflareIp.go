//nolint:staticcheck // no reason
package traefik_real_ip

import (
	"context"
	"net"
	"sync"
)

var (
	cloudFlareIPsInstance []*net.IPNet
	cloudFlareIPsOnce     sync.Once
)

const (
	cloudflareIPv4URL = "https://www.cloudflare.com/ips-v4"
	cloudflareIPv6URL = "https://www.cloudflare.com/ips-v6"
)

var cloudflareProvider = remoteIPProvider{
	name:  "Cloudflare",
	urls:  []string{cloudflareIPv4URL, cloudflareIPv6URL},
	once:  &cloudFlareIPsOnce,
	cache: &cloudFlareIPsInstance,
}

func (resolver *IPResolver) getCloudFlareIPs(ctx context.Context) []*net.IPNet {
	return resolver.getProviderIPs(ctx, cloudflareProvider)
}

func (resolver *IPResolver) getCloudFlareIPFromURL(
	ctx context.Context,
	url string,
) ([]*net.IPNet, error) {
	return resolver.getProviderIPsFromURL(ctx, cloudflareProvider.name, url)
}
