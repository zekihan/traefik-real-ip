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

// Default fallback CIDRs used when remote fetch fails (keeps tests deterministic).
var cloudFlareDefaultCIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
}

func parseDefaultCIDRs(defaults []string) []*net.IPNet {
	res := make([]*net.IPNet, 0, len(defaults))
	for _, s := range defaults {
		_, ipnet, err := net.ParseCIDR(s)
		if err == nil {
			res = append(res, ipnet)
		}
	}
	return res
}

func (resolver *IPResolver) getCloudFlareIPs(ctx context.Context) []*net.IPNet {
	ips := resolver.getProviderIPs(ctx, cloudflareProvider)
	if len(ips) == 0 {
		// fallback to embedded defaults
		return parseDefaultCIDRs(cloudFlareDefaultCIDRs)
	}

	return ips
}

func (resolver *IPResolver) getCloudFlareIPFromURL(
	ctx context.Context,
	url string,
) ([]*net.IPNet, error) {
	return resolver.getProviderIPsFromURL(ctx, cloudflareProvider.name, url)
}
