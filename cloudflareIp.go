package traefik_real_ip

import (
	"context"
	"net"
)

const (
	cloudflareIPv4URL = "https://www.cloudflare.com/ips-v4"
	cloudflareIPv6URL = "https://www.cloudflare.com/ips-v6"
)

var cloudflareProvider = remoteIPProvider{
	name:  "Cloudflare",
	cache: new(remoteIPCache),
	sources: []remoteIPSource{
		{url: cloudflareIPv4URL, ipVersion: ipv4Version},
		{url: cloudflareIPv6URL, ipVersion: ipv6Version},
	},
}

func (resolver *IPResolver) getCloudFlareIPs(ctx context.Context) ([]*net.IPNet, error) {
	return resolver.getProviderIPs(ctx, cloudflareProvider)
}

func (resolver *IPResolver) getCloudFlareIPFromURL(
	ctx context.Context,
	url string,
) ([]*net.IPNet, error) {
	return resolver.getProviderIPsFromURL(ctx, cloudflareProvider.name, url)
}
