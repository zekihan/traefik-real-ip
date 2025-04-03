package traefik_real_ip

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	cloudFlareIPsInstance []*net.IPNet
	cloudFlareIPsOnce     sync.Once
)

func (a *IPResolver) getCloudFlareIPs() []*net.IPNet {
	cloudFlareIPsOnce.Do(func() {
		cloudFlareIPsInstance = make([]*net.IPNet, 0)

		ipv4, err := a.getCloudFlareIPFromURL("https://www.cloudflare.com/ips-v4")
		if err != nil {
			a.logger.Error("Error fetching Cloudflare IPs", slog.String("url", "https://www.cloudflare.com/ips-v4"), slog.Any("error", err))
			panic(fmt.Sprintf("Error fetching Cloudflare IPs: %v", err))
		}
		cloudFlareIPsInstance = append(cloudFlareIPsInstance, ipv4...)

		ipv6, err := a.getCloudFlareIPFromURL("https://www.cloudflare.com/ips-v6")
		if err != nil {
			a.logger.Error("Error fetching Cloudflare IPs", slog.String("url", "https://www.cloudflare.com/ips-v6"), slog.Any("error", err))
			panic(fmt.Sprintf("Error fetching Cloudflare IPs: %v", err))
		}
		cloudFlareIPsInstance = append(cloudFlareIPsInstance, ipv6...)
	})
	return cloudFlareIPsInstance
}

func (a *IPResolver) getCloudFlareIPFromURL(url string) ([]*net.IPNet, error) {
	ips := make([]*net.IPNet, 0)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	response, err := client.Get(url)
	if err != nil {
		a.logger.Error("Error fetching Cloudflare IPs", slog.String("url", url), slog.Any("error", err))
		return ips, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		a.logger.Error("Failed to fetch Cloudflare IPs", slog.String("url", url), slog.Int("status_code", response.StatusCode))
		return nil, fmt.Errorf("failed to fetch Cloudflare IPs: %s", response.Status)
	}

	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		a.logger.Error("Error reading response body", slog.String("url", url), slog.Any("error", err))
		return ips, err
	}
	body := string(bytes)

	lines := strings.Split(body, "\n")

	for _, line := range lines {
		cidr := strings.TrimSpace(line)
		if cidr != "" {
			_, block, err := net.ParseCIDR(cidr)
			if err != nil {
				a.logger.Error("Error parsing CIDR", slog.String("cidr", cidr), slog.Any("error", err))
				return ips, err
			}
			ips = append(ips, block)
		}
	}
	return ips, nil
}
