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
	cfIPsInstance []*net.IPNet
	cfIPsOnce     sync.Once
)

func (a *IPResolver) isTrustedIP(ip net.IP) bool {
	if a.isLocalIP(ip) {
		return true
	}
	for _, ipNet := range a.trustedIPNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	if a.isCFIP(ip) {
		return true
	}
	a.logger.Debug("IP is not trusted", slog.String("ip", ip.String()))
	return false
}

func (a *IPResolver) isCFIP(ip net.IP) bool {
	ips := a.getCFIPs()
	for _, cidr := range ips {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *IPResolver) getCFIPs() []*net.IPNet {
	cfIPsOnce.Do(func() {
		cfIPsInstance = make([]*net.IPNet, 0)

		ipv4, err := a.getCFIP("https://www.cloudflare.com/ips-v4")
		if err != nil {
			a.logger.Error("Error fetching Cloudflare IPs", slog.String("url", "https://www.cloudflare.com/ips-v4"), slog.Any("error", err))
			panic(fmt.Sprintf("Error fetching Cloudflare IPs: %v", err))
		}
		cfIPsInstance = append(cfIPsInstance, ipv4...)

		ipv6, err := a.getCFIP("https://www.cloudflare.com/ips-v6")
		if err != nil {
			a.logger.Error("Error fetching Cloudflare IPs", slog.String("url", "https://www.cloudflare.com/ips-v6"), slog.Any("error", err))
			panic(fmt.Sprintf("Error fetching Cloudflare IPs: %v", err))
		}
		cfIPsInstance = append(cfIPsInstance, ipv6...)
	})
	return cfIPsInstance
}

func (a *IPResolver) getCFIP(url string) ([]*net.IPNet, error) {
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

func (a *IPResolver) isLocalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return true
	}
	return false
}
