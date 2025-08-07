//nolint:staticcheck // no reason
package traefik_real_ip

import (
	"context"
	"errors"
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
	cloudFlareIPsInstance   []*net.IPNet
	cloudFlareIPsOnce       sync.Once
	ErrCloudflareHTTPStatus = errors.New("failed to fetch Cloudflare IPs")
)

const (
	defaultTimeout = 10 * time.Second
)

func (resolver *IPResolver) getCloudFlareIPs(ctx context.Context) []*net.IPNet {
	cloudFlareIPsOnce.Do(func() {
		cloudFlareIPsInstance = make([]*net.IPNet, 0)

		ipv4, err := resolver.getCloudFlareIPFromURL(ctx, "https://www.cloudflare.com/ips-v4")
		if err != nil {
			resolver.logger.ErrorContext(
				ctx,
				"Error fetching Cloudflare IPs",
				slog.String("url", "https://www.cloudflare.com/ips-v4"),
				slog.Any("error", err),
			)
			panic(fmt.Sprintf("Error fetching Cloudflare IPs: %v", err))
		}

		cloudFlareIPsInstance = append(cloudFlareIPsInstance, ipv4...)

		ipv6, err := resolver.getCloudFlareIPFromURL(ctx, "https://www.cloudflare.com/ips-v6")
		if err != nil {
			resolver.logger.ErrorContext(
				ctx,
				"Error fetching Cloudflare IPs",
				slog.String("url", "https://www.cloudflare.com/ips-v6"),
				slog.Any("error", err),
			)
			panic(fmt.Sprintf("Error fetching Cloudflare IPs: %v", err))
		}

		cloudFlareIPsInstance = append(cloudFlareIPsInstance, ipv6...)
	})

	return cloudFlareIPsInstance
}

func (resolver *IPResolver) getCloudFlareIPFromURL(
	ctx context.Context,
	url string,
) ([]*net.IPNet, error) {
	ips := make([]*net.IPNet, 0)

	client := &http.Client{
		Timeout: defaultTimeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		resolver.logger.ErrorContext(
			ctx,
			"Error creating HTTP request",
			slog.String("url", url),
			slog.Any("error", err),
		)

		return ips, fmt.Errorf("error creating HTTP request: %w", err)
	}

	response, err := client.Do(req)
	if err != nil {
		resolver.logger.ErrorContext(
			ctx,
			"Error fetching Cloudflare IPs",
			slog.String("url", url),
			slog.Any("error", err),
		)

		return ips, fmt.Errorf("error fetching Cloudflare IPs: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		resolver.logger.ErrorContext(
			ctx,
			"Failed to fetch Cloudflare IPs",
			slog.String("url", url),
			slog.Int("status_code", response.StatusCode),
		)

		return nil, fmt.Errorf("%w: %s", ErrCloudflareHTTPStatus, response.Status)
	}

	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		resolver.logger.ErrorContext(
			ctx,
			"Error reading response body",
			slog.String("url", url),
			slog.Any("error", err),
		)

		return ips, fmt.Errorf("error reading response body: %w", err)
	}

	body := string(bytes)

	lines := strings.Split(body, "\n")

	for _, line := range lines {
		cidr := strings.TrimSpace(line)
		if cidr != "" {
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
	}

	return ips, nil
}
