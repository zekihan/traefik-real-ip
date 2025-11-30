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
	ErrRemoteIPProviderHTTPStatus = errors.New("failed to fetch remote IP provider ranges")
)

const defaultRemoteProviderTimeout = 10 * time.Second

// remoteIPProvider describes a remote service exposing CIDR blocks.
type remoteIPProvider struct {
	once  *sync.Once
	cache *[]*net.IPNet
	urls  []string
	name  string
}

func (resolver *IPResolver) getProviderIPs(
	ctx context.Context,
	provider remoteIPProvider,
) []*net.IPNet {
	// If cache is already populated, return it directly to avoid
	// triggering provider.once.Do (which may fetch remote URLs).
	if provider.cache != nil && *provider.cache != nil {
		return *provider.cache
	}
	provider.once.Do(func() {
		results := make([]*net.IPNet, 0)

		for _, url := range provider.urls {
			ips, err := resolver.getProviderIPsFromURL(ctx, provider.name, url)
			if err != nil {
				// Log the error and continue with other URLs. Do not panic so tests
				// and callers can handle missing remote data (e.g. via fallbacks).
				resolver.logger.ErrorContext(
					ctx,
					"Error fetching provider IPs",
					slog.String("provider", provider.name),
					slog.String("url", url),
					slog.Any("error", err),
				)
				continue
			}

			results = append(results, ips...)
		}

		*provider.cache = results
	})

	return *provider.cache
}

func (resolver *IPResolver) getProviderIPsFromURL(
	ctx context.Context,
	providerName string,
	url string,
) ([]*net.IPNet, error) {
	ips := make([]*net.IPNet, 0)

	client := &http.Client{Timeout: defaultRemoteProviderTimeout}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		resolver.logger.ErrorContext(
			ctx,
			"Error creating HTTP request",
			slog.String("provider", providerName),
			slog.String("url", url),
			slog.Any("error", err),
		)

		return ips, fmt.Errorf("error creating HTTP request: %w", err)
	}

	response, err := client.Do(req)
	if err != nil {
		resolver.logger.ErrorContext(
			ctx,
			"Error fetching provider IPs",
			slog.String("provider", providerName),
			slog.String("url", url),
			slog.Any("error", err),
		)

		return ips, fmt.Errorf("error fetching %s IPs: %w", providerName, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		resolver.logger.ErrorContext(
			ctx,
			"Failed to fetch provider IPs",
			slog.String("provider", providerName),
			slog.String("url", url),
			slog.Int("status_code", response.StatusCode),
		)

		return nil, fmt.Errorf("%w: %s", ErrRemoteIPProviderHTTPStatus, response.Status)
	}

	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		resolver.logger.ErrorContext(
			ctx,
			"Error reading response body",
			slog.String("provider", providerName),
			slog.String("url", url),
			slog.Any("error", err),
		)

		return ips, fmt.Errorf("error reading response body: %w", err)
	}

	body := string(bytes)

	//nolint:modernize // yaegi does not support strings.SplitSeq
	lines := strings.Split(body, "\n")

	for _, line := range lines {
		cidr := strings.TrimSpace(line)
		if cidr == "" {
			continue
		}

		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			resolver.logger.ErrorContext(
				ctx,
				"Error parsing CIDR",
				slog.String("provider", providerName),
				slog.String("cidr", cidr),
				slog.Any("error", err),
			)

			return ips, fmt.Errorf("error parsing CIDR %s: %w", cidr, err)
		}

		ips = append(ips, block)
	}

	return ips, nil
}
