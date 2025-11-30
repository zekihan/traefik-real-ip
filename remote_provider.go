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

const (
	defaultRemoteProviderTimeout = 10 * time.Second
	maxRetries                   = 5
	initialRetryDelay            = 1 * time.Second
)

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

	var response *http.Response
	var lastErr error

	// Retry logic with exponential backoff
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Calculate delay with exponential backoff: 1s, 2s, 4s, 8s, 16s
			delay := initialRetryDelay * time.Duration(1<<uint(attempt-1))
			resolver.logger.InfoContext(
				ctx,
				"Retrying request",
				slog.String("provider", providerName),
				slog.String("url", url),
				slog.Int("attempt", attempt),
				slog.Duration("delay", delay),
			)

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ips, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
			}
		}

		response, err = client.Do(req)
		if err != nil {
			lastErr = err
			resolver.logger.WarnContext(
				ctx,
				"Request failed, will retry",
				slog.String("provider", providerName),
				slog.String("url", url),
				slog.Int("attempt", attempt+1),
				slog.Int("max_retries", maxRetries+1),
				slog.Any("error", err),
			)
			continue
		}

		// Check status code
		if response.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%w: %s", ErrRemoteIPProviderHTTPStatus, response.Status)
			_ = response.Body.Close()

			// Don't retry on client errors (4xx) - these won't be fixed by retrying
			if response.StatusCode >= 400 && response.StatusCode < 500 {
				resolver.logger.ErrorContext(
					ctx,
					"Client error, will not retry",
					slog.String("provider", providerName),
					slog.String("url", url),
					slog.Int("status_code", response.StatusCode),
				)
				return ips, lastErr
			}

			resolver.logger.WarnContext(
				ctx,
				"Request returned non-OK status, will retry",
				slog.String("provider", providerName),
				slog.String("url", url),
				slog.Int("status_code", response.StatusCode),
				slog.Int("attempt", attempt+1),
				slog.Int("max_retries", maxRetries+1),
			)
			continue
		}

		// Success - break out of retry loop
		break
	}

	// If we exhausted all retries
	if response == nil || response.StatusCode != http.StatusOK {
		resolver.logger.ErrorContext(
			ctx,
			"Failed to fetch provider IPs after retries",
			slog.String("provider", providerName),
			slog.String("url", url),
			slog.Int("max_retries", maxRetries+1),
			slog.Any("error", lastErr),
		)

		if lastErr != nil {
			return ips, fmt.Errorf("error fetching %s IPs after %d retries: %w", providerName, maxRetries+1, lastErr)
		}
		return ips, fmt.Errorf("error fetching %s IPs: unknown error after retries", providerName)
	}

	defer func() { _ = response.Body.Close() }()

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
