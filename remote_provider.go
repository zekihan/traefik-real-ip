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
	name  string
	urls  []string
}

func (resolver *IPResolver) getProviderIPs(
	ctx context.Context,
	provider remoteIPProvider,
) []*net.IPNet {
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
	req, err := resolver.buildRequest(ctx, providerName, url)
	if err != nil {
		return nil, err
	}

	resp, err := resolver.doRequestWithRetry(ctx, req, providerName, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := resolver.readResponseBody(ctx, resp, providerName, url)
	if err != nil {
		return nil, err
	}

	return resolver.parseCIDRs(ctx, body, providerName)
}

func (resolver *IPResolver) buildRequest(
	ctx context.Context,
	providerName string,
	url string,
) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		resolver.logger.ErrorContext(
			ctx,
			"Error creating HTTP request",
			slog.String("provider", providerName),
			slog.String("url", url),
			slog.Any("error", err),
		)

		return nil, fmt.Errorf("error creating HTTP request: %w", err)
	}

	return req, nil
}

func (resolver *IPResolver) doRequestWithRetry(
	ctx context.Context,
	req *http.Request,
	providerName string,
	url string,
) (*http.Response, error) {
	client := &http.Client{Timeout: defaultRemoteProviderTimeout}

	var (
		lastErr  error
		response *http.Response
	)

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := initialRetryDelay * (1 << (attempt - 1))
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
				return nil, fmt.Errorf("context canceled during retry: %w", ctx.Err())
			}
		}

		response, lastErr = client.Do(req)
		if lastErr != nil {
			resolver.logger.WarnContext(
				ctx,
				"Request failed, will retry",
				slog.String("provider", providerName),
				slog.String("url", url),
				slog.Int("attempt", attempt+1),
				slog.Any("error", lastErr),
			)

			continue
		}

		if response.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%w: %s", ErrRemoteIPProviderHTTPStatus, response.Status)

			if response.StatusCode >= 400 && response.StatusCode < 500 {
				resolver.logger.ErrorContext(
					ctx,
					"Client error, will not retry",
					slog.String("provider", providerName),
					slog.String("url", url),
					slog.Int("status_code", response.StatusCode),
				)

				closeErr := response.Body.Close()
				if closeErr != nil {
					resolver.logger.WarnContext(
						ctx,
						"Error closing response body",
						slog.String("provider", providerName),
						slog.String("url", url),
						slog.Any("error", closeErr),
					)
				}

				return nil, lastErr
			}

			resolver.logger.WarnContext(
				ctx,
				"Non-OK status, retrying",
				slog.String("provider", providerName),
				slog.String("url", url),
				slog.Int("status_code", response.StatusCode),
			)

			closeErr := response.Body.Close()
			if closeErr != nil {
				resolver.logger.WarnContext(
					ctx,
					"Error closing response body",
					slog.String("provider", providerName),
					slog.String("url", url),
					slog.Any("error", closeErr),
				)
			}

			continue
		}

		// Success.
		return response, nil
	}

	resolver.logger.ErrorContext(
		ctx,
		"Failed to fetch provider IPs after retries",
		slog.String("provider", providerName),
		slog.String("url", url),
		slog.Int("max_retries", maxRetries+1),
		slog.Any("error", lastErr),
	)

	return nil, fmt.Errorf(
		"error fetching %s IPs after %d retries: %w",
		providerName, maxRetries+1, lastErr,
	)
}

func (resolver *IPResolver) readResponseBody(
	ctx context.Context,
	resp *http.Response,
	providerName, url string,
) (string, error) {
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		resolver.logger.ErrorContext(
			ctx,
			"Error reading response body",
			slog.String("provider", providerName),
			slog.String("url", url),
			slog.Any("error", err),
		)

		return "", fmt.Errorf("error reading response body: %w", err)
	}

	return string(bytes), nil
}

func (resolver *IPResolver) parseCIDRs(
	ctx context.Context,
	body string,
	providerName string,
) ([]*net.IPNet, error) {
	ips := make([]*net.IPNet, 0)

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

			return nil, fmt.Errorf("error parsing CIDR %s: %w", cidr, err)
		}

		ips = append(ips, block)
	}

	return ips, nil
}
