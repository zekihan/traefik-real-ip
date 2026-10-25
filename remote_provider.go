package traefik_real_ip

import (
	"bufio"
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
	ErrRemoteIPProviderData       = errors.New("invalid remote IP provider data")
)

const (
	defaultRemoteProviderTimeout = 2 * time.Second
	maxRetries                   = 5
	initialRetryDelay            = 2 * time.Second
	// Limits apply to decoded responses, including automatically decompressed HTTP bodies.
	maxRemoteProviderBytes     = 1 << 20
	maxRemoteProviderLineBytes = 4096
	maxRemoteProviderCIDRs     = 4096
)

// remoteIPCache publishes only complete, nonempty snapshots. Failed loads leave the
// cache uninitialized so a later New call can retry without restarting the process.
// Successful snapshots remain immutable and cached for the process lifetime.
type remoteIPCache struct {
	ips []*net.IPNet
	mu  sync.Mutex
}

// remoteIPProvider describes a remote service exposing CIDR blocks.
type remoteIPProvider struct {
	cache *remoteIPCache
	name  string
	urls  []string
}

func (resolver *IPResolver) getProviderIPs(
	ctx context.Context,
	provider remoteIPProvider,
) ([]*net.IPNet, error) {
	provider.cache.mu.Lock()
	defer provider.cache.mu.Unlock()

	if len(provider.cache.ips) > 0 {
		return provider.cache.ips, nil
	}

	results := make([]*net.IPNet, 0)
	seen := make(map[string]bool)

	for _, url := range provider.urls {
		ips, err := resolver.getProviderIPsFromURL(ctx, provider.name, url)
		if err != nil {
			return nil, fmt.Errorf("fetching %s ranges from %s: %w", provider.name, url, err)
		}

		for _, block := range ips {
			key := block.String()
			if !seen[key] {
				if len(results) == maxRemoteProviderCIDRs {
					return nil, fmt.Errorf("%w: too many provider CIDRs", ErrRemoteIPProviderData)
				}

				seen[key] = true

				results = append(results, block)
			}
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("%w: empty provider", ErrRemoteIPProviderData)
	}

	provider.cache.ips = results

	return provider.cache.ips, nil
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

	return resolver.readResponseCIDRs(ctx, resp, providerName, url)
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
	client := &http.Client{
		Timeout:       defaultRemoteProviderTimeout,
		Transport:     nil,
		CheckRedirect: nil,
		Jar:           nil,
	}

	var (
		lastErr  error
		response *http.Response
	)

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := initialRetryDelay
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
					slog.Int("statusCode", response.StatusCode),
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
				slog.Int("statusCode", response.StatusCode),
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
		slog.Int("totalAttempts", maxRetries+1),
		slog.Any("error", lastErr),
	)

	return nil, fmt.Errorf(
		"error fetching %s IPs after %d retries: %w",
		providerName, maxRetries+1, lastErr,
	)
}

func (resolver *IPResolver) readResponseCIDRs(
	ctx context.Context,
	resp *http.Response,
	providerName, url string,
) ([]*net.IPNet, error) {
	if resp.ContentLength > maxRemoteProviderBytes {
		return nil, fmt.Errorf(
			"%w: response from %s exceeds byte limit",
			ErrRemoteIPProviderData,
			url,
		)
	}

	// Read at most one byte past the limit to detect oversized chunked or decoded bodies.
	body := &io.LimitedReader{R: resp.Body, N: maxRemoteProviderBytes + 1}

	ips, err := resolver.parseCIDRs(ctx, body, providerName)
	if err != nil {
		return nil, err
	}

	if body.N == 0 {
		return nil, fmt.Errorf(
			"%w: response from %s exceeds byte limit",
			ErrRemoteIPProviderData,
			url,
		)
	}

	return ips, nil
}

func (resolver *IPResolver) parseCIDRs(
	ctx context.Context,
	body io.Reader,
	providerName string,
) ([]*net.IPNet, error) {
	ips := make([]*net.IPNet, 0)
	seen := make(map[string]bool)
	count := 0
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, maxRemoteProviderLineBytes), maxRemoteProviderLineBytes)

	for scanner.Scan() {
		cidr := strings.TrimSpace(scanner.Text())
		if cidr == "" || strings.HasPrefix(cidr, "#") {
			continue
		}

		// Count input entries before deduplication to bound duplicate-heavy responses too.
		count++
		if count > maxRemoteProviderCIDRs {
			return nil, fmt.Errorf("%w: too many CIDRs", ErrRemoteIPProviderData)
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

		// A default route cannot identify a CDN and would authorize every source address.
		ones, _ := block.Mask.Size()
		if ones == 0 {
			return nil, fmt.Errorf("%w: default route", ErrRemoteIPProviderData)
		}

		key := block.String()
		if !seen[key] {
			seen[key] = true

			ips = append(ips, block)
		}
	}

	err := scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("reading %s CIDRs: %w", providerName, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: empty response", ErrRemoteIPProviderData)
	}

	return ips, nil
}
