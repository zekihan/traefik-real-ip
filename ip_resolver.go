package traefik_real_ip

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

var (
	ErrXForwardedForInvalid      = errors.New("header X-Forwarded-For invalid")
	ErrNoValidIPInXForwardedFor  = errors.New("no valid IP found in X-Forwarded-For")
	ErrNoPublicIPInXForwardedFor = errors.New("no public IP found in X-Forwarded-For")
	ErrInvalidIPFormat           = errors.New("invalid IP format")
	ErrXRealIPInvalid            = errors.New("header X-Real-IP invalid")
	ErrCfConnectingIPInvalid     = errors.New("header Cf-Connecting-Ip not found or invalid")
	ErrEoConnectingIPInvalid     = errors.New("header Eo-Connecting-Ip not found or invalid")
)

const (
	maxForwardedForHops  = 32
	maxForwardedForBytes = 4096
	maxSingleIPBytes     = 45
)

func (resolver *IPResolver) getRealIP(
	ctx context.Context,
	srcIP net.IP,
	req *http.Request,
) (net.IP, error) {
	if !resolver.isTrustedIP(ctx, srcIP) {
		resolver.logger.DebugContext(
			ctx,
			"Source IP is not trusted, skipping header checks",
			slog.String("ip", srcIP.String()),
		)

		return srcIP, nil
	}

	cfConnectingIPHeader := req.Header.Values(CfConnectingIP)
	resolver.logger.DebugContext(
		ctx,
		"Checking header",
		slog.String("header", CfConnectingIP),
		slog.Bool("exists", len(cfConnectingIPHeader) > 0),
	)

	if len(cfConnectingIPHeader) > 0 {
		cfIP, err := resolver.handleCFIP(ctx, req)
		if err != nil {
			return nil, err
		}

		return cfIP, nil
	}

	eoConnectingIPHeader := req.Header.Values(EoConnectingIP)
	resolver.logger.DebugContext(
		ctx,
		"Checking header",
		slog.String("header", EoConnectingIP),
		slog.Bool("exists", len(eoConnectingIPHeader) > 0),
	)

	if len(eoConnectingIPHeader) > 0 {
		eoIP, err := resolver.handleEOIP(ctx, req)
		if err != nil {
			return nil, err
		}

		return eoIP, nil
	}

	xRealIPHeader := req.Header.Values(XRealIP)
	resolver.logger.DebugContext(
		ctx,
		"Checking header",
		slog.String("header", XRealIP),
		slog.Bool("exists", len(xRealIPHeader) > 0),
	)

	if len(xRealIPHeader) > 0 {
		xRealIP, err := resolver.handleXRealIP(ctx, req)
		if err != nil {
			return nil, err
		}

		if !resolver.isPrivateIP(xRealIP) {
			return xRealIP, nil
		}

		resolver.logger.DebugContext(
			ctx,
			"X-Real-IP is resolved to a private IP, skipping",
			slog.String("ip", xRealIP.String()),
		)
	}

	xForwardedForHeader := req.Header.Values(XForwardedFor)
	resolver.logger.DebugContext(
		ctx,
		"Checking header",
		slog.String("header", XForwardedFor),
		slog.Bool("exists", len(xForwardedForHeader) > 0),
	)

	if len(xForwardedForHeader) > 0 {
		xForwardedFor, err := resolver.handleXForwardedFor(ctx, srcIP, req)
		if err != nil {
			return nil, err
		}

		return xForwardedFor, nil
	}

	resolver.logger.DebugContext(ctx, "No trusted headers found, returning source IP")

	return srcIP, nil
}

// handleXForwardedFor follows only the contiguous trusted suffix, anchored at the socket peer.
func (resolver *IPResolver) handleXForwardedFor(
	ctx context.Context,
	srcIP net.IP,
	req *http.Request,
) (net.IP, error) {
	if !resolver.isTrustedIP(ctx, srcIP) {
		return srcIP, nil
	}

	values := req.Header.Values(XForwardedFor)
	if len(values) != 1 || len(values[0]) > maxForwardedForBytes {
		return nil, ErrXForwardedForInvalid
	}

	if strings.Count(values[0], ",") >= maxForwardedForHops {
		return nil, ErrXForwardedForInvalid
	}

	hops := strings.Split(values[0], ",")

	ips := make([]net.IP, len(hops))
	for i, hop := range hops {
		ip := net.ParseIP(strings.TrimSpace(hop))
		if ip == nil {
			return nil, ErrXForwardedForInvalid
		}

		ips[i] = ip
	}

	// Validate the entire input before choosing an address, including any untrusted prefix.
	//nolint:modernize // yaegi does not support generics or range-over-function iterators
	for i := len(ips) - 1; i >= 0; i-- {
		if !resolver.isTrustedIP(ctx, ips[i]) {
			return ips[i], nil
		}
	}

	// Every hop is trusted to assert identity. Preserve the leftmost assertion for local chains.
	// This is a trust-policy choice, not independent proof of the originating host.
	return ips[0], nil
}

func (resolver *IPResolver) handleXRealIP(ctx context.Context, req *http.Request) (net.IP, error) {
	realIPs := req.Header.Values(XRealIP)
	if len(realIPs) != 1 {
		return nil, ErrXRealIPInvalid
	}

	resolver.logger.DebugContext(ctx, "Parsing X-Real-IP", slog.Int("valueBytes", len(realIPs[0])))

	if len(realIPs[0]) > maxSingleIPBytes {
		return nil, fmt.Errorf("%w in X-Real-IP", ErrInvalidIPFormat)
	}

	tempIP := net.ParseIP(realIPs[0])
	if tempIP == nil {
		return nil, fmt.Errorf("%w in X-Real-IP", ErrInvalidIPFormat)
	}

	resolver.logger.DebugContext(ctx, "Found valid X-Real-IP", slog.String("ip", tempIP.String()))

	return tempIP, nil
}

func (resolver *IPResolver) handleCFIP(ctx context.Context, req *http.Request) (net.IP, error) {
	cfIPs := req.Header.Values(CfConnectingIP)
	if len(cfIPs) != 1 {
		return nil, ErrCfConnectingIPInvalid
	}

	resolver.logger.DebugContext(
		ctx,
		"Parsing Cf-Connecting-Ip",
		slog.Int("valueBytes", len(cfIPs[0])),
	)

	if len(cfIPs[0]) > maxSingleIPBytes {
		return nil, fmt.Errorf("%w in Cf-Connecting-Ip", ErrInvalidIPFormat)
	}

	tempIP := net.ParseIP(cfIPs[0])
	if tempIP == nil {
		return nil, fmt.Errorf("%w in Cf-Connecting-Ip", ErrInvalidIPFormat)
	}

	resolver.logger.DebugContext(
		ctx,
		"Found valid Cf-Connecting-Ip",
		slog.String("ip", tempIP.String()),
	)

	return tempIP, nil
}

func (resolver *IPResolver) handleEOIP(ctx context.Context, req *http.Request) (net.IP, error) {
	eoIPs := req.Header.Values(EoConnectingIP)
	if len(eoIPs) != 1 {
		return nil, ErrEoConnectingIPInvalid
	}

	resolver.logger.DebugContext(
		ctx,
		"Parsing Eo-Connecting-Ip",
		slog.Int("valueBytes", len(eoIPs[0])),
	)

	if len(eoIPs[0]) > maxSingleIPBytes {
		return nil, fmt.Errorf("%w in Eo-Connecting-Ip", ErrInvalidIPFormat)
	}

	tempIP := net.ParseIP(eoIPs[0])
	if tempIP == nil {
		return nil, fmt.Errorf("%w in Eo-Connecting-Ip", ErrInvalidIPFormat)
	}

	resolver.logger.DebugContext(
		ctx,
		"Found valid Eo-Connecting-Ip",
		slog.String("ip", tempIP.String()),
	)

	return tempIP, nil
}

func (resolver *IPResolver) getSrcIP(ctx context.Context, req *http.Request) (net.IP, error) {
	temp, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to split host and port from RemoteAddr: %w", err)
	}

	host := temp
	if zone := strings.LastIndex(host, "%"); zone >= 0 {
		// Zones are socket metadata and apply only to IPv6 peers, never headers.
		if zone == len(host)-1 || !strings.Contains(host[:zone], ":") {
			return nil, fmt.Errorf("%w: %s", ErrInvalidIPFormat, temp)
		}

		host = host[:zone]
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidIPFormat, temp)
	}

	resolver.logger.DebugContext(ctx, "Parsed source IP", slog.String("ip", ip.String()))

	return ip, nil
}
