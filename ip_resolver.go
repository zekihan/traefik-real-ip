//nolint:staticcheck // no reason
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
	ErrXForwardedForInvalid     = errors.New("header X-Forwarded-For invalid")
	ErrNoValidIPInXForwardedFor = errors.New("no valid IP found in X-Forwarded-For")
	ErrInvalidIPFormat          = errors.New("invalid IP format")
	ErrXRealIPInvalid           = errors.New("header X-Real-IP invalid")
	ErrCfConnectingIPInvalid    = errors.New("header Cf-Connecting-Ip not found or invalid")
)

func (resolver *IPResolver) getRealIP(
	ctx context.Context,
	srcIP net.IP,
	req *http.Request,
) (net.IP, error) {
	cfConnectingIPHeader := req.Header.Values(CfConnectingIP)
	resolver.logger.DebugContext(
		ctx,
		"Checking header",
		slog.String("header", CfConnectingIP),
		slog.Bool("exists", len(cfConnectingIPHeader) > 0),
	)

	if len(cfConnectingIPHeader) > 0 {
		if resolver.isTrustedIP(ctx, srcIP) {
			cfIP, err := resolver.handleCFIP(ctx, req)
			if err != nil {
				return nil, err
			}

			return cfIP, nil
		}

		resolver.logger.DebugContext(
			ctx,
			"Source IP is not trusted, ignoring header",
			slog.String("ip", srcIP.String()),
			slog.String("header", CfConnectingIP),
		)
	}

	xRealIPHeader := req.Header.Values(XRealIP)
	resolver.logger.DebugContext(
		ctx,
		"Checking header",
		slog.String("header", XRealIP),
		slog.Bool("exists", len(xRealIPHeader) > 0),
	)

	if len(xRealIPHeader) > 0 {
		if resolver.isTrustedIP(ctx, srcIP) {
			xRealIP, err := resolver.handleXRealIP(ctx, req)
			if err != nil {
				return nil, err
			}

			return xRealIP, nil
		}

		resolver.logger.DebugContext(
			ctx,
			"Source IP is not trusted, ignoring header",
			slog.String("ip", srcIP.String()),
			slog.String("header", XRealIP),
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
		if resolver.isTrustedIP(ctx, srcIP) {
			xForwardedFor, err := resolver.handleXForwardedFor(ctx, req)
			if err != nil {
				return nil, err
			}

			return xForwardedFor, nil
		}

		resolver.logger.DebugContext(
			ctx,
			"Source IP is not trusted, ignoring header",
			slog.String("ip", srcIP.String()),
			slog.String("header", XForwardedFor),
		)
	}

	resolver.logger.DebugContext(ctx, "No trusted headers found, returning source IP")

	return srcIP, nil
}

func (resolver *IPResolver) handleXForwardedFor(
	ctx context.Context,
	req *http.Request,
) (net.IP, error) {
	xForwardedForList := req.Header.Values(XForwardedFor)
	if len(xForwardedForList) != 1 {
		return nil, ErrXForwardedForInvalid
	}

	resolver.logger.DebugContext(
		ctx,
		"Parsing X-Forwarded-For",
		slog.Any("value", xForwardedForList),
	)

	xForwardedForValuesStr := strings.Split(xForwardedForList[0], ",")
	xForwardedForValues := make([]net.IP, 0)

	if len(xForwardedForValuesStr) > 0 {
		for _, xForwardedForValue := range xForwardedForValuesStr {
			tempIP := net.ParseIP(strings.TrimSpace(xForwardedForValue))
			if tempIP != nil {
				xForwardedForValues = append(xForwardedForValues, tempIP)
			} else {
				resolver.logger.DebugContext(ctx, "Invalid IP format in X-Forwarded-For", slog.String("value", xForwardedForValue))
			}
		}
	}

	for _, xForwardedForValue := range xForwardedForValues {
		if !resolver.isPrivateIP(xForwardedForValue) {
			resolver.logger.DebugContext(
				ctx,
				"Found valid X-Forwarded-For IP",
				slog.String("ip", xForwardedForValue.String()),
			)

			return xForwardedForValue, nil
		}

		resolver.logger.DebugContext(
			ctx,
			"X-Forwarded-For IP is resolver local IP, skipping",
			slog.String("ip", xForwardedForValue.String()),
		)
	}

	return nil, ErrNoValidIPInXForwardedFor
}

func (resolver *IPResolver) handleXRealIP(ctx context.Context, req *http.Request) (net.IP, error) {
	realIPs := req.Header.Values(XRealIP)
	if len(realIPs) != 1 {
		return nil, ErrXRealIPInvalid
	}

	resolver.logger.DebugContext(ctx, "Parsing X-Real-IP", slog.Any("value", realIPs))

	tempIP := net.ParseIP(realIPs[0])
	if tempIP == nil {
		return nil, fmt.Errorf("%w in X-Real-IP: %s", ErrInvalidIPFormat, realIPs[0])
	}

	resolver.logger.DebugContext(ctx, "Found valid X-Real-IP", slog.String("ip", tempIP.String()))

	return tempIP, nil
}

func (resolver *IPResolver) handleCFIP(ctx context.Context, req *http.Request) (net.IP, error) {
	cfIPs := req.Header.Values(CfConnectingIP)
	if len(cfIPs) != 1 {
		return nil, ErrCfConnectingIPInvalid
	}

	resolver.logger.DebugContext(ctx, "Parsing Cf-Connecting-Ip", slog.Any("value", cfIPs))

	tempIP := net.ParseIP(cfIPs[0])
	if tempIP == nil {
		return nil, fmt.Errorf("%w in Cf-Connecting-Ip: %s", ErrInvalidIPFormat, cfIPs[0])
	}

	resolver.logger.DebugContext(
		ctx,
		"Found valid Cf-Connecting-Ip",
		slog.String("ip", tempIP.String()),
	)

	return tempIP, nil
}

func (resolver *IPResolver) getSrcIP(ctx context.Context, req *http.Request) (net.IP, error) {
	temp, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to split host and port from RemoteAddr: %w", err)
	}

	ip := net.ParseIP(temp)
	if ip == nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidIPFormat, temp)
	}

	resolver.logger.DebugContext(ctx, "Parsed source IP", slog.String("ip", ip.String()))

	return ip, nil
}
