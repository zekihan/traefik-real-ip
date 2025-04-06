package traefik_real_ip

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

func (a *IPResolver) getRealIP(srcIP net.IP, req *http.Request) (net.IP, error) {
	cfConnectingIPHeader := req.Header.Values(CfConnectingIP)
	a.logger.Debug("Checking header", slog.String("header", CfConnectingIP), slog.Bool("exists", len(cfConnectingIPHeader) > 0))
	if len(cfConnectingIPHeader) > 0 {
		if a.isTrustedIP(srcIP) {
			cfIP, err := a.handleCFIP(req)
			if err != nil {
				return nil, err
			}
			return cfIP, nil
		} else {
			a.logger.Debug("Source IP is not trusted, ignoring header", slog.String("ip", srcIP.String()), slog.String("header", CfConnectingIP))
		}
	}

	xRealIPHeader := req.Header.Values(XRealIP)
	a.logger.Debug("Checking header", slog.String("header", XRealIP), slog.Bool("exists", len(xRealIPHeader) > 0))
	if len(xRealIPHeader) > 0 {
		if a.isTrustedIP(srcIP) {
			xRealIP, err := a.handleXRealIP(req)
			if err != nil {
				return nil, err
			}
			return xRealIP, nil
		} else {
			a.logger.Debug("Source IP is not trusted, ignoring header", slog.String("ip", srcIP.String()), slog.String("header", XRealIP))
		}
	}

	xForwardedForHeader := req.Header.Values(XForwardedFor)
	a.logger.Debug("Checking header", slog.String("header", XForwardedFor), slog.Bool("exists", len(xForwardedForHeader) > 0))
	if len(xForwardedForHeader) > 0 {
		if a.isTrustedIP(srcIP) {
			xForwardedFor, err := a.handleXForwardedFor(req)
			if err != nil {
				return nil, err
			}
			return xForwardedFor, nil
		} else {
			a.logger.Debug("Source IP is not trusted, ignoring header", slog.String("ip", srcIP.String()), slog.String("header", XForwardedFor))
		}
	}

	a.logger.Debug("No trusted headers found, returning source IP")
	return srcIP, nil
}

func (a *IPResolver) handleXForwardedFor(req *http.Request) (net.IP, error) {
	xForwardedForList := req.Header.Values(XForwardedFor)
	if len(xForwardedForList) == 1 {
		xForwardedForValuesStr := strings.Split(xForwardedForList[0], ",")
		xForwardedForValues := make([]net.IP, 0)
		if len(xForwardedForValuesStr) > 0 {
			for _, xForwardedForValue := range xForwardedForValuesStr {
				tempIP := net.ParseIP(strings.TrimSpace(xForwardedForValue))
				if tempIP != nil {
					xForwardedForValues = append(xForwardedForValues, tempIP)
				} else {
					a.logger.Debug("Invalid IP format in X-Forwarded-For", slog.String("value", xForwardedForValue))
				}
			}
		}
		for _, xForwardedForValue := range xForwardedForValues {
			if !a.isPrivateIP(xForwardedForValue) {
				a.logger.Debug("Found valid X-Forwarded-For IP", slog.String("ip", xForwardedForValue.String()))
				return xForwardedForValue, nil
			}
			a.logger.Debug("X-Forwarded-For IP is a local IP, skipping", slog.String("ip", xForwardedForValue.String()))
		}
		return nil, fmt.Errorf("no valid IP found in X-Forwarded-For")
	} else {
		return nil, fmt.Errorf("header X-Forwarded-For invalid")
	}
}

func (a *IPResolver) handleXRealIP(req *http.Request) (net.IP, error) {
	realIPs := req.Header.Values(XRealIP)
	if len(realIPs) == 1 {
		tempIP := net.ParseIP(realIPs[0])
		if tempIP == nil {
			return nil, fmt.Errorf("invalid IP format in X-Real-IP: %s", realIPs[0])
		}
		a.logger.Debug("Found valid X-Real-IP", slog.String("ip", tempIP.String()))
		return tempIP, nil
	} else {
		return nil, fmt.Errorf("header X-Real-IP invalid")
	}
}

func (a *IPResolver) handleCFIP(req *http.Request) (net.IP, error) {
	cfIPs := req.Header.Values(CfConnectingIP)
	if len(cfIPs) == 1 {
		tempIP := net.ParseIP(cfIPs[0])
		if tempIP == nil {
			return nil, fmt.Errorf("invalid IP format in CF-Connecting-IP: %s", cfIPs[0])
		}
		a.logger.Debug("Found valid CF-Connecting-IP", slog.String("ip", tempIP.String()))
		return tempIP, nil
	} else {
		return nil, fmt.Errorf("header CF-Connecting-IP not found or invalid")
	}
}

func (a *IPResolver) getSrcIP(req *http.Request) (net.IP, error) {
	temp, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(temp)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP format: %s", temp)
	}
	a.logger.Debug("Parsed source IP", slog.String("ip", ip.String()))
	return ip, nil
}
