package traefik_real_ip

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
)

// Config the plugin configuration.
type Config struct {
	TrustedIPs []string `json:"trustedIPs,omitempty"`
	LogLevel   string   `json:"logLevel,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		TrustedIPs: make([]string, 0),
		LogLevel:   "info",
	}
}

// IPResolver plugin.
type IPResolver struct {
	next          http.Handler
	conf          *Config
	name          string
	trustedIPNets []*net.IPNet
	logger        *PluginLogger
}

// New created a new IPResolver plugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	trustedIPNets := make([]*net.IPNet, 0)
	for _, ipRange := range config.TrustedIPs {
		_, ipNet, err := net.ParseCIDR(ipRange)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted IP range: %s", ipRange)
		}
		trustedIPNets = append(trustedIPNets, ipNet)
	}

	logLevel := &slog.LevelVar{}
	switch strings.ToLower(config.LogLevel) {
	case "debug":
		logLevel.Set(slog.LevelDebug)
	case "info":
		logLevel.Set(slog.LevelInfo)
	case "warn":
		logLevel.Set(slog.LevelWarn)
	case "error":
		logLevel.Set(slog.LevelError)
	case "":
		logLevel.Set(slog.LevelInfo)
	default:
		slog.Warn("Invalid log level, using info", slog.String("level", config.LogLevel))
		logLevel.Set(slog.LevelInfo)
	}

	pluginLogger := NewPluginLogger(name, logLevel)

	return &IPResolver{
		next:          next,
		conf:          config,
		name:          name,
		trustedIPNets: trustedIPNets,
		logger:        pluginLogger,
	}, nil
}

func (a *IPResolver) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			a.logger.Error("Panic recovered", err, slog.String("stack", string(debug.Stack())))
			a.next.ServeHTTP(rw, req)
		}
	}()

	srcIP, err := a.getSrcIP(req)
	if err != nil {
		a.logger.Error("Error getting source IP", err)
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	a.logger.Debug("Source IP", slog.String("ip", srcIP.String()))

	ip, err := a.getRealIP(srcIP, req)
	if err != nil {
		a.logger.Error("Error getting real IP", err)
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	isTrusted := a.isTrustedIP(srcIP)
	a.logger.Debug("IP is trusted", slog.String("ip", srcIP.String()), slog.Bool("is_trusted", isTrusted))

	if isTrusted {
		req.Header.Set(X_IS_TRUSTED, "yes")
	} else {
		req.Header.Set(X_IS_TRUSTED, "no")
	}

	req.Header.Set(X_REAL_IP, ip.String())
	a.logger.Debug("Setting header", slog.String("header", X_REAL_IP), slog.String("value", ip.String()))

	if isTrusted {
		if req.Header.Get(X_FORWARDED_FOR) == "" {
			req.Header.Set(X_FORWARDED_FOR, ip.String())
			a.logger.Debug("Setting header", slog.String("header", X_FORWARDED_FOR), slog.String("value", ip.String()))
		} else {
			newVals := make([]string, 0)
			newVals = append(newVals, ip.String())
			vals := strings.Split(req.Header.Get(X_FORWARDED_FOR), ",")
			for _, val := range vals {
				if strings.TrimSpace(val) == "" {
					continue
				}
				if strings.TrimSpace(val) == ip.String() {
					continue
				}
				newVals = append(newVals, strings.TrimSpace(val))
			}
			req.Header.Set(X_FORWARDED_FOR, strings.Join(newVals, ", "))
			a.logger.Debug("Setting header", slog.String("header", X_FORWARDED_FOR), slog.String("value", strings.Join(newVals, ", ")))
		}
	} else {
		req.Header.Set(X_FORWARDED_FOR, srcIP.String())
		a.logger.Debug("Setting header", slog.String("header", X_FORWARDED_FOR), slog.String("value", srcIP.String()))
	}

	a.next.ServeHTTP(rw, req)
}

func (a *IPResolver) getRealIP(srcIP net.IP, req *http.Request) (net.IP, error) {
	cfConnectingIPHeader := req.Header.Values(CF_CONNECTING_IP)
	a.logger.Debug("Checking header", slog.String("header", CF_CONNECTING_IP), slog.Bool("exists", len(cfConnectingIPHeader) > 0))
	if len(cfConnectingIPHeader) > 0 {
		if a.isTrustedIP(srcIP) {
			cfIP, err := a.handleCFIP(req)
			if err != nil {
				return nil, err
			}
			return cfIP, nil
		} else {
			a.logger.Debug("Source IP is not trusted, ignoring header", slog.String("ip", srcIP.String()), slog.String("header", CF_CONNECTING_IP))
		}
	}

	xRealIPHeader := req.Header.Values(X_REAL_IP)
	a.logger.Debug("Checking header", slog.String("header", X_REAL_IP), slog.Bool("exists", len(xRealIPHeader) > 0))
	if len(xRealIPHeader) > 0 {
		if a.isTrustedIP(srcIP) {
			xRealIP, err := a.handleXRealIP(req)
			if err != nil {
				return nil, err
			}
			return xRealIP, nil
		} else {
			a.logger.Debug("Source IP is not trusted, ignoring header", slog.String("ip", srcIP.String()), slog.String("header", X_REAL_IP))
		}
	}

	xForwardedForHeader := req.Header.Values(X_FORWARDED_FOR)
	a.logger.Debug("Checking header", slog.String("header", X_FORWARDED_FOR), slog.Bool("exists", len(xForwardedForHeader) > 0))
	if len(xForwardedForHeader) > 0 {
		if a.isTrustedIP(srcIP) {
			xForwardedFor, err := a.handleXForwardedFor(req)
			if err != nil {
				return nil, err
			}
			return xForwardedFor, nil
		} else {
			a.logger.Debug("Source IP is not trusted, ignoring header", slog.String("ip", srcIP.String()), slog.String("header", X_FORWARDED_FOR))
		}
	}

	a.logger.Debug("No trusted headers found, returning source IP")
	return srcIP, nil
}

func (a *IPResolver) handleXForwardedFor(req *http.Request) (net.IP, error) {
	xForwardedForList := req.Header.Values(X_FORWARDED_FOR)
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
			if !a.isLocalIP(xForwardedForValue) {
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
	realIPs := req.Header.Values(X_REAL_IP)
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
	cfIPs := req.Header.Values(CF_CONNECTING_IP)
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
