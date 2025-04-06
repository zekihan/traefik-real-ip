package traefik_real_ip

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"strings"
)

// Config the plugin configuration.
type Config struct {
	ThrustLocal      bool     `json:"thrustLocal,omitempty"`
	ThrustCloudFlare bool     `json:"thrustCloudFlare,omitempty"`
	TrustedIPs       []string `json:"trustedIPs,omitempty"`
	LogLevel         string   `json:"logLevel,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		ThrustLocal:      true,
		ThrustCloudFlare: true,
		TrustedIPs:       make([]string, 0),
		LogLevel:         "info",
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
	ipResolver := &IPResolver{
		next: next,
		conf: config,
		name: name,
	}

	trustedIPNets := make([]*net.IPNet, 0)
	if config.ThrustLocal {
		localIPs := ipResolver.getLocalIPs()
		if len(localIPs) == 0 {
			return nil, fmt.Errorf("error getting local IPs")
		}
		trustedIPNets = append(trustedIPNets, localIPs...)
	}
	if config.ThrustCloudFlare {
		cloudFlareIPs := ipResolver.getCloudFlareIPs()
		if len(cloudFlareIPs) == 0 {
			return nil, fmt.Errorf("error getting Cloudflare IPs")
		}
		trustedIPNets = append(trustedIPNets, cloudFlareIPs...)
	}
	for _, ipRange := range config.TrustedIPs {
		_, ipNet, err := net.ParseCIDR(ipRange)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted IP range: %s", ipRange)
		}
		trustedIPNets = append(trustedIPNets, ipNet)
	}

	ipResolver.trustedIPNets = trustedIPNets

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
	ipResolver.logger = pluginLogger

	return ipResolver, nil
}

func (a *IPResolver) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	defer a.handlePanic(rw, req)

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
		req.Header.Set(XIsTrusted, "yes")
	} else {
		req.Header.Set(XIsTrusted, "no")
	}

	req.Header.Set(XRealIP, ip.String())
	a.logger.Debug("Setting header", slog.String("header", XRealIP), slog.String("value", ip.String()))

	if isTrusted {
		if req.Header.Get(XForwardedFor) == "" {
			req.Header.Set(XForwardedFor, ip.String())
			a.logger.Debug("Setting header", slog.String("header", XForwardedFor), slog.String("value", ip.String()))
		} else {
			newVals := make([]string, 0)
			newVals = append(newVals, ip.String())
			vals := strings.Split(req.Header.Get(XForwardedFor), ",")
			for _, val := range vals {
				if strings.TrimSpace(val) == "" {
					continue
				}
				if strings.TrimSpace(val) == ip.String() {
					continue
				}
				newVals = append(newVals, strings.TrimSpace(val))
			}
			req.Header.Set(XForwardedFor, strings.Join(newVals, ", "))
			a.logger.Debug("Setting header", slog.String("header", XForwardedFor), slog.String("value", strings.Join(newVals, ", ")))
		}
	} else {
		req.Header.Set(XForwardedFor, srcIP.String())
		a.logger.Debug("Setting header", slog.String("header", XForwardedFor), slog.String("value", srcIP.String()))
	}

	a.next.ServeHTTP(rw, req)
}

func (a *IPResolver) handlePanic(rw http.ResponseWriter, req *http.Request) {
	r := recover()
	err := getPanicError(r)
	if err == nil {
		return
	}

	if errors.Is(err, http.ErrAbortHandler) {
		retryCount, ok := req.Context().Value(RetryCountKey).(int)
		if ok {
			if retryCount > 3 {
				a.logger.Info("Max retry count reached, aborting", slog.Int(string(RetryCountKey), retryCount), ErrorAttrWithoutStack(err))
				a.next.ServeHTTP(rw, req)
				return // suppress
			}
		} else {
			retryCount = 1
		}
		a.logger.Info("Retrying request", slog.Int(string(RetryCountKey), retryCount))
		req = req.WithContext(context.WithValue(req.Context(), RetryCountKey, retryCount+1))
		a.ServeHTTP(rw, req)
		return // suppress
	}

	a.logger.Error("Panic recovered", ErrorAttr(err))
	a.next.ServeHTTP(rw, req)
}

func getPanicError(r any) error {
	if r == nil {
		return nil
	}

	err, ok := r.(error)
	if ok {
		return err
	}

	refVal, ok := r.(reflect.Value)
	if ok && refVal.IsValid() && refVal.CanInterface() {
		refValInt := refVal.Interface()
		if err, ok := refValInt.(error); ok {
			return err
		}
	}

	return fmt.Errorf("panic: %v", r)
}
