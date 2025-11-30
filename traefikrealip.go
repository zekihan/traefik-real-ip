//nolint:staticcheck // no reason
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

// Static errors.
var (
	ErrGettingLocalIPs       = errors.New("error getting local IPs")
	ErrGettingCloudflareIPs  = errors.New("error getting Cloudflare IPs")
	ErrGettingEdgeOneIPs     = errors.New("error getting EdgeOne IPs")
	ErrInvalidTrustedIPRange = errors.New("invalid trusted IP range")
	ErrPanic                 = errors.New("panic")
)

// Config the plugin configuration.
type Config struct {
	LogLevel         string   `json:"logLevel,omitempty"`
	TrustedIPs       []string `json:"trustedIPs,omitempty"`
	ThrustLocal      bool     `json:"thrustLocal,omitempty"`
	ThrustCloudFlare bool     `json:"thrustCloudFlare,omitempty"`
	ThrustEdgeOne    bool     `json:"thrustEdgeOne,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		ThrustLocal:      true,
		ThrustCloudFlare: true,
		ThrustEdgeOne:    false,
		TrustedIPs:       make([]string, 0),
		LogLevel:         "info",
	}
}

// IPResolver plugin.
type IPResolver struct {
	next          http.Handler
	conf          *Config
	logger        *PluginLogger
	name          string
	trustedIPNets []*net.IPNet
}

// New created a new IPResolver plugin.
func New(
	ctx context.Context,
	next http.Handler,
	config *Config,
	name string,
) (http.Handler, error) {
	ipResolver := &IPResolver{
		next: next,
		conf: config,
		name: name,
	}

	trustedIPNets := make([]*net.IPNet, 0)

	if config.ThrustLocal {
		localIPs := ipResolver.getLocalIPs(ctx)
		if len(localIPs) == 0 {
			return nil, ErrGettingLocalIPs
		}

		trustedIPNets = append(trustedIPNets, localIPs...)
	}

	if config.ThrustCloudFlare {
		cloudFlareIPs := ipResolver.getCloudFlareIPs(ctx)
		if len(cloudFlareIPs) == 0 {
			// Fallback to embedded defaults.
			cloudFlareIPs = parseDefaultCIDRs(cloudFlareDefaultCIDRs)
		}

		trustedIPNets = append(trustedIPNets, cloudFlareIPs...)
	}

	if config.ThrustEdgeOne {
		edgeOneIPs := ipResolver.getEdgeOneIPs(ctx)
		if len(edgeOneIPs) == 0 {
			// Fallback to embedded defaults if defined.
			edgeOneIPs = parseDefaultCIDRs(edgeOneDefaultCIDRs)
		}

		trustedIPNets = append(trustedIPNets, edgeOneIPs...)
	}

	for _, ipRange := range config.TrustedIPs {
		_, ipNet, err := net.ParseCIDR(ipRange)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidTrustedIPRange, ipRange)
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
		slog.WarnContext(
			ctx,
			"Invalid log level, using info",
			slog.String("level", config.LogLevel),
		)
		logLevel.Set(slog.LevelInfo)
	}

	pluginLogger := NewPluginLogger(name, logLevel)
	ipResolver.logger = pluginLogger

	return ipResolver, nil
}

func (resolver *IPResolver) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	defer resolver.handlePanic(rw, req)

	ctx := req.Context()

	srcIP, err := resolver.getSrcIP(ctx, req)
	if err != nil {
		resolver.logger.ErrorContext(ctx, "Error getting source IP", err)
		http.Error(rw, err.Error(), http.StatusBadRequest)

		return
	}

	resolver.logger.DebugContext(ctx, "Source IP", slog.String("ip", srcIP.String()))

	ip, err := resolver.getRealIP(ctx, srcIP, req)
	if err != nil {
		resolver.logger.ErrorContext(ctx, "Error getting real IP", err)
		http.Error(rw, err.Error(), http.StatusBadRequest)

		return
	}

	isTrusted := resolver.isTrustedIP(ctx, srcIP)
	resolver.logger.DebugContext(
		ctx,
		"IP is trusted",
		slog.String("ip", srcIP.String()),
		slog.Bool("is_trusted", isTrusted),
	)

	if isTrusted {
		req.Header.Set(XIsTrusted, "yes")
	} else {
		req.Header.Set(XIsTrusted, "no")
	}

	req.Header.Set(XRealIP, ip.String())
	resolver.logger.DebugContext(
		ctx,
		"Setting header",
		slog.String("header", XRealIP),
		slog.String("value", ip.String()),
	)

	if isTrusted {
		resolver.handleTrustedIPNets(ctx, req, ip)
	} else {
		req.Header.Set(XForwardedFor, srcIP.String())
		resolver.logger.DebugContext(
			ctx,
			"Setting header",
			slog.String("header", XForwardedFor),
			slog.String("value", srcIP.String()),
		)
	}

	resolver.next.ServeHTTP(rw, req)
}

func (resolver *IPResolver) handleTrustedIPNets(ctx context.Context, req *http.Request, ip net.IP) {
	if req.Header.Get(XForwardedFor) == "" {
		req.Header.Set(XForwardedFor, ip.String())
		resolver.logger.DebugContext(
			ctx,
			"Setting header",
			slog.String("header", XForwardedFor),
			slog.String("value", ip.String()),
		)

		return
	}

	newVals := make([]string, 0)
	newVals = append(newVals, ip.String())

	//nolint:modernize // yaegi does not support strings.SplitSeq
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
	resolver.logger.DebugContext(
		ctx,
		"Setting header",
		slog.String("header", XForwardedFor),
		slog.String("value", strings.Join(newVals, ", ")),
	)
}

func (resolver *IPResolver) handlePanic(rw http.ResponseWriter, req *http.Request) {
	recovered := recover()

	ctx := req.Context()

	err := getPanicError(recovered)
	if err == nil {
		return
	}

	if errors.Is(err, http.ErrAbortHandler) {
		retryCount, ok := req.Context().Value(RetryCountKey).(int)
		if ok {
			if retryCount > MaxRetryCount {
				resolver.logger.InfoContext(
					ctx,
					"Max retry count reached, aborting",
					slog.Int(string(RetryCountKey), retryCount),
					ErrorAttrWithoutStack(err),
				)
				resolver.next.ServeHTTP(rw, req)

				return // suppress
			}
		} else {
			retryCount = 1
		}

		resolver.logger.InfoContext(
			ctx,
			"Retrying request",
			slog.Int(string(RetryCountKey), retryCount),
		)
		req = req.WithContext(context.WithValue(ctx, RetryCountKey, retryCount+1))
		resolver.ServeHTTP(rw, req)

		return // suppress
	}

	resolver.logger.ErrorContext(ctx, "Panic recovered", ErrorAttr(err))
	resolver.next.ServeHTTP(rw, req)
}

func getPanicError(recovered any) error {
	if recovered == nil {
		return nil
	}

	err, ok := recovered.(error)
	if ok {
		return err
	}

	refVal, ok := recovered.(reflect.Value)
	if ok && refVal.IsValid() && refVal.CanInterface() {
		refValInt := refVal.Interface()
		if err, ok := refValInt.(error); ok {
			return err
		}
	}

	return fmt.Errorf("%w: %v", ErrPanic, recovered)
}
