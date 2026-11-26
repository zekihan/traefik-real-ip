package traefik_real_ip

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
)

// Static errors.
var (
	ErrGettingCloudflareIPs     = errors.New("error getting Cloudflare IPs")
	ErrGettingEdgeOneIPs        = errors.New("error getting EdgeOne IPs")
	ErrInvalidTrustedIPRange    = errors.New("invalid trusted IP range")
	ErrInvalidXForwardedForMode = errors.New("invalid X-Forwarded-For mode")
	ErrInvalidPanicPolicy       = errors.New("invalid panic policy")
	ErrUnknownConfigKey         = errors.New("unknown configuration key")
	ErrScopedOnlyOption         = errors.New("configuration option requires scopedTrust: true")
	ErrPanic                    = errors.New("panic")
	ErrUntrustedIP              = errors.New("request from untrusted IP denied")
)

const (
	XForwardedForModeAppend  = "append"
	XForwardedForModeReplace = "replace"

	PanicPolicyLegacyRetry = "legacy-retry"
	PanicPolicyPropagate   = "propagate"
)

// Config the plugin configuration.
type Config struct {
	//nolint:revive // Traefik's decoder supports the remain option.
	Unknown                  map[string]any `json:"-"                                  mapstructure:",remain"`
	LegacyThrustEdgeOne      *bool          `json:"thrustEdgeOne,omitempty"            mapstructure:"thrustEdgeOne"`
	LegacyThrustCloudFlare   *bool          `json:"thrustCloudFlare,omitempty"         mapstructure:"thrustCloudFlare"`
	LegacyThrustLocal        *bool          `json:"thrustLocal,omitempty"              mapstructure:"thrustLocal"`
	CloudflareAuthSecretFile string         `json:"cloudflareAuthSecretFile,omitempty"`
	LogLevel                 string         `json:"logLevel,omitempty"`
	CloudflareAuthHeader     string         `json:"cloudflareAuthHeader,omitempty"`
	XForwardedForMode        string         `json:"xForwardedForMode,omitempty"`
	PanicPolicy              string         `json:"panicPolicy,omitempty"`
	ForwardedTrustedIPs      []string       `json:"forwardedTrustedIPs,omitempty"`
	TrustedIPs               []string       `json:"trustedIPs,omitempty"`
	CloudflareTrustedIPs     []string       `json:"cloudflareTrustedIPs,omitempty"`
	TrustLocal               bool           `json:"trustLocal,omitempty"               mapstructure:"trustLocal"`
	TrustCloudFlare          bool           `json:"trustCloudFlare,omitempty"          mapstructure:"trustCloudFlare"`
	TrustEdgeOne             bool           `json:"trustEdgeOne,omitempty"             mapstructure:"trustEdgeOne"`
	DenyUntrusted            bool           `json:"denyUntrusted,omitempty"`
	ScopedTrust              bool           `json:"scopedTrust,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		TrustLocal:             true,
		TrustCloudFlare:        true,
		TrustEdgeOne:           false,
		LegacyThrustLocal:      nil,
		LegacyThrustCloudFlare: nil,
		LegacyThrustEdgeOne:    nil,
		TrustedIPs:             make([]string, 0),
		LogLevel:               "info",
		PanicPolicy:            PanicPolicyLegacyRetry,
		DenyUntrusted:          false,
		XForwardedForMode:      XForwardedForModeAppend,

		ScopedTrust:              false,
		ForwardedTrustedIPs:      make([]string, 0),
		CloudflareTrustedIPs:     make([]string, 0),
		CloudflareAuthHeader:     "",
		CloudflareAuthSecretFile: "",
		Unknown:                  nil,
	}
}

func configTrustLocal(config *Config) bool {
	if config.LegacyThrustLocal != nil {
		return *config.LegacyThrustLocal
	}

	return config.TrustLocal
}

func configTrustCloudFlare(config *Config) bool {
	if config.LegacyThrustCloudFlare != nil {
		return *config.LegacyThrustCloudFlare
	}

	return config.TrustCloudFlare
}

func configTrustEdgeOne(config *Config) bool {
	if config.LegacyThrustEdgeOne != nil {
		return *config.LegacyThrustEdgeOne
	}

	return config.TrustEdgeOne
}

func hasDeprecatedTrustKeys(config *Config) bool {
	return config.LegacyThrustLocal != nil || config.LegacyThrustCloudFlare != nil ||
		config.LegacyThrustEdgeOne != nil
}

func validateConfig(config *Config) error {
	if len(config.Unknown) > 0 {
		keys := make([]string, 0, len(config.Unknown))
		for key := range config.Unknown {
			keys = append(keys, key)
		}

		sort.Strings(keys)

		return fmt.Errorf("%w: %s", ErrUnknownConfigKey, strings.Join(keys, ", "))
	}

	if !config.ScopedTrust {
		switch {
		case len(config.ForwardedTrustedIPs) > 0:
			return fmt.Errorf("%w: forwardedTrustedIPs", ErrScopedOnlyOption)
		case len(config.CloudflareTrustedIPs) > 0:
			return fmt.Errorf("%w: cloudflareTrustedIPs", ErrScopedOnlyOption)
		case config.CloudflareAuthHeader != "":
			return fmt.Errorf("%w: cloudflareAuthHeader", ErrScopedOnlyOption)
		case config.CloudflareAuthSecretFile != "":
			return fmt.Errorf("%w: cloudflareAuthSecretFile", ErrScopedOnlyOption)
		}
	}

	if !isValidPanicPolicy(config.PanicPolicy) {
		return fmt.Errorf("%w: %s", ErrInvalidPanicPolicy, config.PanicPolicy)
	}

	if config.XForwardedForMode != "" &&
		config.XForwardedForMode != XForwardedForModeAppend &&
		config.XForwardedForMode != XForwardedForModeReplace {
		return fmt.Errorf("%w: %s", ErrInvalidXForwardedForMode, config.XForwardedForMode)
	}

	return nil
}

func isValidPanicPolicy(policy string) bool {
	return policy == "" || policy == PanicPolicyLegacyRetry || policy == PanicPolicyPropagate
}

// IPResolver plugin.
type IPResolver struct {
	next          http.Handler
	conf          *Config
	logger        *PluginLogger
	scoped        *scopedTrust
	name          string
	trustedIPNets []*net.IPNet
}

// New returns middleware that resolves the client IP from trusted peers.
func New(
	ctx context.Context,
	next http.Handler,
	config *Config,
	name string,
) (http.Handler, error) {
	configErr := validateConfig(config)
	if configErr != nil {
		return nil, configErr
	}

	ipResolver := &IPResolver{
		next: next,
		conf: config,
		name: name, logger: nil, trustedIPNets: nil, scoped: nil,
	}

	pluginLogger := NewPluginLogger(ctx, name, config.LogLevel)

	ipResolver.logger = pluginLogger
	if hasDeprecatedTrustKeys(config) {
		pluginLogger.WarnContext(ctx, "thrust* configuration keys are deprecated; use trust* keys")
	}

	if config.ScopedTrust {
		return newScopedResolver(ctx, ipResolver, config)
	}

	trustedIPNets := make([]*net.IPNet, 0)

	for _, ipRange := range config.TrustedIPs {
		_, ipNet, err := net.ParseCIDR(ipRange)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidTrustedIPRange, ipRange)
		}

		trustedIPNets = append(trustedIPNets, ipNet)
	}

	results := sync.Map{}
	errWg, errCtx := errgroup.WithContext(ctx)

	if configTrustLocal(config) {
		errWg.Go(func() error {
			ips := ipResolver.getLocalIPs(errCtx)
			ipResolver.logTrustedIPFetchResult(errCtx, "local", len(ips))
			results.Store("local", ips)

			return nil
		})
	}

	if configTrustCloudFlare(config) {
		errWg.Go(func() error {
			ips, err := ipResolver.getCloudFlareIPs(errCtx)
			if err != nil {
				return fmt.Errorf("%w: %w", ErrGettingCloudflareIPs, err)
			}

			ipResolver.logTrustedIPFetchResult(errCtx, "Cloudflare", len(ips))
			results.Store("cloudflare", ips)

			return nil
		})
	}

	if configTrustEdgeOne(config) {
		errWg.Go(func() error {
			ips, err := ipResolver.getEdgeOneIPs(errCtx)
			if err != nil {
				return fmt.Errorf("%w: %w", ErrGettingEdgeOneIPs, err)
			}

			ipResolver.logTrustedIPFetchResult(errCtx, "EdgeOne", len(ips))
			results.Store("edgeone", ips)

			return nil
		})
	}

	err := errWg.Wait()
	if err != nil {
		return nil, fmt.Errorf("error fetching trusted IPs: %w", err)
	}

	results.Range(func(key, value any) bool {
		ips, ok := value.([]*net.IPNet)
		if !ok {
			ipResolver.logger.WarnContext(
				errCtx,
				"Invalid type for trusted IPs",
				slog.String("key", fmt.Sprintf("%v", key)),
			)

			return true
		}

		trustedIPNets = append(trustedIPNets, ips...)

		return true
	})

	ipResolver.trustedIPNets = trustedIPNets

	return ipResolver, nil
}

func (resolver *IPResolver) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	resolver.serveHTTP(rw, req, nil)
}

func (resolver *IPResolver) serveHTTP(rw http.ResponseWriter, req *http.Request, ip net.IP) {
	defer resolver.handlePanic(rw, req, &ip)

	if resolver.scoped != nil {
		resolver.serveScoped(rw, req, &ip)

		return
	}

	ctx := req.Context()

	srcIP, err := resolver.getSrcIP(ctx, req)
	if err != nil {
		resolver.logger.DebugContext(
			ctx,
			"Invalid source IP",
			ErrorAttrWithoutStack(ErrInvalidIPFormat),
		)
		http.Error(rw, "invalid source IP", http.StatusBadRequest)

		return
	}

	resolver.logger.DebugContext(ctx, "Source IP", slog.String("ip", srcIP.String()))

	if ip == nil {
		ip, err = resolver.getRealIP(ctx, srcIP, req)
		if err != nil {
			resolver.logger.DebugContext(ctx, "Invalid identity header", ErrorAttrWithoutStack(err))
			http.Error(rw, "invalid client IP headers", http.StatusBadRequest)

			return
		}
	}

	isTrusted := resolver.isTrustedIP(ctx, srcIP)
	resolver.logger.DebugContext(
		ctx,
		"IP is trusted",
		slog.String("ip", srcIP.String()),
		slog.Bool("isTrusted", isTrusted),
	)

	if !isTrusted && resolver.conf.DenyUntrusted {
		resolver.logger.WarnContext(
			ctx,
			"Denying request from untrusted IP",
			slog.String("ip", srcIP.String()),
		)
		http.Error(rw, ErrUntrustedIP.Error(), http.StatusForbidden)

		return
	}

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

func (resolver *IPResolver) logTrustedIPFetchResult(
	ctx context.Context,
	provider string,
	count int,
) {
	if count == 0 {
		resolver.logger.WarnContext(
			ctx,
			"No trusted IPs loaded from provider",
			slog.String("provider", provider),
		)

		return
	}

	resolver.logger.DebugContext(
		ctx,
		"Fetched trusted IPs",
		slog.String("provider", provider),
		slog.Int("count", count),
	)
}

func (resolver *IPResolver) handleTrustedIPNets(ctx context.Context, req *http.Request, ip net.IP) {
	if resolver.conf.XForwardedForMode == XForwardedForModeReplace {
		req.Header.Set(XForwardedFor, ip.String())
		resolver.logger.DebugContext(
			ctx,
			"Replacing header",
			slog.String("header", XForwardedFor),
			slog.String("value", ip.String()),
		)

		return
	}

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

	newVals := []string{ip.String()}

	//nolint:modernize // yaegi does not support strings.SplitSeq
	vals := strings.Split(req.Header.Get(XForwardedFor), ",")
	for _, val := range vals {
		hop := strings.TrimSpace(val)
		if hop == "" || net.ParseIP(hop).Equal(ip) {
			continue
		}

		newVals = append(newVals, hop)
	}

	req.Header.Set(XForwardedFor, strings.Join(newVals, ", "))
	resolver.logger.DebugContext(
		ctx,
		"Setting header",
		slog.String("header", XForwardedFor),
		slog.Int("valueBytes", len(req.Header.Get(XForwardedFor))),
	)
}

func (resolver *IPResolver) handlePanic(
	rw http.ResponseWriter,
	req *http.Request,
	ip *net.IP,
) {
	recovered := recover()
	if recovered != nil && resolver.conf.PanicPolicy == PanicPolicyPropagate {
		// Preserve the original panic for the enclosing HTTP server or recovery middleware.
		// In particular, never replay a request whose downstream effects are unknown.
		panic(recovered)
	}

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
		// Reuse the resolved identity: outgoing headers may have been reordered or
		// modified downstream and are no longer the original proxy assertion.
		resolver.serveHTTP(rw, req, *ip)

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
