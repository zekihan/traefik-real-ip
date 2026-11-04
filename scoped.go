package traefik_real_ip

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	ErrScopedTrustedIPs = errors.New(
		"trustedIPs is not used in scoped mode; use forwardedTrustedIPs",
	)
	ErrEdgeAuthHeaderName = errors.New(
		"cloudflareAuthHeader and cloudflareAuthSecretFile must be set together",
	)
	ErrEdgeAuthFailed  = errors.New("edge authentication failed")
	ErrEdgeSecretEmpty = errors.New("edge secret file holds no usable secret")
)

const (
	// Secrets shorter than this are rejected as misconfiguration.
	minEdgeSecretBytes = 16
	// At most the current and the previous secret, so rotation has no gap.
	maxEdgeSecrets            = 2
	maxEdgeSecretFileBytes    = 4096
	edgeSecretRecheckInterval = 10 * time.Second
)

// identityHeaders are removed from every request in scoped mode. Only X-Real-IP and
// X-Forwarded-For are written back, both set to the single resolved client address.
var identityHeaders = []string{
	CfConnectingIP,
	"Cf-Connecting-Ipv6",
	"Cf-Pseudo-Ipv4",
	EoConnectingIP,
	"True-Client-Ip",
	"X-Client-Ip",
	"X-Cluster-Client-Ip",
	"X-Original-Forwarded-For",
	"Fastly-Client-Ip",
	"Forwarded",
	XIsTrusted,
}

type scopedTrust struct {
	edgeAuth   *edgeAuth
	forwarded  []*net.IPNet
	cloudflare []*net.IPNet
	edgeOne    []*net.IPNet
}

// edgeAuth verifies a shared secret that the CDN edge adds to every request.
// The secret file is re-read when it changes, so a rotated Kubernetes Secret
// takes effect without rebuilding the middleware.
type edgeAuth struct {
	modTime time.Time
	checked time.Time
	loadErr error
	header  string
	path    string
	secrets [][]byte
	size    int64
	mu      sync.Mutex
}

func newScopedTrust(config *Config) (*scopedTrust, error) {
	if len(config.TrustedIPs) > 0 {
		return nil, ErrScopedTrustedIPs
	}

	forwarded, err := parseCIDRs(config.ForwardedTrustedIPs)
	if err != nil {
		return nil, err
	}

	cloudflare, err := parseCIDRs(config.CloudflareTrustedIPs)
	if err != nil {
		return nil, err
	}

	trust := &scopedTrust{forwarded: forwarded, cloudflare: cloudflare, edgeOne: nil, edgeAuth: nil}

	if (config.CloudflareAuthHeader == "") != (config.CloudflareAuthSecretFile == "") {
		return nil, ErrEdgeAuthHeaderName
	}

	if config.CloudflareAuthHeader != "" {
		trust.edgeAuth = &edgeAuth{
			header: http.CanonicalHeaderKey(config.CloudflareAuthHeader),
			path:   config.CloudflareAuthSecretFile,
			mu:     sync.Mutex{}, secrets: nil, modTime: time.Time{}, size: 0,
			checked: time.Time{}, loadErr: nil,
		}
	}

	return trust, nil
}

func parseCIDRs(ranges []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(ranges))

	for _, ipRange := range ranges {
		_, ipNet, err := net.ParseCIDR(ipRange)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidTrustedIPRange, ipRange)
		}

		nets = append(nets, ipNet)
	}

	return nets, nil
}

func netsContain(nets []*net.IPNet, ip net.IP) bool {
	for _, ipNet := range nets {
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

func (trust *scopedTrust) trusts(ip net.IP) bool {
	return netsContain(trust.forwarded, ip) || netsContain(trust.cloudflare, ip) ||
		netsContain(trust.edgeOne, ip)
}

// load returns the configured secrets, re-reading the file at most once per interval
// and only when its modification time or size changed.
func (auth *edgeAuth) load(now time.Time) ([][]byte, error) {
	auth.mu.Lock()
	defer auth.mu.Unlock()

	if !auth.checked.IsZero() && now.Sub(auth.checked) < edgeSecretRecheckInterval {
		return auth.secrets, auth.loadErr
	}

	auth.checked = now

	info, err := os.Stat(auth.path)
	if err != nil {
		// Separate assignments: yaegi panics on tuple assignment of nil to fields.
		auth.secrets = nil
		auth.loadErr = fmt.Errorf("stat edge secret: %w", err)

		return nil, auth.loadErr
	}

	if auth.loadErr == nil && auth.secrets != nil &&
		info.ModTime().Equal(auth.modTime) && info.Size() == auth.size {
		return auth.secrets, nil
	}

	secrets, err := readEdgeSecrets(auth.path)
	if err != nil {
		auth.secrets = nil
		auth.loadErr = err

		return nil, err
	}

	auth.secrets = secrets
	auth.loadErr = nil
	auth.modTime = info.ModTime()
	auth.size = info.Size()

	return secrets, nil
}

func readEdgeSecrets(path string) ([][]byte, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read edge secret: %w", err)
	}

	if len(body) > maxEdgeSecretFileBytes {
		return nil, fmt.Errorf("%w: file too large", ErrEdgeSecretEmpty)
	}

	secrets := make([][]byte, 0, maxEdgeSecrets)

	//nolint:modernize // yaegi does not support strings.SplitSeq
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if len(line) < minEdgeSecretBytes || len(secrets) == maxEdgeSecrets {
			return nil, ErrEdgeSecretEmpty
		}

		secrets = append(secrets, []byte(line))
	}

	if len(secrets) == 0 {
		return nil, ErrEdgeSecretEmpty
	}

	return secrets, nil
}

func (auth *edgeAuth) verify(req *http.Request, now time.Time) error {
	values := req.Header.Values(auth.header)
	if len(values) != 1 {
		return ErrEdgeAuthFailed
	}

	secrets, err := auth.load(now)
	if err != nil {
		return err
	}

	matched := 0

	for _, secret := range secrets {
		matched |= subtle.ConstantTimeCompare([]byte(values[0]), secret)
	}

	if matched != 1 {
		return ErrEdgeAuthFailed
	}

	return nil
}

// resolveScoped applies per-header trust: a CDN header counts only from that CDN's
// peers (and only with a valid edge secret when one is configured); X-Real-IP and
// X-Forwarded-For count only from forwardedTrustedIPs. It returns the HTTP status to
// reply with when the request must be refused.
func (resolver *IPResolver) resolveScoped(
	ctx context.Context,
	srcIP net.IP,
	req *http.Request,
) (net.IP, int, error) {
	trust := resolver.scoped

	if netsContain(trust.cloudflare, srcIP) {
		cfIP, status, err := resolver.resolveCloudflare(ctx, srcIP, req)
		if err != nil || cfIP != nil {
			return cfIP, status, err
		}
	}

	if netsContain(trust.edgeOne, srcIP) && len(req.Header.Values(EoConnectingIP)) > 0 {
		eoIP, err := resolver.handleEOIP(ctx, req)
		if err != nil {
			return nil, http.StatusBadRequest, err
		}

		return eoIP, http.StatusOK, nil
	}

	if !netsContain(trust.forwarded, srcIP) {
		return srcIP, http.StatusOK, nil
	}

	return resolver.resolveForwarded(ctx, srcIP, req)
}

// resolveCloudflare handles a peer allowed to send Cf-Connecting-Ip. A nil address
// with no error means the request carried no Cloudflare assertion.
func (resolver *IPResolver) resolveCloudflare(
	ctx context.Context,
	srcIP net.IP,
	req *http.Request,
) (net.IP, int, error) {
	hasHeader := len(req.Header.Values(CfConnectingIP)) > 0

	if auth := resolver.scoped.edgeAuth; auth != nil {
		err := auth.verify(req, time.Now())
		if err == nil && !hasHeader {
			err = ErrCfConnectingIPInvalid
		}

		if err != nil {
			resolver.logger.WarnContext(
				ctx,
				"Refusing unauthenticated edge request",
				slog.String("ip", srcIP.String()),
				ErrorAttrWithoutStack(err),
			)

			return nil, http.StatusForbidden, ErrEdgeAuthFailed
		}
	}

	if !hasHeader {
		return nil, http.StatusOK, nil
	}

	cfIP, err := resolver.handleCFIP(ctx, req)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}

	return cfIP, http.StatusOK, nil
}

func (resolver *IPResolver) resolveForwarded(
	ctx context.Context,
	srcIP net.IP,
	req *http.Request,
) (net.IP, int, error) {
	if len(req.Header.Values(XRealIP)) > 0 {
		xRealIP, err := resolver.handleXRealIP(ctx, req)
		if err != nil {
			return nil, http.StatusBadRequest, err
		}

		if !resolver.isPrivateIP(xRealIP) {
			return xRealIP, http.StatusOK, nil
		}
	}

	if len(req.Header.Values(XForwardedFor)) > 0 {
		forwarded, err := resolver.handleXForwardedFor(ctx, srcIP, req)
		if err != nil {
			return nil, http.StatusBadRequest, err
		}

		return forwarded, http.StatusOK, nil
	}

	return srcIP, http.StatusOK, nil
}

// setScopedHeaders removes every alternative identity assertion and the edge secret,
// then writes the resolved address as the only X-Real-IP and X-Forwarded-For value.
func (resolver *IPResolver) setScopedHeaders(req *http.Request, ip net.IP) {
	for _, header := range identityHeaders {
		req.Header.Del(header)
	}

	if resolver.scoped.edgeAuth != nil {
		req.Header.Del(resolver.scoped.edgeAuth.header)
	}

	req.Header.Set(XRealIP, ip.String())
	req.Header.Set(XForwardedFor, ip.String())
}

func (resolver *IPResolver) serveScoped(rw http.ResponseWriter, req *http.Request, ip *net.IP) {
	if *ip == nil {
		resolved, ok := resolver.identifyScoped(rw, req)
		if !ok {
			return
		}

		*ip = resolved
	}

	resolver.setScopedHeaders(req, *ip)
	resolver.next.ServeHTTP(rw, req)
}

// identifyScoped resolves the client address, or writes the refusal and returns false.
func (resolver *IPResolver) identifyScoped(
	rw http.ResponseWriter,
	req *http.Request,
) (net.IP, bool) {
	ctx := req.Context()

	srcIP, err := resolver.getSrcIP(ctx, req)
	if err != nil {
		http.Error(rw, "invalid source IP", http.StatusBadRequest)

		return nil, false
	}

	if resolver.conf.DenyUntrusted && !resolver.scoped.trusts(srcIP) {
		resolver.logger.WarnContext(
			ctx,
			"Denying request from untrusted IP",
			slog.String("ip", srcIP.String()),
		)
		http.Error(rw, ErrUntrustedIP.Error(), http.StatusForbidden)

		return nil, false
	}

	resolved, status, err := resolver.resolveScoped(ctx, srcIP, req)
	if err != nil {
		resolver.logger.DebugContext(ctx, "Refusing request", ErrorAttrWithoutStack(err))

		message := "invalid client IP headers"
		if status == http.StatusForbidden {
			message = "forbidden"
		}

		http.Error(rw, message, status)

		return nil, false
	}

	return resolved, true
}

func newScopedResolver(
	ctx context.Context,
	resolver *IPResolver,
	config *Config,
) (http.Handler, error) {
	trust, err := newScopedTrust(config)
	if err != nil {
		return nil, err
	}

	if config.ThrustCloudFlare {
		ips, err := resolver.getCloudFlareIPs(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrGettingCloudflareIPs, err)
		}

		trust.cloudflare = append(trust.cloudflare, ips...)
	}

	if config.ThrustEdgeOne {
		ips, err := resolver.getEdgeOneIPs(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrGettingEdgeOneIPs, err)
		}

		trust.edgeOne = ips
	}

	if trust.edgeAuth != nil {
		// A missing secret must not take the middleware (and with abortOnPluginFailure,
		// every router) down; requests that need it are refused until it appears.
		_, err := trust.edgeAuth.load(time.Now())
		if err != nil {
			resolver.logger.ErrorContext(ctx, "Edge secret unavailable", ErrorAttrWithoutStack(err))
		}
	}

	// X-Forwarded-For walking uses the generic trusted set, which in scoped mode is
	// exactly forwardedTrustedIPs.
	resolver.trustedIPNets = trust.forwarded
	resolver.scoped = trust

	return resolver, nil
}
