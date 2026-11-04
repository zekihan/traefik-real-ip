package traefik_real_ip_test

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	traefikrealip "github.com/zekihan/traefik-real-ip"
)

const (
	edgeHeader   = "X-Edge-Auth"
	edgeSecret   = "current-secret-0123456789"
	edgeSecret2  = "previous-secret-0123456789"
	cfEdgeIPv4   = "173.245.48.10"
	cfEdgeIPv6   = "2400:cb00::10"
	podIPv4      = "10.42.3.67"
	podIPv6      = "fd12:3456:789a:4203::23b"
	clientIPv4   = "198.51.100.7"
	clientIPv6   = "2001:db8::7"
	spoofedIPv4  = "203.0.113.99"
	lanClientIP  = "192.168.2.71"
	podCIDRv4    = "10.42.0.0/16"
	podCIDRv6    = "fd12:3456:789a:4200::/56"
	forbidden    = http.StatusForbidden
	okStatus     = http.StatusOK
	badRequest   = http.StatusBadRequest
	untrustedHdr = "untrusted"
)

type scopedCase struct {
	headers  map[string][]string
	expected map[string]string
	desc     string
	remote   string
	absent   []string
	status   int
}

func writeSecret(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "edge-secret")

	err := os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	return path
}

func newScoped(t *testing.T, mutate func(*traefikrealip.Config)) http.Handler {
	t.Helper()

	cfg := traefikrealip.CreateConfig()
	cfg.ScopedTrust = true
	cfg.ThrustCloudFlare = false
	cfg.XForwardedForMode = traefikrealip.XForwardedForModeReplace

	if mutate != nil {
		mutate(cfg)
	}

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	handler, err := traefikrealip.New(t.Context(), next, cfg, "scoped")
	if err != nil {
		t.Fatal(err)
	}

	return handler
}

func runScoped(t *testing.T, handler http.Handler, test *scopedCase) {
	t.Helper()

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"http://localhost",
		http.NoBody,
	)
	req.RemoteAddr = netJoin(test.remote)

	for key, values := range test.headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != test.status {
		t.Fatalf(
			"%s: status %d, want %d (%s)",
			test.desc,
			recorder.Code,
			test.status,
			recorder.Body.String(),
		)
	}

	if test.status != okStatus {
		return
	}

	for key, want := range test.expected {
		if got := req.Header.Values(key); len(got) != 1 || got[0] != want {
			t.Errorf("%s: %s = %q, want %q", test.desc, key, got, want)
		}
	}

	for _, key := range test.absent {
		if got := req.Header.Values(key); len(got) != 0 {
			t.Errorf("%s: %s should be removed, got %q", test.desc, key, got)
		}
	}
}

func netJoin(ip string) string {
	if ip != "" && ip[0] != '[' && containsColon(ip) {
		return "[" + ip + "]:12345"
	}

	return ip + ":12345"
}

func containsColon(value string) bool {
	for _, r := range value {
		if r == ':' {
			return true
		}
	}

	return false
}

var spoofHeaders = map[string][]string{
	"Cf-Connecting-Ip": {spoofedIPv4},
	"True-Client-Ip":   {spoofedIPv4},
	"X-Real-Ip":        {spoofedIPv4},
	"X-Forwarded-For":  {spoofedIPv4},
	"Forwarded":        {"for=" + spoofedIPv4},
	"Eo-Connecting-Ip": {spoofedIPv4},
	"X-Client-Ip":      {spoofedIPv4},
	"X-Is-Trusted":     {"yes"},
}

var strippedHeaders = []string{
	"Cf-Connecting-Ip", "True-Client-Ip", "Forwarded", "Eo-Connecting-Ip",
	"X-Client-Ip", "X-Is-Trusted", edgeHeader,
}

func withHeaders(base, extra map[string][]string) map[string][]string {
	merged := make(map[string][]string, len(base)+len(extra))
	maps.Copy(merged, base)
	maps.Copy(merged, extra)

	return merged
}

// A listener with no trusted peers (LAN VIP) uses the socket peer and strips every assertion.
func TestScopedNoTrustUsesPeer(t *testing.T) {
	handler := newScoped(t, nil)

	for _, remote := range []string{lanClientIP, podIPv4, podIPv6, clientIPv6, cfEdgeIPv4} {
		runScoped(t, handler, &scopedCase{
			desc: "no trust " + remote, remote: remote, status: okStatus,
			headers:  spoofHeaders,
			expected: map[string]string{"X-Real-Ip": remote, "X-Forwarded-For": remote},
			absent:   strippedHeaders,
		})
	}
}

// The cloudflared listener: pod peers may assert Cf-Connecting-Ip only with the edge secret.
func TestScopedCloudflaredWithEdgeSecret(t *testing.T) {
	path := writeSecret(t, edgeSecret+"\n"+edgeSecret2+"\n")
	handler := newScoped(t, func(cfg *traefikrealip.Config) {
		cfg.CloudflareTrustedIPs = []string{podCIDRv4, podCIDRv6}
		cfg.CloudflareAuthHeader = edgeHeader
		cfg.CloudflareAuthSecretFile = path
	})

	for _, remote := range []string{podIPv4, podIPv6} {
		for _, client := range []string{clientIPv4, clientIPv6} {
			runScoped(t, handler, &scopedCase{
				desc: "valid secret " + remote + " " + client, remote: remote, status: okStatus,
				headers: withHeaders(spoofHeaders, map[string][]string{
					"Cf-Connecting-Ip": {client}, edgeHeader: {edgeSecret},
				}),
				expected: map[string]string{"X-Real-Ip": client, "X-Forwarded-For": client},
				absent:   strippedHeaders,
			})
		}

		runScoped(t, handler, &scopedCase{
			desc:   "previous secret",
			remote: remote,
			status: okStatus,
			headers: map[string][]string{
				"Cf-Connecting-Ip": {clientIPv4},
				edgeHeader:         {edgeSecret2},
			},
			expected: map[string]string{"X-Real-Ip": clientIPv4},
			absent:   nil,
		})

		for desc, headers := range map[string]map[string][]string{
			"missing secret":   {"Cf-Connecting-Ip": {clientIPv4}},
			"wrong secret":     {"Cf-Connecting-Ip": {clientIPv4}, edgeHeader: {"wrong-secret-0123456789"}},
			"duplicate secret": {"Cf-Connecting-Ip": {clientIPv4}, edgeHeader: {edgeSecret, edgeSecret}},
			"secret, no cf ip": {edgeHeader: {edgeSecret}},
			"nothing":          {},
		} {
			runScoped(
				t,
				handler,
				&scopedCase{
					desc:     desc,
					remote:   remote,
					status:   forbidden,
					headers:  headers,
					expected: nil,
					absent:   nil,
				},
			)
		}
	}

	// Peers outside the cloudflared ranges never get Cf-Connecting-Ip, even with the secret.
	runScoped(t, handler, &scopedCase{
		desc: "lan with secret", remote: lanClientIP, status: okStatus,
		headers:  map[string][]string{"Cf-Connecting-Ip": {spoofedIPv4}, edgeHeader: {edgeSecret}},
		expected: map[string]string{"X-Real-Ip": lanClientIP},
		absent:   strippedHeaders,
	})
}

// Cloudflare ranges grant Cf-Connecting-Ip only, never X-Real-IP or X-Forwarded-For.
func TestScopedCloudflareRangesOnlyGrantCfHeader(t *testing.T) {
	handler := newScoped(t, func(cfg *traefikrealip.Config) { cfg.ThrustCloudFlare = true })

	runScoped(t, handler, &scopedCase{
		desc: "cf edge with header", remote: cfEdgeIPv6, status: okStatus,
		headers:  map[string][]string{"Cf-Connecting-Ip": {clientIPv6}},
		expected: map[string]string{"X-Real-Ip": clientIPv6},
		absent:   nil,
	})
	runScoped(t, handler, &scopedCase{
		desc: "cf edge, xff only", remote: cfEdgeIPv4, status: okStatus,
		headers:  map[string][]string{"X-Forwarded-For": {spoofedIPv4}, "X-Real-Ip": {spoofedIPv4}},
		expected: map[string]string{"X-Real-Ip": cfEdgeIPv4, "X-Forwarded-For": cfEdgeIPv4},
		absent:   nil,
	})
	runScoped(t, handler, &scopedCase{
		desc: "private peer", remote: podIPv4, status: okStatus,
		headers:  map[string][]string{"Cf-Connecting-Ip": {spoofedIPv4}},
		expected: map[string]string{"X-Real-Ip": podIPv4},
		absent:   nil,
	})
}

// Another Cloudflare customer's zone reaches the frp listener from Cloudflare ranges without the
// secret.
func TestScopedCloudflareRangesRequireSecret(t *testing.T) {
	path := writeSecret(t, edgeSecret)
	handler := newScoped(t, func(cfg *traefikrealip.Config) {
		cfg.ThrustCloudFlare = true
		cfg.CloudflareAuthHeader = edgeHeader
		cfg.CloudflareAuthSecretFile = path
	})

	runScoped(t, handler, &scopedCase{
		desc: "foreign zone", remote: cfEdgeIPv4, status: forbidden,
		headers:  map[string][]string{"Cf-Connecting-Ip": {spoofedIPv4}},
		expected: nil, absent: nil,
	})
	runScoped(t, handler, &scopedCase{
		desc: "our zone", remote: cfEdgeIPv4, status: okStatus,
		headers:  map[string][]string{"Cf-Connecting-Ip": {clientIPv4}, edgeHeader: {edgeSecret}},
		expected: map[string]string{"X-Real-Ip": clientIPv4},
		absent:   []string{edgeHeader},
	})
	runScoped(t, handler, &scopedCase{
		desc: "direct client", remote: clientIPv6, status: okStatus,
		headers:  map[string][]string{"Cf-Connecting-Ip": {spoofedIPv4}, edgeHeader: {edgeSecret}},
		expected: map[string]string{"X-Real-Ip": clientIPv6},
		absent:   strippedHeaders,
	})
}

// forwardedTrustedIPs is the only way X-Real-IP or X-Forwarded-For can be accepted.
func TestScopedForwardedTrust(t *testing.T) {
	handler := newScoped(t, func(cfg *traefikrealip.Config) {
		cfg.ForwardedTrustedIPs = []string{"127.0.0.1/32"}
	})

	runScoped(t, handler, &scopedCase{
		desc:   "trusted forwarder",
		remote: "127.0.0.1",
		status: okStatus,
		headers: map[string][]string{
			"X-Forwarded-For":  {clientIPv4 + ", 127.0.0.1"},
			"Cf-Connecting-Ip": {spoofedIPv4},
		},
		expected: map[string]string{"X-Real-Ip": clientIPv4, "X-Forwarded-For": clientIPv4},
		absent:   []string{"Cf-Connecting-Ip"},
	})
	runScoped(t, handler, &scopedCase{
		desc: "untrusted forwarder", remote: podIPv4, status: okStatus,
		headers:  map[string][]string{"X-Forwarded-For": {spoofedIPv4}},
		expected: map[string]string{"X-Real-Ip": podIPv4, "X-Forwarded-For": podIPv4},
		absent:   nil,
	})
}

func TestScopedMissingSecretFailsClosedPerRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")
	handler := newScoped(t, func(cfg *traefikrealip.Config) {
		cfg.CloudflareTrustedIPs = []string{podCIDRv4}
		cfg.CloudflareAuthHeader = edgeHeader
		cfg.CloudflareAuthSecretFile = path
	})

	runScoped(t, handler, &scopedCase{
		desc: "secret missing", remote: podIPv4, status: forbidden,
		headers:  map[string][]string{"Cf-Connecting-Ip": {clientIPv4}, edgeHeader: {edgeSecret}},
		expected: nil, absent: nil,
	})
	// Other peers are unaffected by the missing secret.
	runScoped(t, handler, &scopedCase{
		desc: "lan unaffected", remote: lanClientIP, status: okStatus,
		expected: map[string]string{"X-Real-Ip": lanClientIP},
		headers:  nil, absent: nil,
	})
}

func TestScopedSecretRotationIsPickedUp(t *testing.T) {
	path := writeSecret(t, edgeSecret)
	handler := newScoped(t, func(cfg *traefikrealip.Config) {
		cfg.CloudflareTrustedIPs = []string{podCIDRv4}
		cfg.CloudflareAuthHeader = edgeHeader
		cfg.CloudflareAuthSecretFile = path
	})

	// Replace the file the way kubelet does: a new inode with a new mtime.
	next := path + ".new"

	err := os.WriteFile(next, []byte(edgeSecret2), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	future := time.Now().Add(time.Minute)

	err = os.Chtimes(next, future, future)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Rename(next, path)
	if err != nil {
		t.Fatal(err)
	}

	traefikrealip.ExpireEdgeSecretCacheForTest(handler)

	runScoped(t, handler, &scopedCase{
		desc: "rotated secret", remote: podIPv4, status: okStatus,
		headers:  map[string][]string{"Cf-Connecting-Ip": {clientIPv4}, edgeHeader: {edgeSecret2}},
		expected: map[string]string{"X-Real-Ip": clientIPv4},
		absent:   nil,
	})
	runScoped(t, handler, &scopedCase{
		desc: "old secret gone", remote: podIPv4, status: forbidden,
		headers:  map[string][]string{"Cf-Connecting-Ip": {clientIPv4}, edgeHeader: {edgeSecret}},
		expected: nil, absent: nil,
	})
}

func TestScopedConfigErrors(t *testing.T) {
	for desc, mutate := range map[string]func(*traefikrealip.Config){
		"trustedIPs set":    func(cfg *traefikrealip.Config) { cfg.TrustedIPs = []string{"10.0.0.0/8"} },
		"header only":       func(cfg *traefikrealip.Config) { cfg.CloudflareAuthHeader = edgeHeader },
		"file only":         func(cfg *traefikrealip.Config) { cfg.CloudflareAuthSecretFile = "/tmp/x" },
		"bad forwarded":     func(cfg *traefikrealip.Config) { cfg.ForwardedTrustedIPs = []string{"nope"} },
		"bad cloudflare ip": func(cfg *traefikrealip.Config) { cfg.CloudflareTrustedIPs = []string{"10.0.0.0/33"} },
	} {
		cfg := traefikrealip.CreateConfig()
		cfg.ScopedTrust = true
		cfg.ThrustCloudFlare = false
		mutate(cfg)

		_, err := traefikrealip.New(t.Context(), http.NotFoundHandler(), cfg, "scoped")
		if err == nil {
			t.Errorf("%s: expected error", desc)
		}
	}
}

func TestScopedRejectsShortOrExtraSecrets(t *testing.T) {
	for desc, content := range map[string]string{
		"short":       "tooshort",
		"three":       edgeSecret + "\n" + edgeSecret2 + "\nthird-secret-0123456789",
		"empty lines": "\n\n",
	} {
		path := writeSecret(t, content)
		handler := newScoped(t, func(cfg *traefikrealip.Config) {
			cfg.CloudflareTrustedIPs = []string{podCIDRv4}
			cfg.CloudflareAuthHeader = edgeHeader
			cfg.CloudflareAuthSecretFile = path
		})

		runScoped(t, handler, &scopedCase{
			desc:   desc,
			remote: podIPv4,
			status: forbidden,
			headers: map[string][]string{
				"Cf-Connecting-Ip": {clientIPv4},
				edgeHeader:         {edgeSecret},
			},
			expected: nil, absent: nil,
		})
	}
}

func TestScopedInvalidCfHeader(t *testing.T) {
	path := writeSecret(t, edgeSecret)
	handler := newScoped(t, func(cfg *traefikrealip.Config) {
		cfg.CloudflareTrustedIPs = []string{podCIDRv4}
		cfg.CloudflareAuthHeader = edgeHeader
		cfg.CloudflareAuthSecretFile = path
	})

	runScoped(t, handler, &scopedCase{
		desc: "garbage", remote: podIPv4, status: badRequest,
		headers:  map[string][]string{"Cf-Connecting-Ip": {untrustedHdr}, edgeHeader: {edgeSecret}},
		expected: nil, absent: nil,
	})
}
