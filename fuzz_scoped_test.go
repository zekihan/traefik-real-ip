package traefik_real_ip

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Bits of the flags argument of FuzzScopedResolve.
const (
	scopedEdgeAuth = 1 << iota
	scopedDeny
	scopedHasCF
	scopedHasEO
	scopedHasXRI
	scopedHasXFF
	scopedHasAuth
	scopedRealSecret
	scopedRepeatCF
	scopedRepeatAuth
	scopedRepeatXFF
	scopedOverlap
	scopedAbortOnce
)

const (
	scopedAuthHeader = "X-Edge-Auth"
	scopedSecret     = "fuzz-current-secret-0123456789"  //nolint:gosec // test fixture
	scopedSecretOld  = "fuzz-previous-secret-0123456789" //nolint:gosec // test fixture
	scopedVariants   = 8
)

var (
	scopedCloudflareExtra = []string{"10.42.0.0/16", "fd42::/64"}
	scopedForwarded       = []string{"10.0.0.0/8", "fd00::/8", "::ffff:192.0.2.0/120"}
	scopedForwardedNoCF   = []string{"10.0.0.0/9", "fd00::/8", "::ffff:192.0.2.0/120"}
)

type scopedInput struct {
	peer, cf, eo, xri, xff, auth, other string
	flags                               uint16
}

func (input *scopedInput) has(flag uint16) bool {
	return input.flags&flag != 0
}

func (input *scopedInput) header() http.Header {
	header := make(http.Header)
	add := func(present, repeat uint16, name, value string) {
		if input.has(present) {
			header.Add(name, value)

			if input.has(repeat) {
				header.Add(name, value)
			}
		}
	}

	auth := input.auth
	if input.has(scopedRealSecret) {
		auth = scopedSecret
	}

	add(scopedHasCF, scopedRepeatCF, CfConnectingIP, input.cf)
	add(scopedHasEO, 0, EoConnectingIP, input.eo)
	add(scopedHasXRI, 0, XRealIP, input.xri)
	add(scopedHasXFF, scopedRepeatXFF, XForwardedFor, input.xff)
	add(scopedHasAuth, scopedRepeatAuth, scopedAuthHeader, auth)

	for _, name := range identityHeaders {
		if header.Get(name) == "" {
			header.Set(name, input.other)
		}
	}

	return header
}

type scopedFixture struct {
	resolvers  [scopedVariants]*IPResolver
	cloudflare [scopedVariants][]netip.Prefix
	forwarded  [scopedVariants][]netip.Prefix
	edgeOne    []netip.Prefix
}

func newScopedFixture(f *testing.F) *scopedFixture {
	f.Helper()

	path := filepath.Join(f.TempDir(), "edge-secret")

	err := os.WriteFile(path, []byte(scopedSecret+"\n"+scopedSecretOld+"\n"), 0o600)
	if err != nil {
		f.Fatal(err)
	}

	cloudflare := loadFixtureCIDRs(f, "remote_ips/cloudflare_v4", "remote_ips/cloudflare_v6")
	cloudflare = append(cloudflare, scopedCloudflareExtra...)
	edgeOne := loadFixtureCIDRs(f, "remote_ips/edgeone")
	fixture := &scopedFixture{
		resolvers:  [scopedVariants]*IPResolver{},
		cloudflare: [scopedVariants][]netip.Prefix{},
		forwarded:  [scopedVariants][]netip.Prefix{},
		edgeOne:    refPrefixes(edgeOne),
	}

	for variant := range scopedVariants {
		forwarded := scopedForwardedNoCF
		if variant&variantOverlap != 0 {
			forwarded = scopedForwarded
		}

		cfg := CreateConfig()
		cfg.ScopedTrust = true
		cfg.ThrustCloudFlare = false
		cfg.LogLevel = LogLevelError
		cfg.CloudflareTrustedIPs = cloudflare
		cfg.ForwardedTrustedIPs = forwarded
		cfg.DenyUntrusted = variant&variantDeny != 0

		if variant&variantEdgeAuth != 0 {
			cfg.CloudflareAuthHeader = scopedAuthHeader
			cfg.CloudflareAuthSecretFile = path
		}

		fixture.resolvers[variant] = newScopedVariant(f, cfg, edgeOne)
		fixture.cloudflare[variant] = refPrefixes(cloudflare)
		fixture.forwarded[variant] = refPrefixes(forwarded)
	}

	return fixture
}

// Bits of a scoped configuration variant.
const (
	variantEdgeAuth = 1 << iota
	variantDeny
	variantOverlap
)

func scopedVariant(flags uint16) int {
	variant := 0
	if flags&scopedEdgeAuth != 0 {
		variant |= variantEdgeAuth
	}

	if flags&scopedDeny != 0 {
		variant |= variantDeny
	}

	if flags&scopedOverlap != 0 {
		variant |= variantOverlap
	}

	return variant
}

func newScopedVariant(f *testing.F, cfg *Config, edgeOne []string) *IPResolver {
	f.Helper()

	handler, err := New(f.Context(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		cfg, "fuzz-scoped")
	if err != nil {
		f.Fatal(err)
	}

	resolver, ok := handler.(*IPResolver)
	if !ok {
		f.Fatal("unexpected handler type")
	}

	resolver.logger = discardLogger()
	// EdgeOne ranges come from the checked-in snapshot instead of a provider fetch.
	resolver.scoped.edgeOne = mustParseCIDRs(f, edgeOne)

	return resolver
}

func scopedSeeds() []scopedInput {
	cf, xff := uint16(scopedHasCF), uint16(scopedHasXFF)
	auth := uint16(scopedEdgeAuth | scopedHasAuth | scopedRealSecret)

	return []scopedInput{
		{"173.245.48.10", "198.51.100.7", "", "", "", "", "6.6.6.6", cf},
		{"173.245.48.10", "198.51.100.7", "", "", "", "", "", cf | auth},
		{
			"173.245.48.10",
			"198.51.100.7",
			"",
			"",
			"",
			"wrong-secret-0123456789",
			"",
			cf | scopedEdgeAuth | scopedHasAuth,
		},
		{
			"10.42.3.67",
			"2001:db8::7",
			"",
			"",
			"203.0.113.99",
			"",
			"",
			cf | auth | xff | scopedOverlap,
		},
		{"10.42.3.67", "", "", "", "203.0.113.99", "", "", auth | xff | scopedOverlap},
		{"10.1.1.1", "198.51.100.7", "", "", "203.0.113.99, 10.2.2.2", "", "for=1.2.3.4", cf | xff},
		{"10.1.1.1", "", "", "203.0.113.5", "", "", "", scopedHasXRI},
		{"10.1.1.1", "", "", "192.168.2.71", "203.0.113.1, 10.0.0.5", "", "", scopedHasXRI | xff},
		{
			"203.0.113.50",
			"1.2.3.4",
			"5.6.7.8",
			"9.9.9.9",
			"8.8.8.8",
			"",
			"7.7.7.7",
			cf | xff | scopedHasXRI,
		},
		{"203.0.113.50", "", "", "", "", "", "", scopedDeny},
		{"43.175.0.5", "", "198.51.100.3", "", "", "", "", scopedHasEO},
		{"43.175.0.5", "198.51.100.4", "198.51.100.3", "", "", "", "", scopedHasEO | cf},
		{"::ffff:192.0.2.9", "", "", "", "198.51.100.200, 192.0.2.10", "", "", xff},
		{
			"fd42::9",
			"2001:db8::1",
			"",
			"",
			"",
			scopedSecretOld,
			"",
			cf | scopedEdgeAuth | scopedHasAuth,
		},
		{"173.245.48.10", "1.2.3.4", "", "", "", "", "", cf | auth | scopedRepeatAuth},
		{"10.1.1.1", "", "", "", "203.0.113.99, 10.2.2.2", "", "", xff | scopedAbortOnce},
		{"173.245.48.10", "198.51.100.7", "", "", "", "", "", cf | auth | scopedAbortOnce},
	}
}

// FuzzScopedResolve drives scoped-trust mode with peers from every trust class and checks
// the reference: Cf-Connecting-Ip only from Cloudflare peers with a valid edge secret,
// Eo-Connecting-Ip only from EdgeOne peers, X-Real-IP/X-Forwarded-For only from forwarded
// peers, and every other identity header (and the secret) stripped downstream.
func FuzzScopedResolve(f *testing.F) {
	fixture := newScopedFixture(f)

	for _, seed := range scopedSeeds() {
		f.Add(seed.peer, seed.flags, seed.cf, seed.eo, seed.xri, seed.xff, seed.auth, seed.other)
	}

	f.Fuzz(func(t *testing.T, peer string, flags uint16, cf, eo, xri, xff, auth, other string) {
		input := &scopedInput{
			peer: peer, flags: flags, cf: cf, eo: eo, xri: xri, xff: xff, auth: auth, other: other,
		}
		checkScoped(t, fixture, input)
	})
}

func checkScoped(t *testing.T, fixture *scopedFixture, input *scopedInput) {
	t.Helper()

	variant := scopedVariant(input.flags)
	base := fixture.resolvers[variant]
	record := &downstreamRecord{headers: nil}
	resolver := *base
	resolver.next = record.handler(input.has(scopedAbortOnce))

	header := input.header()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = net.JoinHostPort(input.peer, fuzzPeerPort)
	req.Header = header.Clone()

	recorder := httptest.NewRecorder()
	resolver.ServeHTTP(recorder, req)

	ref := &refScoped{
		cloudflare: fixture.cloudflare[variant],
		forwarded:  fixture.forwarded[variant],
		edgeOne:    fixture.edgeOne,
		edgeAuth:   input.has(scopedEdgeAuth),
		deny:       input.has(scopedDeny),
	}

	status, client := http.StatusBadRequest, netip.Addr{}

	peer, peerOK := refRemoteAddr(req.RemoteAddr)
	if peerOK {
		status, client = ref.resolve(peer, header)
	}

	if recorder.Code != status {
		t.Fatalf("status %d, want %d (client %v)", recorder.Code, status, client)
	}

	if status != http.StatusOK {
		if len(record.headers) != 0 {
			t.Fatal("refused request reached downstream")
		}

		return
	}

	wantCalls := 1
	if input.has(scopedAbortOnce) {
		wantCalls = maxRetryCalls
	}

	if len(record.headers) != wantCalls {
		t.Fatalf("%d downstream calls, want %d", len(record.headers), wantCalls)
	}

	stripped := slices.Clone(identityHeaders)
	if input.has(scopedEdgeAuth) {
		stripped = append(stripped, scopedAuthHeader)
	}

	// An abort retry must reuse the identity resolved for the original request.
	for _, got := range record.headers {
		assertScopedHeaders(t, got, client, stripped)
	}
}

func assertScopedHeaders(t *testing.T, got http.Header, client netip.Addr, stripped []string) {
	t.Helper()

	for _, name := range stripped {
		if _, ok := got[http.CanonicalHeaderKey(name)]; ok {
			t.Fatalf("identity header %s not stripped: %q", name, got.Values(name))
		}
	}

	for _, name := range []string{XRealIP, XForwardedFor} {
		values := got.Values(name)
		if len(values) != 1 || assertCanonicalIP(t, name, values[0]) != client {
			t.Fatalf("%s = %q, want %v", name, values, client)
		}
	}
}

type refScoped struct {
	cloudflare, forwarded, edgeOne []netip.Prefix
	edgeAuth, deny                 bool
}

// resolve models README "Scoped trust" and returns the status and client address.
func (ref *refScoped) resolve(peer netip.Addr, header http.Header) (int, netip.Addr) {
	inCF := refContains(ref.cloudflare, peer)
	inEO := refContains(ref.edgeOne, peer)
	inForwarded := refContains(ref.forwarded, peer)

	if ref.deny && !inCF && !inEO && !inForwarded {
		return http.StatusForbidden, netip.Addr{}
	}

	if inCF {
		hasCF := len(header.Values(CfConnectingIP)) > 0
		if ref.edgeAuth && (!hasCF || !refSecretValid(header.Values(scopedAuthHeader))) {
			return http.StatusForbidden, netip.Addr{}
		}

		if hasCF {
			return refStatus(refSingle(header.Values(CfConnectingIP)))
		}
	}

	if inEO && len(header.Values(EoConnectingIP)) > 0 {
		return refStatus(refSingle(header.Values(EoConnectingIP)))
	}

	if !inForwarded {
		return http.StatusOK, peer
	}

	return ref.resolveForwarded(peer, header)
}

func (ref *refScoped) resolveForwarded(peer netip.Addr, header http.Header) (int, netip.Addr) {
	if values := header.Values(XRealIP); len(values) > 0 {
		client, ok := refSingle(values)
		if !ok || !refIsPrivate(client) {
			return refStatus(client, ok)
		}
	}

	if values := header.Values(XForwardedFor); len(values) > 0 {
		hops, ok := refParseChain(values)
		if !ok {
			return http.StatusBadRequest, netip.Addr{}
		}

		client, _ := refWalk(ref.forwarded, hops)

		return http.StatusOK, client
	}

	return http.StatusOK, peer
}

func refStatus(client netip.Addr, ok bool) (int, netip.Addr) {
	if !ok {
		return http.StatusBadRequest, netip.Addr{}
	}

	return http.StatusOK, client
}

func refSecretValid(values []string) bool {
	return len(values) == 1 && (values[0] == scopedSecret || values[0] == scopedSecretOld)
}

// FuzzEdgeSecrets checks the edge secret file parser and verifier: at most two trimmed,
// nonempty secrets of at least 16 bytes from a file of at most 4 KiB, and a request is
// authenticated only by exactly one header value equal to one of them.
func FuzzEdgeSecrets(f *testing.F) {
	f.Add([]byte(scopedSecret+"\n"+scopedSecretOld+"\n"), scopedSecret, false)
	f.Add([]byte(scopedSecret+"\r\n"), scopedSecret, false)
	f.Add([]byte(" \t"+scopedSecret+" \n\n"), scopedSecret, true)
	f.Add([]byte("short\n"), "short", false)
	f.Add([]byte("a\nb\nc\n"), "a", false)
	f.Add([]byte(scopedSecret+"\n"+scopedSecretOld+"\n"+scopedSecret), scopedSecret, false)
	f.Add([]byte(scopedSecret+"\u00a0"), scopedSecret, false)
	f.Add([]byte(""), "", false)

	dir := f.TempDir()

	f.Fuzz(func(t *testing.T, content []byte, presented string, repeat bool) {
		path := filepath.Join(dir, "secret")

		err := os.WriteFile(path, content, 0o600)
		if err != nil {
			t.Fatal(err)
		}

		secrets, err := readEdgeSecrets(path)

		want, wantOK := refEdgeSecrets(content)
		if (err == nil) != wantOK {
			t.Fatalf("readEdgeSecrets error %v, reference valid %v", err, wantOK)
		}

		if !wantOK {
			return
		}

		if len(secrets) != len(want) {
			t.Fatalf("secrets %q, want %q", secrets, want)
		}

		for index, secret := range secrets {
			if string(secret) != want[index] {
				t.Fatalf("secrets %q, want %q", secrets, want)
			}
		}

		checkEdgeVerify(t, path, presented, repeat, want)
	})
}

func checkEdgeVerify(t *testing.T, path, presented string, repeat bool, secrets []string) {
	t.Helper()

	auth := &edgeAuth{
		header: scopedAuthHeader, path: path,
		mu: sync.Mutex{}, secrets: nil, modTime: time.Time{}, size: 0,
		checked: time.Time{}, loadErr: nil,
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	req.Header.Add(scopedAuthHeader, presented)

	if repeat {
		req.Header.Add(scopedAuthHeader, presented)
	}

	err := auth.verify(req, time.Now())
	want := !repeat && slices.Contains(secrets, presented)

	if (err == nil) != want {
		t.Fatalf("verify(%q, repeat %v) = %v, want accepted %v", presented, repeat, err, want)
	}
}

func refEdgeSecrets(content []byte) ([]string, bool) {
	if len(content) > maxEdgeSecretFileBytes {
		return nil, false
	}

	secrets := make([]string, 0, maxEdgeSecrets)

	for line := range strings.SplitSeq(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if len(line) < minEdgeSecretBytes || len(secrets) == maxEdgeSecrets {
			return nil, false
		}

		secrets = append(secrets, line)
	}

	return secrets, len(secrets) > 0
}
