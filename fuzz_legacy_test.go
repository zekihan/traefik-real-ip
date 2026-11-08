package traefik_real_ip

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Bits of the flags argument of FuzzLegacyResolve.
const (
	legacyTrustLocal = 1 << iota
	legacyTrustCloudflare
	legacyDeny
	legacyReplace
	legacyHasCF
	legacyHasEO
	legacyHasXRI
	legacyHasXFF
	legacyRepeatCF
	legacyRepeatXRI
	legacyRepeatXFF
	legacyAbortOnce
	legacyRepeatEO
)

const (
	fuzzMaxCIDRs   = 8
	fuzzPeerPort   = "443"
	maxRetryCalls  = 2
	maxLogBytes    = 64 << 10
	maxSingleChars = 45
)

type legacyInput struct {
	peer, cidrs, cf, eo, xri, xff string
	flags                         uint16
}

type downstreamRecord struct {
	headers []http.Header
}

func (record *downstreamRecord) handler(abortOnce bool) http.Handler {
	return http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		record.headers = append(record.headers, req.Header.Clone())

		if abortOnce && len(record.headers) == 1 {
			panic(http.ErrAbortHandler)
		}
	})
}

func (input *legacyInput) has(flag uint16) bool {
	return input.flags&flag != 0
}

func (input *legacyInput) header() http.Header {
	header := make(http.Header)
	fields := []struct {
		name, value     string
		present, repeat uint16
	}{
		{CfConnectingIP, input.cf, legacyHasCF, legacyRepeatCF},
		{EoConnectingIP, input.eo, legacyHasEO, legacyRepeatEO},
		{XRealIP, input.xri, legacyHasXRI, legacyRepeatXRI},
		{XForwardedFor, input.xff, legacyHasXFF, legacyRepeatXFF},
	}

	for _, field := range fields {
		if !input.has(field.present) {
			continue
		}

		header.Add(field.name, field.value)

		if input.has(field.repeat) {
			header.Add(field.name, field.value)
		}
	}

	// A client-supplied verdict must always be overwritten.
	header.Set(XIsTrusted, "yes")

	return header
}

func (input *legacyInput) config(cloudflare []string) (*Config, []string) {
	cidrs := fuzzCIDRList(input.cidrs, fuzzMaxCIDRs)
	trusted := append([]string{}, cidrs...)

	if input.has(legacyTrustCloudflare) {
		cidrs = append(cidrs, cloudflare...)
		trusted = append(trusted, cloudflare...)
	}

	if input.has(legacyTrustLocal) {
		trusted = append(trusted, refLocalCIDRs...)
	}

	cfg := CreateConfig()
	cfg.LogLevel = LogLevelError
	cfg.ThrustCloudFlare = false
	cfg.ThrustLocal = input.has(legacyTrustLocal)
	cfg.TrustedIPs = cidrs
	cfg.DenyUntrusted = input.has(legacyDeny)

	if input.has(legacyReplace) {
		cfg.XForwardedForMode = XForwardedForModeReplace
	}

	return cfg, trusted
}

func legacySeeds() []legacyInput {
	all := uint16(legacyTrustLocal | legacyTrustCloudflare)
	xff := uint16(legacyHasXFF)

	return []legacyInput{
		{"10.0.0.1", "", "", "", "", "198.51.100.66, 203.0.113.10, 10.0.0.2", all | xff},
		{
			"192.0.2.1",
			"192.0.3.0/24\n192.0.2.0/24",
			"",
			"",
			"",
			"198.51.100.66, 203.0.113.10, 192.0.2.2",
			xff,
		},
		{
			"203.0.113.5",
			"",
			"1.2.3.4",
			"",
			"5.6.7.8",
			"9.9.9.9",
			all | legacyHasCF | legacyHasXRI | xff,
		},
		{"203.0.113.5", "", "", "", "", "", all | legacyDeny},
		{"173.245.48.10", "", "2001:db8::7", "", "", "", all | legacyHasCF},
		{"173.245.48.10", "", "2001:db8::7", "", "", "", all | legacyHasCF | legacyRepeatCF},
		{"10.0.0.1", "", "", "198.51.100.9", "", "", all | legacyHasEO},
		{"10.0.0.1", "", "", "", "192.168.1.5", "10.9.9.9, 203.0.113.7", all | legacyHasXRI | xff},
		{"10.0.0.1", "", "", "", "::ffff:198.51.100.1", "", all | legacyHasXRI},
		{"fe80::1%eth0", "", "", "", "", "fd20::10, fd00::2", all | xff},
		{"fd00::1", "fd00::/8", "", "", "", "fd99::66, 2001:db8::10, fd00::2", xff | legacyReplace},
		{"10.0.0.1", "::ffff:198.51.100.0/120", "", "", "", "198.51.100.8,10.0.0.3", all | xff},
		{"::ffff:10.0.0.1", "", "", "", "", "1.1.1.1 ,\t2.2.2.2", all | xff},
		{"10.0.0.1", "", "", "", "", "1.1.1.1, ", all | xff},
		{"10.0.0.1", "", "", "", "", "1.1.1.1\u00a0, 10.0.0.9", all | xff},
		{"10.0.0.1", "", "", "", "", "1.1.1.1", all | xff | legacyRepeatXFF},
		{"10.0.0.1", "", "", "", "", "[2001:db8::1]:443, 1.2.3.4:80", all | xff},
		{
			"10.0.0.1",
			"",
			"",
			"",
			"0000:0000:0000:0000:0000:ffff:255.255.255.255",
			"",
			all | legacyHasXRI,
		},
		{"10.0.0.1", "", "", "", "", "1.1.1.1", all | xff | legacyAbortOnce},
		{"10.0.0.1", "", "8.8.8.8", "", "", "8.8.8.8, 7.7.7.7", all | legacyHasCF | xff},
		{"127.0.0.1", "", "", "", "", strings.Repeat("10.0.0.1,", 31) + "10.0.0.1", all | xff},
		{"127.0.0.1", "", "", "", "", strings.Repeat("10.0.0.1,", 32) + "10.0.0.1", all | xff},
	}
}

// FuzzLegacyResolve drives the default (non-scoped) middleware with arbitrary peers, trust
// lists and identity headers and compares every outcome with the reference model:
// status, resolved X-Real-IP, X-Is-Trusted and the outgoing X-Forwarded-For.
func FuzzLegacyResolve(f *testing.F) {
	cloudflare := loadFixtureCIDRs(f, "remote_ips/cloudflare_v4", "remote_ips/cloudflare_v6")

	for _, seed := range legacySeeds() {
		f.Add(seed.peer, seed.cidrs, seed.flags, seed.cf, seed.eo, seed.xri, seed.xff)
	}

	f.Fuzz(func(t *testing.T, peer, cidrs string, flags uint16, cf, eo, xri, xff string) {
		input := &legacyInput{
			peer: peer, cidrs: cidrs, flags: flags, cf: cf, eo: eo, xri: xri, xff: xff,
		}
		checkLegacy(t, input, cloudflare)
	})
}

func checkLegacy(t *testing.T, input *legacyInput, cloudflare []string) {
	t.Helper()

	cfg, trusted := input.config(cloudflare)
	record := &downstreamRecord{headers: nil}

	handler, err := New(t.Context(), record.handler(input.has(legacyAbortOnce)), cfg, "fuzz")
	if err != nil {
		t.Fatalf("New rejected filtered config: %v", err)
	}

	resolver, ok := handler.(*IPResolver)
	if !ok {
		t.Fatal("unexpected handler type")
	}

	resolver.logger = discardLogger()

	header := input.header()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = net.JoinHostPort(input.peer, fuzzPeerPort)
	req.Header = header.Clone()

	recorder := httptest.NewRecorder()
	resolver.ServeHTTP(recorder, req)

	ref := &refLegacy{
		trusted: refPrefixes(trusted),
		deny:    input.has(legacyDeny),
		replace: input.has(legacyReplace),
	}

	peerAddr, peerOK := refRemoteAddr(req.RemoteAddr)
	if !peerOK {
		if recorder.Code != http.StatusBadRequest || len(record.headers) != 0 {
			t.Fatalf("invalid peer %q accepted with status %d", input.peer, recorder.Code)
		}

		return
	}

	want := ref.resolve(peerAddr, header)
	assertLegacyOutcome(t, &want, recorder.Code, record, peerAddr)

	if calls := len(record.headers); want.status == http.StatusOK &&
		input.has(legacyAbortOnce) != (calls == maxRetryCalls) {
		t.Fatalf("%d downstream calls, abort retry %v", calls, input.has(legacyAbortOnce))
	}

	assertProvenance(t, header, peerAddr, ref.trusted, record)
}

func assertLegacyOutcome(
	t *testing.T,
	want *refOutcome,
	status int,
	record *downstreamRecord,
	peer netip.Addr,
) {
	t.Helper()

	if want.status != http.StatusOK {
		if status != want.status || len(record.headers) != 0 {
			t.Fatalf("status %d (downstream calls %d), want %d", status, len(record.headers),
				want.status)
		}

		return
	}

	if len(record.headers) == 0 || len(record.headers) > maxRetryCalls {
		t.Fatalf("status %d with %d downstream calls, want 200", status, len(record.headers))
	}

	for _, got := range record.headers {
		assertLegacyHeaders(t, want, got, peer)
	}
}

func assertLegacyHeaders(t *testing.T, want *refOutcome, got http.Header, peer netip.Addr) {
	t.Helper()

	verdict := map[bool]string{true: "yes", false: "no"}[want.trusted]

	client := assertCanonicalIP(t, XRealIP, got.Get(XRealIP))
	if client != want.client || len(got.Values(XRealIP)) != 1 {
		t.Fatalf("X-Real-IP %v, want %v", got.Values(XRealIP), want.client)
	}

	if got.Get(XIsTrusted) != verdict || len(got.Values(XIsTrusted)) != 1 {
		t.Fatalf("X-Is-Trusted %v, want %s", got.Values(XIsTrusted), verdict)
	}

	if got.Get(XForwardedFor) != want.xff || len(got.Values(XForwardedFor)) != 1 {
		t.Fatalf("X-Forwarded-For %q, want %q", got.Values(XForwardedFor), want.xff)
	}

	if !want.trusted && client != peer {
		t.Fatalf("untrusted peer %v attributed to %v", peer, client)
	}
}

// assertProvenance is an oracle independent of the reference walk: a resolved address
// other than the peer must come from an identity header of a trusted peer, and an
// address taken from X-Forwarded-For must have only trusted hops on its right.
func assertProvenance(
	t *testing.T,
	header http.Header,
	peer netip.Addr,
	trusted []netip.Prefix,
	record *downstreamRecord,
) {
	t.Helper()

	if len(record.headers) == 0 {
		return
	}

	client, _ := refParseIP(record.headers[0].Get(XRealIP))
	if client == peer {
		return
	}

	if !refContains(trusted, peer) {
		t.Fatalf("headers of untrusted peer %v produced %v", peer, client)
	}

	for _, name := range []string{CfConnectingIP, EoConnectingIP, XRealIP} {
		if addr, ok := refSingle(header.Values(name)); ok && addr == client {
			return
		}
	}

	hops, ok := refParseChain(header.Values(XForwardedFor))
	if !ok {
		t.Fatalf("client %v has no valid source header", client)
	}

	for _, hop := range slices.Backward(hops) {
		if hop == client {
			return
		}

		if !refContains(trusted, hop) {
			t.Fatalf("client %v taken from beyond untrusted hop %v", client, hop)
		}
	}

	t.Fatalf("client %v not present in X-Forwarded-For", client)
}

// Address pool for FuzzForwardedForChain. Each chain byte selects an entry (low 6 bits)
// and the whitespace around it (high 2 bits).
var xffPool = []string{
	// Trusted by xffTrustedCIDRs.
	"10.1.2.3", "::ffff:10.1.2.3", "::FFFF:10.1.2.3", "0:0:0:0:0:ffff:a01:203",
	"192.168.1.1", "fd00::1", "FD00:0:0::1", "fd00:0000::0001",
	"2001:db8:aaaa::5", "198.51.100.7", "::ffff:198.51.100.7", "10.255.255.255",
	// Untrusted look-alikes of trusted addresses.
	"::10.1.2.3", "64:ff9b::a01:203", "2002:a01:203::1", "::ffff:0:10.1.2.3",
	"fe80::1", "2001:db8:aaab::5", "198.51.101.7", "11.1.2.3",
	"192.169.1.1", "fe00::1", "::ffff:198.51.101.7", "::a01:203",
	// Untrusted public.
	"1.1.1.1", "203.0.113.9", "2001:db8:bbbb::1", "8.8.8.8",
	"0.0.0.0", "::", "255.255.255.255", "ff02::1",
	// Malformed.
	"", "10.1.2.3:80", "[fd00::1]", "fd00::1%eth0",
	"010.1.2.3", "1.2.3", "unknown", "_hidden",
	"10.1.2.3\u00a0", "\u00851.1.1.1", "1.1.1.1\u3000", "\u20281.1.1.1",
	"1.1.1.1\x00", "1.1.1.1/32", "1.1.1.1;", "\"1.1.1.1\"",
	"fd00:::1", "fd00::1::2", "1:2:3:4:5:6:7:8:9", "::ffff:1.1.1.01",
	"0x0a.1.2.3", "10.1.2.3.", "+10.1.2.3", "\uff11.1.1.1",
	"10.1.2.3 10.1.2.4", "fd00::g", "1:2:3:4:5:6:7::", "1:2:3:4:5:6:7:8::",
	"\v1.1.1.1", "1.1.1.1\f", "1.1.1.1\r", "\n1.1.1.1",
}

var xffTrustedCIDRs = []string{
	"10.0.0.0/8", "192.168.0.0/16", "fd00::/8", "2001:db8:aaaa::/48", "::ffff:198.51.100.0/120",
}

var xffPeers = []string{
	"10.0.0.1", "::ffff:10.0.0.1", "192.168.0.1", "fd00::ff", "2001:db8:aaaa::1",
	"198.51.100.1", "203.0.113.1", "2001:db8:bbbb::1",
}

var xffSpacing = [][2]string{{"", ""}, {" ", ""}, {"", " "}, {"\t", " "}}

const (
	xffPoolMask   = 0x3f
	xffSpaceShift = 6
)

func buildChain(chain []byte) string {
	parts := make([]string, 0, len(chain))

	for _, selector := range chain {
		spacing := xffSpacing[selector>>xffSpaceShift]
		parts = append(parts, spacing[0]+xffPool[int(selector&xffPoolMask)%len(xffPool)]+spacing[1])
	}

	return strings.Join(parts, ",")
}

func newChainResolver(tb testing.TB, cidrs []string) *IPResolver {
	tb.Helper()

	return &IPResolver{
		logger: discardLogger(), conf: CreateConfig(), name: "fuzz", next: nil, scoped: nil,
		trustedIPNets: mustParseCIDRs(tb, cidrs),
	}
}

// FuzzForwardedForChain composes X-Forwarded-For chains from a pool of trusted, look-alike,
// untrusted and malformed hops and checks the trust walk against the reference: the
// result is never left of an untrusted hop, and equivalent spellings of the same chain
// (whitespace, IPv4-mapped, expanded or upper-case IPv6) resolve identically.
func FuzzForwardedForChain(f *testing.F) {
	f.Add(uint8(0), []byte{24, 0, 4})
	f.Add(uint8(0), []byte{25, 12, 0})
	f.Add(uint8(1), []byte{1, 2, 3, 4, 5, 6, 7})
	f.Add(uint8(4), []byte{13, 14, 15, 9})
	f.Add(uint8(6), []byte{0, 1})
	f.Add(uint8(0), []byte{40, 0})
	f.Add(uint8(0), []byte{0x40 | 24, 0xc0 | 5, 0x80 | 10})
	f.Add(uint8(3), bytes.Repeat([]byte{5}, 33))

	resolver := newChainResolver(f, xffTrustedCIDRs)
	trusted := refPrefixes(xffTrustedCIDRs)

	f.Fuzz(func(t *testing.T, peerSelector uint8, chain []byte) {
		peer := netip.MustParseAddr(xffPeers[int(peerSelector)%len(xffPeers)])
		xff := buildChain(chain)

		got, gotErr := resolveChain(t.Context(), resolver, peer, xff)

		want, wantIndex, wantOK := peer.Unmap(), -1, true
		if refContains(trusted, peer) {
			var hops []netip.Addr

			hops, wantOK = refParseChain([]string{xff})
			if wantOK {
				want, wantIndex = refWalk(trusted, hops)
				checkChainSpellings(t, resolver, peer, hops, want)
			}
		}

		if (gotErr == nil) != wantOK {
			t.Fatalf("chain %q: error %v, reference valid %v", xff, gotErr, wantOK)
		}

		if wantOK && got != want {
			t.Fatalf("chain %q: got %v, want %v (hop %d)", xff, got, want, wantIndex)
		}
	})
}

func resolveChain(
	ctx context.Context,
	resolver *IPResolver,
	peer netip.Addr,
	xff string,
) (netip.Addr, error) {
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/", http.NoBody)
	req.Header.Set(XForwardedFor, xff)

	ip, err := resolver.handleXForwardedFor(ctx, net.IP(peer.AsSlice()), req)
	if err != nil {
		return netip.Addr{}, err
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("%w: %v", ErrInvalidIPFormat, ip)
	}

	return addr.Unmap(), nil
}

func expandedIPv6(addr netip.Addr) string {
	raw := addr.As16()
	groups := make([]string, 0, refIPv6Groups)

	for index := 0; index < len(raw); index += 2 {
		groups = append(groups, fmt.Sprintf("%04X", binary.BigEndian.Uint16(raw[index:])))
	}

	return strings.Join(groups, ":")
}

func checkChainSpellings(
	t *testing.T,
	resolver *IPResolver,
	peer netip.Addr,
	hops []netip.Addr,
	want netip.Addr,
) {
	t.Helper()

	canonical := make([]string, 0, len(hops))
	alternate := make([]string, 0, len(hops))

	for _, hop := range hops {
		canonical = append(canonical, hop.String())

		if hop.Is4() {
			alternate = append(alternate, "::ffff:"+hop.String())
		} else {
			alternate = append(alternate, expandedIPv6(hop))
		}
	}

	for _, spelling := range []string{
		strings.Join(canonical, ", "),
		strings.Join(canonical, ","),
		" \t" + strings.Join(alternate, " ,\t") + "\t ",
	} {
		got, err := resolveChain(t.Context(), resolver, peer, spelling)
		if err != nil || got != want {
			t.Fatalf("equivalent chain %q: got %v (%v), want %v", spelling, got, err, want)
		}
	}
}

var rawPeers = []string{
	"10.0.0.1:41000", "173.245.48.10:443", "[2400:cb00::10]:443", "203.0.113.5:5555",
	"[fe80::1%eth0]:80", "[::ffff:10.0.0.1]:80", "[2001:db8::5]:1", "198.51.100.20:9",
}

var rawTrustedCIDRs = []string{"198.51.100.0/24"}

// FuzzRawHTTPRequest parses raw HTTP/1.1 request bytes with net/http, as Traefik does, and
// serves them through the default middleware. Beyond agreeing with the reference, the
// debug log must stay bounded and must not echo long raw header values, and re-encoding
// the request with different header-name case and optional whitespace gives the same
// result.
func FuzzRawHTTPRequest(f *testing.F) {
	for _, seed := range rawRequestSeeds() {
		f.Add(uint8(0), false, []byte(seed))
		f.Add(uint8(1), true, []byte(seed))
	}

	cloudflare := loadFixtureCIDRs(f, "remote_ips/cloudflare_v4", "remote_ips/cloudflare_v6")
	trusted := append(append(append([]string{}, rawTrustedCIDRs...), cloudflare...),
		refLocalCIDRs...)

	f.Fuzz(func(t *testing.T, peerSelector uint8, replace bool, raw []byte) {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			return
		}

		remote := rawPeers[int(peerSelector)%len(rawPeers)]
		ref := &refLegacy{trusted: refPrefixes(trusted), deny: false, replace: replace}

		first := serveRaw(t, req, remote, replace, cloudflare, ref)

		variant, ok := respell(req.Header)
		if !ok {
			return
		}

		again, err := http.ReadRequest(bufio.NewReader(strings.NewReader(variant)))
		if err != nil {
			t.Fatalf("re-encoded request rejected: %v\n%q", err, variant)
		}

		second := serveRaw(t, again, remote, replace, cloudflare, ref)
		if first != second {
			t.Fatalf("respelled request changed result: %q vs %q", first, second)
		}
	})
}

func rawRequestSeeds() []string {
	return []string{
		"GET / HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: 198.51.100.66, 203.0.113.10\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nx-forwarded-for: 1.1.1.1\r\nX-FORWARDED-FOR: 2.2.2.2\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nCf-Connecting-Ip: 2001:db8::1\r\nX-Real-Ip: 1.2.3.4\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\ncf-connecting-ip:\t 9.9.9.9 \t\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nEo-Connecting-Ip: 1.2.3.4\r\nX-Is-Trusted: yes\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX-Real-IP: 10.1.1.1\r\nX-Forwarded-For: 5.5.5.5,10.1.1.1\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: \r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: 1.1.1.1\xc2\xa0, 10.0.0.2\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nForwarded: for=1.2.3.4;proto=https\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: " + strings.Repeat("A", 5000) + "\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX-Real-IP: " + strings.Repeat("1", 200) + "\r\n\r\n",
	}
}

func serveRaw(
	t *testing.T,
	req *http.Request,
	remote string,
	replace bool,
	cloudflare []string,
	ref *refLegacy,
) string {
	t.Helper()

	cfg := CreateConfig()
	cfg.LogLevel = LogLevelError
	cfg.ThrustCloudFlare = false

	cfg.TrustedIPs = append(append([]string{}, rawTrustedCIDRs...), cloudflare...)

	if replace {
		cfg.XForwardedForMode = XForwardedForModeReplace
	}

	record := &downstreamRecord{headers: nil}

	handler, err := New(t.Context(), record.handler(false), cfg, "fuzz")
	if err != nil {
		t.Fatal(err)
	}

	resolver, ok := handler.(*IPResolver)
	if !ok {
		t.Fatal("unexpected handler type")
	}

	var logs bytes.Buffer

	resolver.logger = bufferLogger(&logs)

	header := req.Header.Clone()
	req.RemoteAddr = remote
	req = req.WithContext(t.Context())

	recorder := httptest.NewRecorder()
	resolver.ServeHTTP(recorder, req)

	peer, _ := refRemoteAddr(remote)
	want := ref.resolve(peer, header)
	assertLegacyOutcome(t, &want, recorder.Code, record, peer)
	assertProvenance(t, header, peer, ref.trusted, record)
	assertBoundedLogs(t, logs.String(), header)

	// Only identity output is compared: names that are not valid tokens are kept verbatim
	// by net/textproto, so their case legitimately differs between spellings.
	identity := make([]string, 0, len(record.headers))
	for _, got := range record.headers {
		identity = append(identity, fmt.Sprintf("%q %q %q", got.Values(XRealIP),
			got.Values(XForwardedFor), got.Values(XIsTrusted)))
	}

	return fmt.Sprintf("%d %v", recorder.Code, identity)
}

// assertBoundedLogs checks that diagnostics stay small and never echo raw header values.
// Every address the plugin logs is at most 45 bytes, so a longer header substring in the
// log would be a raw echo.
func assertBoundedLogs(t *testing.T, logs string, header http.Header) {
	t.Helper()

	if len(logs) > maxLogBytes || strings.Contains(logs, "exceptionStacktrace") {
		t.Fatalf("unbounded diagnostics: %d bytes", len(logs))
	}

	for _, values := range header {
		for _, value := range values {
			if len(value) <= maxSingleChars {
				continue
			}

			for _, window := range []string{value[:maxSingleChars+1], value[len(value)-maxSingleChars-1:]} {
				if strings.Contains(logs, window) {
					t.Fatalf("raw header value echoed in logs: %q", window)
				}
			}
		}
	}
}

// respell re-encodes headers with alternating header-name case and optional whitespace
// around every value. It reports false when a value cannot be re-encoded faithfully.
func respell(header http.Header) (string, bool) {
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}

	sort.Strings(names)

	var out strings.Builder

	out.WriteString("GET / HTTP/1.1\r\n")

	for index, name := range names {
		spelled := strings.ToLower(name)
		if index%2 == 1 {
			spelled = strings.ToUpper(name)
		}

		for _, value := range header[name] {
			if strings.ContainsAny(value, "\r\n\x00") || refOWS(value) != value {
				return "", false
			}

			out.WriteString(spelled + ":\t " + value + " \t\r\n")
		}
	}

	out.WriteString("\r\n")

	return out.String(), true
}
