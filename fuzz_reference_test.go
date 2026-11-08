package traefik_real_ip

import (
	"bufio"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
)

// This file holds an independent reference model of the documented resolution rules.
// It parses address literals with its own RFC 4291 / dotted-quad grammar and evaluates
// trust with net/netip, so it shares no parsing or containment code with production.

const (
	refMaxHops       = 32
	refMaxXFFBytes   = 4096
	refIPv4Bits      = 32
	refIPv6Bits      = 128
	refMappedBits    = 96
	refIPv6Groups    = 8
	refMaxGroupHex   = 4
	refIPv4Octets    = 4
	refMaxOctetValue = 255
	refMaxOctetChars = 3
	refDecimalBase   = 10
	refHexBase       = 16
)

var refLocalCIDRs = []string{
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

// refParseIPv4 accepts only canonical dotted quads: four decimal octets, no leading zeros.
func refParseIPv4(text string) ([4]byte, bool) {
	var out [4]byte

	parts := strings.Split(text, ".")
	if len(parts) != refIPv4Octets {
		return out, false
	}

	for index, part := range parts {
		if part == "" || len(part) > refMaxOctetChars || (len(part) > 1 && part[0] == '0') {
			return out, false
		}

		value := 0

		for _, char := range []byte(part) {
			if char < '0' || char > '9' {
				return out, false
			}

			value = value*refDecimalBase + int(char-'0')
		}

		if value > refMaxOctetValue {
			return out, false
		}

		out[index] = byte(value)
	}

	return out, true
}

func refHexValue(char byte) (uint16, bool) {
	switch {
	case char >= '0' && char <= '9':
		return uint16(char - '0'), true
	case char >= 'a' && char <= 'f':
		return uint16(char-'a') + refDecimalBase, true
	case char >= 'A' && char <= 'F':
		return uint16(char-'A') + refDecimalBase, true
	default:
		return 0, false
	}
}

// refGroups parses colon-separated 16-bit groups; the last field may be a dotted quad.
func refGroups(text string, allowIPv4 bool) ([]uint16, bool) {
	if text == "" {
		return nil, true
	}

	fields := strings.Split(text, ":")
	groups := make([]uint16, 0, refIPv6Groups)

	for index, field := range fields {
		if allowIPv4 && index == len(fields)-1 && strings.Contains(field, ".") {
			quad, ok := refParseIPv4(field)
			if !ok {
				return nil, false
			}

			groups = append(
				groups,
				uint16(quad[0])<<8|uint16(quad[1]),
				uint16(quad[2])<<8|uint16(quad[3]),
			)

			continue
		}

		if field == "" || len(field) > refMaxGroupHex {
			return nil, false
		}

		var value uint16

		for _, char := range []byte(field) {
			digit, ok := refHexValue(char)
			if !ok {
				return nil, false
			}

			value = value*refHexBase + digit
		}

		groups = append(groups, value)
	}

	return groups, true
}

// refParseIPv6 implements the RFC 4291 section 2.2 text forms without zones.
func refParseIPv6(text string) ([16]byte, bool) {
	var out [16]byte

	head, tail, compressed := text, "", false
	if before, after, found := strings.Cut(text, "::"); found {
		head, tail, compressed = before, after, true
		if strings.Contains(tail, "::") {
			return out, false
		}
	}

	headGroups, ok := refGroups(head, !compressed)
	if !ok {
		return out, false
	}

	tailGroups, ok := refGroups(tail, true)
	if !ok {
		return out, false
	}

	total := len(headGroups) + len(tailGroups)
	if (compressed && total >= refIPv6Groups) || (!compressed && total != refIPv6Groups) {
		return out, false
	}

	groups := make([]uint16, refIPv6Groups)
	copy(groups, headGroups)
	copy(groups[refIPv6Groups-len(tailGroups):], tailGroups)

	for index, group := range groups {
		binary.BigEndian.PutUint16(out[2*index:], group)
	}

	return out, true
}

// refParseLiteral returns the address exactly as written (IPv4-mapped stays IPv6).
func refParseLiteral(text string) (netip.Addr, bool) {
	if strings.Contains(text, ":") {
		raw, ok := refParseIPv6(text)
		if !ok {
			return netip.Addr{}, false
		}

		return netip.AddrFrom16(raw), true
	}

	raw, ok := refParseIPv4(text)
	if !ok {
		return netip.Addr{}, false
	}

	return netip.AddrFrom4(raw), true
}

// refParseIP returns the client address in canonical form: IPv4-mapped IPv6 is IPv4.
func refParseIP(text string) (netip.Addr, bool) {
	addr, ok := refParseLiteral(text)

	return addr.Unmap(), ok
}

// refParseBits accepts a decimal prefix length without sign or leading zeros.
func refParseBits(text string, maxBits int) (int, bool) {
	if text == "" || len(text) > 3 || (len(text) > 1 && text[0] == '0') {
		return 0, false
	}

	bits := 0

	for _, char := range []byte(text) {
		if char < '0' || char > '9' {
			return 0, false
		}

		bits = bits*refDecimalBase + int(char-'0')
	}

	return bits, bits <= maxBits
}

// refParsePrefix parses a CIDR and normalizes IPv4-mapped prefixes of at least /96 to the
// equivalent IPv4 prefix, so membership is decided on the canonical client address.
func refParsePrefix(text string) (netip.Prefix, bool) {
	addrText, bitsText, found := strings.Cut(text, "/")
	if !found {
		return netip.Prefix{}, false
	}

	addr, ok := refParseLiteral(addrText)
	if !ok {
		return netip.Prefix{}, false
	}

	maxBits := refIPv4Bits
	if addr.Is6() {
		maxBits = refIPv6Bits
	}

	bits, ok := refParseBits(bitsText, maxBits)
	if !ok {
		return netip.Prefix{}, false
	}

	prefix := netip.PrefixFrom(addr, bits).Masked()
	if prefix.Addr().Is4In6() && prefix.Bits() >= refMappedBits {
		return netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-refMappedBits), true
	}

	return prefix, true
}

func refContains(prefixes []netip.Prefix, addr netip.Addr) bool {
	addr = addr.Unmap()

	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

func refIsPrivate(addr netip.Addr) bool {
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalMulticast() ||
		addr.IsLinkLocalUnicast()
}

// refPeerHost parses the host part of RemoteAddr. A zone is socket metadata and is
// accepted only as a single nonempty identifier after an IPv6 literal.
func refPeerHost(host string) (netip.Addr, bool) {
	addrText, zone, hasZone := strings.Cut(host, "%")
	if hasZone && (zone == "" || strings.Contains(zone, "%") || !strings.Contains(addrText, ":")) {
		return netip.Addr{}, false
	}

	return refParseIP(addrText)
}

// refRemoteAddr parses a host:port socket address as net/http reports it.
func refRemoteAddr(remote string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return netip.Addr{}, false
	}

	return refPeerHost(host)
}

// refOWS trims only the optional whitespace allowed around list elements (RFC 9110 5.6.1).
func refOWS(text string) string {
	return strings.Trim(text, " \t")
}

func refSingle(values []string) (netip.Addr, bool) {
	if len(values) != 1 {
		return netip.Addr{}, false
	}

	return refParseIP(values[0])
}

// refParseChain validates the whole X-Forwarded-For field, returning every hop.
func refParseChain(values []string) ([]netip.Addr, bool) {
	if len(values) != 1 || len(values[0]) > refMaxXFFBytes {
		return nil, false
	}

	tokens := strings.Split(values[0], ",")
	if len(tokens) > refMaxHops {
		return nil, false
	}

	hops := make([]netip.Addr, 0, len(tokens))

	for _, token := range tokens {
		hop, ok := refParseIP(refOWS(token))
		if !ok {
			return nil, false
		}

		hops = append(hops, hop)
	}

	return hops, true
}

// refWalk returns the first untrusted hop from the right, or the leftmost hop when all
// hops are trusted, together with its index.
func refWalk(trusted []netip.Prefix, hops []netip.Addr) (netip.Addr, int) {
	for index, hop := range slices.Backward(hops) {
		if !refContains(trusted, hop) {
			return hop, index
		}
	}

	return hops[0], 0
}

type refOutcome struct {
	client  netip.Addr
	xff     string
	status  int
	trusted bool
}

type refLegacy struct {
	trusted []netip.Prefix
	deny    bool
	replace bool
}

func (ref *refLegacy) resolve(peer netip.Addr, header http.Header) refOutcome {
	if !refContains(ref.trusted, peer) {
		if ref.deny {
			return refOutcome{
				status:  http.StatusForbidden,
				client:  netip.Addr{},
				xff:     "",
				trusted: false,
			}
		}

		return refOutcome{status: http.StatusOK, client: peer, xff: peer.String(), trusted: false}
	}

	client, ok := ref.clientFromHeaders(peer, header)
	if !ok {
		return refOutcome{
			status:  http.StatusBadRequest,
			client:  netip.Addr{},
			xff:     "",
			trusted: true,
		}
	}

	return refOutcome{
		status: http.StatusOK, client: client, xff: ref.outgoingXFF(client, header), trusted: true,
	}
}

func (ref *refLegacy) clientFromHeaders(peer netip.Addr, header http.Header) (netip.Addr, bool) {
	for _, name := range []string{CfConnectingIP, EoConnectingIP} {
		values := header.Values(name)
		if len(values) > 0 {
			return refSingle(values)
		}
	}

	values := header.Values(XRealIP)
	if len(values) > 0 {
		client, ok := refSingle(values)
		if !ok || !refIsPrivate(client) {
			return client, ok
		}
	}

	values = header.Values(XForwardedFor)
	if len(values) > 0 {
		hops, ok := refParseChain(values)
		if !ok {
			return netip.Addr{}, false
		}

		client, _ := refWalk(ref.trusted, hops)

		return client, true
	}

	return peer, true
}

// outgoingXFF models xForwardedForMode for a trusted peer: append puts the client first
// and keeps the other nonempty entries of the first incoming field line.
func (ref *refLegacy) outgoingXFF(client netip.Addr, header http.Header) string {
	if ref.replace {
		return client.String()
	}

	incoming := header.Get(XForwardedFor)
	if incoming == "" {
		return client.String()
	}

	out := []string{client.String()}

	for token := range strings.SplitSeq(incoming, ",") {
		token = strings.TrimSpace(token)
		if token != "" && token != client.String() {
			out = append(out, token)
		}
	}

	return strings.Join(out, ", ")
}

// refPrefixes parses CIDRs with the reference grammar, dropping rejected entries.
func refPrefixes(cidrs []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(cidrs))

	for _, cidr := range cidrs {
		prefix, ok := refParsePrefix(cidr)
		if ok {
			prefixes = append(prefixes, prefix)
		}
	}

	return prefixes
}

// fuzzCIDRList splits fuzz input into at most limit CIDRs accepted by both the reference
// grammar and net.ParseCIDR, so header targets exercise trust walks rather than config
// parsing (covered by FuzzConfigCIDRs).
func fuzzCIDRList(text string, limit int) []string {
	cidrs := make([]string, 0, limit)

	for line := range strings.SplitSeq(text, "\n") {
		if len(cidrs) == limit {
			break
		}

		_, _, err := net.ParseCIDR(line)
		if _, ok := refParsePrefix(line); ok && err == nil {
			cidrs = append(cidrs, line)
		}
	}

	return cidrs
}

func loadFixtureCIDRs(tb testing.TB, paths ...string) []string {
	tb.Helper()

	cidrs := make([]string, 0)

	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			tb.Fatal(err)
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				cidrs = append(cidrs, line)
			}
		}

		closeErr := file.Close()
		if scanner.Err() != nil || closeErr != nil {
			tb.Fatal(scanner.Err(), closeErr)
		}
	}

	return cidrs
}

func mustParseCIDRs(tb testing.TB, cidrs []string) []*net.IPNet {
	tb.Helper()

	nets, err := parseCIDRs(cidrs)
	if err != nil {
		tb.Fatal(err)
	}

	return nets
}

func discardLogger() *PluginLogger {
	return &PluginLogger{logger: slog.New(slog.DiscardHandler), pluginName: "fuzz"}
}

func bufferLogger(writer io.Writer) *PluginLogger {
	handler := slog.NewTextHandler(writer, &slog.HandlerOptions{
		Level: slog.LevelDebug, ReplaceAttr: replaceAttr, AddSource: false,
	})

	return &PluginLogger{logger: slog.New(handler), pluginName: "fuzz"}
}

// assertCanonicalIP checks that an outgoing identity value is a canonical address literal.
func assertCanonicalIP(t *testing.T, name, value string) netip.Addr {
	t.Helper()

	addr, ok := refParseIP(value)
	if !ok || addr.String() != value {
		t.Fatalf("%s is not a canonical address: %q", name, value)
	}

	return addr
}
