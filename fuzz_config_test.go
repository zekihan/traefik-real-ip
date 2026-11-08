package traefik_real_ip

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

const (
	fuzzMaxConfigCIDRs = 16
	providerLineSlack  = 2
)

// refParsePrefixLenient additionally accepts leading zeros in the prefix length, as
// net.ParseCIDR does ("10.0.0.0/08" is 10.0.0.0/8). The value is unambiguous decimal, so
// this stdlib leniency is recorded in docs/fuzzing.md rather than treated as a defect.
func refParsePrefixLenient(text string) (netip.Prefix, bool) {
	addrText, bitsText, found := strings.Cut(text, "/")
	if found && len(bitsText) > 1 {
		trimmed := strings.TrimLeft(bitsText, "0")
		if trimmed == "" {
			trimmed = "0"
		}

		text = addrText + "/" + trimmed
	}

	return refParsePrefix(text)
}

// prefixFromIPNet converts a production network to the reference form.
func prefixFromIPNet(block *net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(block.IP)
	ones, bits := block.Mask.Size()

	if !ok || bits == 0 {
		return netip.Prefix{}, false
	}

	if bits == refIPv4Bits {
		addr = addr.Unmap()
	}

	prefix := netip.PrefixFrom(addr, ones)
	if addr.Is4In6() && ones >= refMappedBits {
		prefix = netip.PrefixFrom(addr.Unmap(), ones-refMappedBits)
	}

	return prefix, prefix.IsValid()
}

var membershipProbes = []string{
	"0.0.0.0", "255.255.255.255", "::", "::ffff:0:0", "10.0.0.1", "::ffff:10.0.0.1",
	"::a00:1", "64:ff9b::a00:1", "2002:a00:1::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
}

// probeAddrs returns boundary addresses of a prefix in IPv4 and IPv4-mapped spellings.
func probeAddrs(prefix netip.Prefix) []netip.Addr {
	first := prefix.Masked().Addr()
	raw := first.AsSlice()
	hostBits := len(raw)*8 - prefix.Bits()

	for index := len(raw) - 1; index >= 0 && hostBits > 0; index-- {
		take := min(hostBits, 8)
		raw[index] |= byte(1<<take - 1)
		hostBits -= take
	}

	last, _ := netip.AddrFromSlice(raw)
	probes := []netip.Addr{first, last}

	for _, addr := range []netip.Addr{first, last} {
		if addr.Is4() {
			probes = append(probes, netip.AddrFrom16(addr.As16()))
		}
	}

	return probes
}

// assertSameMembership compares production containment with reference containment on the
// boundaries of every network and on fixed probes, in both IPv4 and IPv4-mapped forms.
func assertSameMembership(t *testing.T, nets []*net.IPNet, prefixes []netip.Prefix) {
	t.Helper()

	probes := make([]netip.Addr, 0, len(membershipProbes)+4*len(prefixes))
	for _, text := range membershipProbes {
		probes = append(probes, netip.MustParseAddr(text))
	}

	for _, prefix := range prefixes {
		probes = append(probes, probeAddrs(prefix)...)
	}

	for _, probe := range probes {
		got := netsContain(nets, net.IP(probe.AsSlice()))
		if want := refContains(prefixes, probe); got != want {
			t.Fatalf("membership of %v: production %v, reference %v (%v)", probe, got, want,
				prefixes)
		}
	}
}

// FuzzProviderCIDRs feeds arbitrary provider responses to the streaming CIDR parser. An
// accepted snapshot must be nonempty, bounded, deduplicated, free of default routes
// (including IPv4-mapped spellings) and equal to the reference parse; a response with any
// invalid entry is rejected in full.
func FuzzProviderCIDRs(f *testing.F) {
	for _, seed := range []string{
		"173.245.48.0/20\n103.21.244.0/22\n",
		"2400:cb00::/32\r\n2606:4700::/32",
		"# comment\n\n  1.2.3.0/24  \n1.2.3.0/24\n::ffff:1.2.3.0/120\n",
		"0.0.0.0/0\n", "::/0\n", "::ffff:0:0/96\n", "::ffff:0.0.0.0/97\n", "0.0.0.0/1\n",
		"1.2.3.4/24\n", "1.2.3.0/024\n", "1.2.3.0/33\n", "fe80::1%eth0/64\n", "1.2.3.0/24 #x\n",
		"", "#only\n", "1.2.3.0/24\x00\n", "1.2.3.0/24\u00a0\n", strings.Repeat("9.9.9.0/24\n", 300),
	} {
		f.Add([]byte(seed))
	}

	resolver := newChainResolver(f, nil)

	f.Fuzz(func(t *testing.T, body []byte) {
		nets, err := resolver.parseCIDRs(t.Context(), bytes.NewReader(body), "fuzz")
		if err == nil {
			assertProviderInvariants(t, nets)
		}

		want, wantOK, exact := refProviderCIDRs(body)
		if !exact {
			return
		}

		if (err == nil) != wantOK {
			t.Fatalf("parseCIDRs error %v, reference valid %v", err, wantOK)
		}

		if !wantOK {
			return
		}

		if len(nets) != len(want) {
			t.Fatalf("parsed %v, want %v", nets, want)
		}

		for index, block := range nets {
			prefix, ok := prefixFromIPNet(block)
			if !ok || prefix != want[index] {
				t.Fatalf("entry %d: %v, want %v", index, block, want[index])
			}
		}

		assertSameMembership(t, nets, want)
	})
}

func assertProviderInvariants(t *testing.T, nets []*net.IPNet) {
	t.Helper()

	if len(nets) == 0 || len(nets) > maxRemoteProviderCIDRs {
		t.Fatalf("accepted %d CIDRs", len(nets))
	}

	seen := make(map[string]bool, len(nets))

	for _, block := range nets {
		ones, _ := block.Mask.Size()
		if ones == 0 || (block.Contains(net.IPv4zero) && block.Contains(net.IPv4bcast)) {
			t.Fatalf("accepted default route %v", block)
		}

		if seen[block.String()] {
			t.Fatalf("duplicate %v", block)
		}

		seen[block.String()] = true
	}
}

// refProviderCIDRs models the provider format. exact is false when a line is close to the
// scanner's buffer size, where only the invariants are checked.
func refProviderCIDRs(body []byte) ([]netip.Prefix, bool, bool) {
	prefixes := make([]netip.Prefix, 0)
	seen := make(map[netip.Prefix]bool)
	count := 0

	for line := range strings.SplitSeq(string(body), "\n") {
		if len(line) >= maxRemoteProviderLineBytes-providerLineSlack {
			return nil, false, false
		}

		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		count++

		prefix, ok := refParsePrefixLenient(line)
		if count > maxRemoteProviderCIDRs || !ok || prefix.Bits() == 0 {
			return nil, false, true
		}

		if !seen[prefix] {
			seen[prefix] = true
			prefixes = append(prefixes, prefix)
		}
	}

	return prefixes, len(prefixes) > 0, true
}

// FuzzSourceAddr checks RemoteAddr parsing: a zone is accepted only after an IPv6
// literal, and the parsed peer equals the reference.
func FuzzSourceAddr(f *testing.F) {
	for _, seed := range []string{
		"10.0.0.1:443", "[fe80::1%eth0]:80", "[fe80::1%]:80", "[1.2.3.4%eth0]:80",
		"[::ffff:10.0.0.1%25en0]:1", "[fe80::1%a%b]:80", "1.2.3.4", "[::1]:", ":80",
		"[2001:db8::1]:http", "010.0.0.1:1", "[::ffff:1.2.3.4]:5", "@:1", "[]:1",
	} {
		f.Add(seed)
	}

	resolver := newChainResolver(f, nil)

	f.Fuzz(func(t *testing.T, remote string) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
		req.RemoteAddr = remote

		ip, err := resolver.getSrcIP(t.Context(), req)

		want, wantOK := refRemoteAddr(remote)

		if (err == nil) != wantOK {
			t.Fatalf("getSrcIP(%q) error %v, reference valid %v", remote, err, wantOK)
		}

		if !wantOK {
			return
		}

		got, ok := netip.AddrFromSlice(ip)
		if !ok || got.Unmap() != want || ip.String() != want.String() {
			t.Fatalf("getSrcIP(%q) = %v, want %v", remote, ip, want)
		}
	})
}

// FuzzConfigCIDRs builds middleware configurations from arbitrary trusted ranges, modes
// and policies. New must succeed exactly for valid configurations, and the trust sets it
// builds must have the same membership as the reference prefixes, including for
// IPv4-mapped spellings of ranges and addresses.
func FuzzConfigCIDRs(f *testing.F) {
	for _, seed := range []string{
		"10.0.0.0/8", "192.0.2.1/24", "::ffff:192.0.2.0/120\n2001:db8::/32", "::ffff:0:0/96",
		"10.0.0.0/08", "10.0.0.0/8 ", "fe80::/10%eth0", "fe80::%eth0/10", "1.2.3.4", "::/0",
		"0.0.0.0/0", "10.0.0.0/-1", "10.0.0.0/+8", "::ffff:10.0.0.0/95", "::10.0.0.0/104",
	} {
		f.Add(seed, false, "", "")
		f.Add(seed, true, XForwardedForModeReplace, PanicPolicyPropagate)
	}

	f.Add("10.0.0.0/8", false, "Append", "legacy")

	f.Fuzz(func(t *testing.T, cidrs string, scoped bool, mode, policy string) {
		list := strings.Split(cidrs, "\n")
		if len(list) > fuzzMaxConfigCIDRs {
			list = list[:fuzzMaxConfigCIDRs]
		}

		cfg := CreateConfig()
		cfg.LogLevel = LogLevelError
		cfg.ThrustCloudFlare = false
		cfg.ThrustLocal = false
		cfg.ScopedTrust = scoped
		cfg.XForwardedForMode = mode
		cfg.PanicPolicy = policy
		cfg.TrustedIPs = list

		if scoped {
			cfg.TrustedIPs = nil
			cfg.ForwardedTrustedIPs = list
			cfg.CloudflareTrustedIPs = list
		}

		handler, err := New(t.Context(), http.NotFoundHandler(), cfg, "fuzz")

		prefixes, wantOK := refConfigPrefixes(list)
		wantOK = wantOK && isValidPanicPolicy(policy) &&
			(mode == "" || mode == XForwardedForModeAppend || mode == XForwardedForModeReplace)

		if (err == nil) != wantOK {
			t.Fatalf("New(%q, mode %q, policy %q) error %v, want valid %v", list, mode, policy,
				err, wantOK)
		}

		if err != nil {
			return
		}

		resolver, ok := handler.(*IPResolver)
		if !ok {
			t.Fatal("unexpected handler type")
		}

		assertSameMembership(t, resolver.trustedIPNets, prefixes)

		if scoped {
			assertSameMembership(t, resolver.scoped.cloudflare, prefixes)
		}
	})
}

func refConfigPrefixes(list []string) ([]netip.Prefix, bool) {
	prefixes := make([]netip.Prefix, 0, len(list))

	for _, text := range list {
		prefix, ok := refParsePrefixLenient(text)
		if !ok {
			return nil, false
		}

		prefixes = append(prefixes, prefix)
	}

	return prefixes, true
}
