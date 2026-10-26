package traefik_real_ip

import (
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestIPResolver_getRealIP(t *testing.T) {
	ipResolver := &IPResolver{
		logger: NewPluginLogger(
			t.Context(),
			"test",
			LogLevelDebug,
		),
		next:          nil,
		conf:          nil,
		name:          "",
		trustedIPNets: nil,
	}

	trustedIPNets := make([]*net.IPNet, 0, len(ipResolver.trustedIPNets))
	trustedIPNets = append(trustedIPNets, ipResolver.getLocalIPs(t.Context())...)

	body, err := os.ReadFile("remote_ips/cloudflare_v4")
	if err != nil {
		t.Fatal(err)
	}

	ips, err := ipResolver.parseCIDRs(t.Context(), strings.NewReader(string(body)), "fixture")
	if err != nil {
		t.Fatal(err)
	}

	trustedIPNets = append(trustedIPNets, ips...)

	tests := []struct {
		headers       map[string]string
		name          string
		srcIP         string
		expectedIP    string
		trustedCIDRs  []string
		expectedError bool
	}{
		{
			name:         "Cf-Connecting-Ip from trusted source",
			srcIP:        "103.21.244.23",
			headers:      map[string]string{CfConnectingIP: "192.168.1.100"},
			trustedCIDRs: []string{"1.1.1.0/24"},
			expectedIP:   "192.168.1.100", expectedError: false,
		},
		{
			name:         "Cf-Connecting-Ip from untrusted source",
			srcIP:        "2.2.2.2",
			headers:      map[string]string{CfConnectingIP: "192.168.1.100"},
			trustedCIDRs: []string{"1.1.1.0/24"},
			expectedIP:   "2.2.2.2", expectedError: false,
		},
		{
			name:         "X-Real-IP from trusted source",
			srcIP:        "103.21.244.23",
			headers:      map[string]string{XRealIP: "203.0.113.10"},
			trustedCIDRs: []string{"1.1.1.0/24"},
			expectedIP:   "203.0.113.10", expectedError: false,
		},
		{
			name:         "X-Forwarded-For from trusted source",
			srcIP:        "192.168.1.1",
			headers:      map[string]string{XForwardedFor: "203.0.113.10, 192.168.1.1"},
			trustedCIDRs: []string{"1.1.1.0/24"},
			expectedIP:   "203.0.113.10", expectedError: false,
		},
		{
			name:         "No headers, return source IP",
			srcIP:        "203.0.113.50",
			headers:      map[string]string{},
			trustedCIDRs: []string{},
			expectedIP:   "203.0.113.50", expectedError: false,
		},
		{
			name:          "Invalid Cf-Connecting-Ip",
			srcIP:         "192.168.1.1",
			headers:       map[string]string{CfConnectingIP: "invalid-ip"},
			trustedCIDRs:  []string{"1.1.1.0/24"},
			expectedError: true, expectedIP: "",
		},
		{
			name:       "Eo-Connecting-Ip from trusted source",
			srcIP:      "10.0.0.1",
			headers:    map[string]string{EoConnectingIP: "198.51.100.10"},
			expectedIP: "198.51.100.10", trustedCIDRs: nil, expectedError: false,
		},
		{
			name:         "Eo-Connecting-Ip from untrusted source",
			srcIP:        "2.2.2.2",
			headers:      map[string]string{EoConnectingIP: "198.51.100.10"},
			trustedCIDRs: []string{"1.1.1.0/24"},
			expectedIP:   "2.2.2.2", expectedError: false,
		},
		{
			name:          "Invalid Eo-Connecting-Ip",
			srcIP:         "10.0.0.1",
			headers:       map[string]string{EoConnectingIP: "invalid-ip"},
			expectedError: true, expectedIP: "", trustedCIDRs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &IPResolver{
				logger:        NewPluginLogger(t.Context(), "test", LogLevelDebug),
				trustedIPNets: trustedIPNets, next: nil, conf: nil, name: "",
			}

			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			srcIP := net.ParseIP(tt.srcIP)
			result, err := resolver.getRealIP(t.Context(), srcIP, req)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}

				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)

				return
			}

			if result.String() != tt.expectedIP {
				t.Errorf("Expected IP %s, got %s", tt.expectedIP, result.String())
			}
		})
	}
}

func TestIPResolver_handleXForwardedFor(t *testing.T) {
	resolver := newTestResolver(t)

	for _, cidr := range []string{"192.0.2.0/24", "2001:db8:ffff::/48"} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}

		resolver.trustedIPNets = append(resolver.trustedIPNets, block)
	}

	tests := []struct {
		wantErr error
		name    string
		peer    string
		header  string
		want    string
	}{
		{
			name:    "single client",
			peer:    "192.0.2.1",
			header:  "203.0.113.10",
			want:    "203.0.113.10",
			wantErr: nil,
		},
		{
			name:   "attacker prefix",
			peer:   "192.0.2.1",
			header: "198.51.100.66, 203.0.113.10, 192.0.2.2",
			want:   "203.0.113.10", wantErr: nil,
		},
		{
			name:   "multiple trusted proxies",
			peer:   "192.0.2.1",
			header: "198.51.100.66, 203.0.113.10, 192.0.2.2, 192.0.2.3",
			want:   "203.0.113.10", wantErr: nil,
		},
		{
			name:   "no trusted header suffix",
			peer:   "192.0.2.1",
			header: "198.51.100.66, 203.0.113.10",
			want:   "203.0.113.10", wantErr: nil,
		},
		{
			name:   "private untrusted boundary",
			peer:   "192.0.2.1",
			header: "198.51.100.66, 10.0.0.1, 192.0.2.2",
			want:   "10.0.0.1", wantErr: nil,
		},
		{
			name:   "stop before trusted prefix",
			peer:   "192.0.2.1",
			header: "192.0.2.4, 203.0.113.10",
			want:   "203.0.113.10", wantErr: nil,
		},
		{
			name:   "untrusted peer",
			peer:   "203.0.113.20",
			header: "198.51.100.66, 192.0.2.2",
			want:   "203.0.113.20", wantErr: nil,
		},
		{
			name:   "IPv6 suffix",
			peer:   "2001:db8:ffff::1",
			header: "198.51.100.66, 2001:db8::10, 2001:db8:ffff::2",
			want:   "2001:db8::10", wantErr: nil,
		},
		{
			name:   "IPv4 mapped proxy",
			peer:   "::ffff:192.0.2.1",
			header: "198.51.100.66, 203.0.113.10, ::ffff:192.0.2.2",
			want:   "203.0.113.10", wantErr: nil,
		},
		{
			name:   "spaces",
			peer:   "192.0.2.1",
			header: " 203.0.113.10 , 192.0.2.2 ",
			want:   "203.0.113.10", wantErr: nil,
		},
		{
			name:    "malformed prefix",
			peer:    "192.0.2.1",
			header:  "invalid, 203.0.113.10, 192.0.2.2",
			wantErr: ErrXForwardedForInvalid, want: "",
		},
		{
			name:    "malformed suffix",
			peer:    "192.0.2.1",
			header:  "203.0.113.10, invalid",
			wantErr: ErrXForwardedForInvalid, want: "",
		},
		{
			name:    "empty hop",
			peer:    "192.0.2.1",
			header:  "203.0.113.10, , 192.0.2.2",
			wantErr: ErrXForwardedForInvalid, want: "",
		},
		{
			name:    "empty header",
			peer:    "192.0.2.1",
			header:  "",
			wantErr: ErrXForwardedForInvalid,
			want:    "",
		},
		{
			name:    "address with port",
			peer:    "192.0.2.1",
			header:  "203.0.113.10:80",
			wantErr: ErrXForwardedForInvalid, want: "",
		},
		{
			name:    "all trusted",
			peer:    "192.0.2.1",
			header:  "192.0.2.2, 192.0.2.3",
			wantErr: nil, want: "192.0.2.2",
		},
		{
			name:   "hop limit",
			peer:   "192.0.2.1",
			header: "203.0.113.10" + strings.Repeat(", 192.0.2.2", maxForwardedForHops-1),
			want:   "203.0.113.10", wantErr: nil,
		},
		{
			name:    "too many hops",
			peer:    "192.0.2.1",
			header:  "203.0.113.10" + strings.Repeat(", 192.0.2.2", maxForwardedForHops),
			wantErr: ErrXForwardedForInvalid, want: "",
		},
		{
			name:   "byte limit",
			peer:   "192.0.2.1",
			header: "203.0.113.10" + strings.Repeat(" ", maxForwardedForBytes-len("203.0.113.10")),
			want:   "203.0.113.10", wantErr: nil,
		},
		{
			name:    "too many bytes",
			peer:    "192.0.2.1",
			header:  strings.Repeat(" ", maxForwardedForBytes+1),
			wantErr: ErrXForwardedForInvalid, want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set(XForwardedFor, tt.header)

			ip, err := resolver.handleXForwardedFor(t.Context(), net.ParseIP(tt.peer), req)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}

			if tt.wantErr == nil && ip.String() != tt.want {
				t.Fatalf("expected IP %s, got %s", tt.want, ip)
			}
		})
	}

	t.Run("multiple header fields", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
		req.Header.Add(XForwardedFor, "203.0.113.10")
		req.Header.Add(XForwardedFor, "192.0.2.2")

		_, err := resolver.handleXForwardedFor(t.Context(), net.ParseIP("192.0.2.1"), req)
		if !errors.Is(err, ErrXForwardedForInvalid) {
			t.Fatalf("expected ambiguous header rejection, got %v", err)
		}
	})
}

func TestIPResolver_handleXRealIP(t *testing.T) {
	resolver := &IPResolver{
		logger: NewPluginLogger(
			t.Context(),
			"test",
			LogLevelDebug,
		),
		next:          nil,
		conf:          nil,
		name:          "",
		trustedIPNets: nil,
	}

	tests := []struct {
		name          string
		headerValue   string
		expectedIP    string
		expectedError bool
	}{
		{
			name:        "Valid IP",
			headerValue: "203.0.113.10",
			expectedIP:  "203.0.113.10", expectedError: false,
		},
		{
			name:          "Invalid IP format",
			headerValue:   "invalid-ip",
			expectedError: true, expectedIP: "",
		},
		{
			name:        "IPv6 address",
			headerValue: "2001:db8::1",
			expectedIP:  "2001:db8::1", expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			req.Header.Set(XRealIP, tt.headerValue)

			result, err := resolver.handleXRealIP(t.Context(), req)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}

				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)

				return
			}

			if result.String() != tt.expectedIP {
				t.Errorf("Expected IP %s, got %s", tt.expectedIP, result.String())
			}
		})
	}

	// Test multiple X-Real-IP headers (should fail)
	t.Run("Multiple X-Real-IP headers", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
		req.Header.Add(XRealIP, "203.0.113.10")
		req.Header.Add(XRealIP, "203.0.113.11")

		_, err := resolver.handleXRealIP(t.Context(), req)
		if err == nil {
			t.Errorf("Expected error for multiple X-Real-IP headers")
		}
	})
}

func TestIPResolver_handleCFIP(t *testing.T) {
	resolver := &IPResolver{
		logger: NewPluginLogger(
			t.Context(),
			"test",
			LogLevelDebug,
		),
		next:          nil,
		conf:          nil,
		name:          "",
		trustedIPNets: nil,
	}

	tests := []struct {
		name          string
		headerValue   string
		expectedIP    string
		expectedError bool
	}{
		{
			name:        "Valid IP",
			headerValue: "203.0.113.10",
			expectedIP:  "203.0.113.10", expectedError: false,
		},
		{
			name:          "Invalid IP format",
			headerValue:   "invalid-ip",
			expectedError: true, expectedIP: "",
		},
		{
			name:        "IPv6 address",
			headerValue: "2001:db8::1",
			expectedIP:  "2001:db8::1", expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			req.Header.Set(CfConnectingIP, tt.headerValue)

			result, err := resolver.handleCFIP(t.Context(), req)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}

				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)

				return
			}

			if result.String() != tt.expectedIP {
				t.Errorf("Expected IP %s, got %s", tt.expectedIP, result.String())
			}
		})
	}

	// Test multiple Cf-Connecting-Ip headers (should fail)
	t.Run("Multiple Cf-Connecting-Ip headers", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
		req.Header.Add(CfConnectingIP, "203.0.113.10")
		req.Header.Add(CfConnectingIP, "203.0.113.11")

		_, err := resolver.handleCFIP(t.Context(), req)
		if err == nil {
			t.Errorf("Expected error for multiple Cf-Connecting-Ip headers")
		}
	})
}

func TestIPResolver_handleEOIP(t *testing.T) {
	resolver := &IPResolver{
		logger: NewPluginLogger(
			t.Context(),
			"test",
			LogLevelDebug,
		),
		next:          nil,
		conf:          nil,
		name:          "",
		trustedIPNets: nil,
	}

	tests := []struct {
		name          string
		headerValue   string
		expectedIP    string
		expectedError bool
	}{
		{
			name:        "Valid IP",
			headerValue: "198.51.100.10",
			expectedIP:  "198.51.100.10", expectedError: false,
		},
		{
			name:          "Invalid IP format",
			headerValue:   "invalid-ip",
			expectedError: true, expectedIP: "",
		},
		{
			name:        "IPv6 address",
			headerValue: "2001:db8::2",
			expectedIP:  "2001:db8::2", expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			req.Header.Set(EoConnectingIP, tt.headerValue)

			result, err := resolver.handleEOIP(t.Context(), req)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}

				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)

				return
			}

			if result.String() != tt.expectedIP {
				t.Errorf("Expected IP %s, got %s", tt.expectedIP, result.String())
			}
		})
	}

	// Test multiple Eo-Connecting-Ip headers (should fail)
	t.Run("Multiple Eo-Connecting-Ip headers", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
		req.Header.Add(EoConnectingIP, "198.51.100.10")
		req.Header.Add(EoConnectingIP, "198.51.100.11")

		_, err := resolver.handleEOIP(t.Context(), req)
		if err == nil {
			t.Errorf("Expected error for multiple Eo-Connecting-Ip headers")
		}
	})
}

func TestIPResolver_getSrcIP(t *testing.T) {
	resolver := &IPResolver{
		logger: NewPluginLogger(
			t.Context(),
			"test",
			LogLevelDebug,
		),
		next:          nil,
		conf:          nil,
		name:          "",
		trustedIPNets: nil,
	}

	tests := []struct {
		name          string
		remoteAddr    string
		expectedIP    string
		expectedError bool
	}{
		{
			name:       "Valid IPv4 with port",
			remoteAddr: "203.0.113.10:12345",
			expectedIP: "203.0.113.10", expectedError: false,
		},
		{
			name:       "Valid IPv6 with port",
			remoteAddr: "[2001:db8::1]:12345",
			expectedIP: "2001:db8::1", expectedError: false,
		},
		{
			name:          "Invalid format - no port",
			remoteAddr:    "203.0.113.10",
			expectedError: true, expectedIP: "",
		},
		{
			name:          "Invalid IP format",
			remoteAddr:    "invalid-ip:12345",
			expectedError: true, expectedIP: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			req.RemoteAddr = tt.remoteAddr

			result, err := resolver.getSrcIP(t.Context(), req)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}

				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)

				return
			}

			if result.String() != tt.expectedIP {
				t.Errorf("Expected IP %s, got %s", tt.expectedIP, result.String())
			}
		})
	}
}
