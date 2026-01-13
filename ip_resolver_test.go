package traefik_real_ip

import (
	"net"
	"net/http"
	"testing"
)

func TestIPResolver_getRealIP(t *testing.T) {
	ipResolver := &IPResolver{
		logger: NewPluginLogger(t.Context(), "test", LogLevelDebug),
	}

	trustedIPNets := make([]*net.IPNet, 0, len(ipResolver.trustedIPNets))
	trustedIPNets = append(trustedIPNets, ipResolver.getLocalIPs(t.Context())...)
	trustedIPNets = append(trustedIPNets, ipResolver.getCloudFlareIPs(t.Context())...)

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
			expectedIP:   "192.168.1.100",
		},
		{
			name:         "Cf-Connecting-Ip from untrusted source",
			srcIP:        "2.2.2.2",
			headers:      map[string]string{CfConnectingIP: "192.168.1.100"},
			trustedCIDRs: []string{"1.1.1.0/24"},
			expectedIP:   "2.2.2.2",
		},
		{
			name:         "X-Real-IP from trusted source",
			srcIP:        "103.21.244.23",
			headers:      map[string]string{XRealIP: "203.0.113.10"},
			trustedCIDRs: []string{"1.1.1.0/24"},
			expectedIP:   "203.0.113.10",
		},
		{
			name:         "X-Forwarded-For from trusted source",
			srcIP:        "192.168.1.1",
			headers:      map[string]string{XForwardedFor: "203.0.113.10, 192.168.1.1"},
			trustedCIDRs: []string{"1.1.1.0/24"},
			expectedIP:   "203.0.113.10",
		},
		{
			name:         "No headers, return source IP",
			srcIP:        "203.0.113.50",
			headers:      map[string]string{},
			trustedCIDRs: []string{},
			expectedIP:   "203.0.113.50",
		},
		{
			name:          "Invalid Cf-Connecting-Ip",
			srcIP:         "192.168.1.1",
			headers:       map[string]string{CfConnectingIP: "invalid-ip"},
			trustedCIDRs:  []string{"1.1.1.0/24"},
			expectedError: true,
		},
		{
			name:       "Eo-Connecting-Ip from trusted source",
			srcIP:      "10.0.0.1",
			headers:    map[string]string{EoConnectingIP: "198.51.100.10"},
			expectedIP: "198.51.100.10",
		},
		{
			name:         "Eo-Connecting-Ip from untrusted source",
			srcIP:        "2.2.2.2",
			headers:      map[string]string{EoConnectingIP: "198.51.100.10"},
			trustedCIDRs: []string{"1.1.1.0/24"},
			expectedIP:   "2.2.2.2",
		},
		{
			name:          "Invalid Eo-Connecting-Ip",
			srcIP:         "10.0.0.1",
			headers:       map[string]string{EoConnectingIP: "invalid-ip"},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &IPResolver{
				logger:        NewPluginLogger(t.Context(), "test", LogLevelDebug),
				trustedIPNets: trustedIPNets,
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
	resolver := &IPResolver{
		logger: NewPluginLogger(t.Context(), "test", LogLevelDebug),
	}

	tests := []struct {
		name          string
		headerValue   string
		expectedIP    string
		expectedError bool
	}{
		{
			name:        "Single public IP",
			headerValue: "203.0.113.10",
			expectedIP:  "203.0.113.10",
		},
		{
			name:        "Multiple IPs, first public",
			headerValue: "203.0.113.10, 192.168.1.1",
			expectedIP:  "203.0.113.10",
		},
		{
			name:        "Multiple IPs, second public",
			headerValue: "192.168.1.1, 203.0.113.10",
			expectedIP:  "203.0.113.10",
		},
		{
			name:          "Only private IPs",
			headerValue:   "192.168.1.1, 10.0.0.1",
			expectedError: true,
		},
		{
			name:          "Invalid IP format",
			headerValue:   "invalid-ip",
			expectedError: true,
		},
		{
			name:        "IPs with spaces",
			headerValue: " 203.0.113.10 , 192.168.1.1 ",
			expectedIP:  "203.0.113.10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			req.Header.Set(XForwardedFor, tt.headerValue)

			result, err := resolver.handleXForwardedFor(t.Context(), req)

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

func TestIPResolver_handleXRealIP(t *testing.T) {
	resolver := &IPResolver{
		logger: NewPluginLogger(t.Context(), "test", LogLevelDebug),
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
			expectedIP:  "203.0.113.10",
		},
		{
			name:          "Invalid IP format",
			headerValue:   "invalid-ip",
			expectedError: true,
		},
		{
			name:        "IPv6 address",
			headerValue: "2001:db8::1",
			expectedIP:  "2001:db8::1",
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
		logger: NewPluginLogger(t.Context(), "test", LogLevelDebug),
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
			expectedIP:  "203.0.113.10",
		},
		{
			name:          "Invalid IP format",
			headerValue:   "invalid-ip",
			expectedError: true,
		},
		{
			name:        "IPv6 address",
			headerValue: "2001:db8::1",
			expectedIP:  "2001:db8::1",
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
		logger: NewPluginLogger(t.Context(), "test", LogLevelDebug),
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
			expectedIP:  "198.51.100.10",
		},
		{
			name:          "Invalid IP format",
			headerValue:   "invalid-ip",
			expectedError: true,
		},
		{
			name:        "IPv6 address",
			headerValue: "2001:db8::2",
			expectedIP:  "2001:db8::2",
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
		logger: NewPluginLogger(t.Context(), "test", LogLevelDebug),
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
			expectedIP: "203.0.113.10",
		},
		{
			name:       "Valid IPv6 with port",
			remoteAddr: "[2001:db8::1]:12345",
			expectedIP: "2001:db8::1",
		},
		{
			name:          "Invalid format - no port",
			remoteAddr:    "203.0.113.10",
			expectedError: true,
		},
		{
			name:          "Invalid IP format",
			remoteAddr:    "invalid-ip:12345",
			expectedError: true,
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
