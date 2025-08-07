package traefik_real_ip

import (
	"log/slog"
	"net"
	"net/http"
	"testing"
)

func TestIPResolver_getRealIP(t *testing.T) {
	level := &slog.LevelVar{}
	level.Set(slog.LevelDebug)
	ipResolver := &IPResolver{
		logger: NewPluginLogger("test", level),
	}

	trustedIPNets := make([]*net.IPNet, 0)
	trustedIPNets = append(trustedIPNets, ipResolver.getLocalIPs()...)
	trustedIPNets = append(trustedIPNets, ipResolver.getCloudFlareIPs()...)

	tests := []struct {
		name          string
		srcIP         string
		headers       map[string]string
		trustedCIDRs  []string
		expectedIP    string
		expectedError bool
	}{
		{
			name:         "CF-Connecting-IP from trusted source",
			srcIP:        "103.21.244.23",
			headers:      map[string]string{CfConnectingIP: "192.168.1.100"},
			trustedCIDRs: []string{"1.1.1.0/24"},
			expectedIP:   "192.168.1.100",
		},
		{
			name:         "CF-Connecting-IP from untrusted source",
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
			name:          "Invalid CF-Connecting-IP",
			srcIP:         "192.168.1.1",
			headers:       map[string]string{CfConnectingIP: "invalid-ip"},
			trustedCIDRs:  []string{"1.1.1.0/24"},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &IPResolver{
				logger:        NewPluginLogger("test", level),
				trustedIPNets: trustedIPNets,
			}

			req, _ := http.NewRequest("GET", "/", nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			srcIP := net.ParseIP(tt.srcIP)
			result, err := resolver.getRealIP(srcIP, req)

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
	level := &slog.LevelVar{}
	level.Set(slog.LevelDebug)
	resolver := &IPResolver{
		logger: NewPluginLogger("test", level),
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
			req, _ := http.NewRequest("GET", "/", nil)
			req.Header.Set(XForwardedFor, tt.headerValue)

			result, err := resolver.handleXForwardedFor(req)

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
	level := &slog.LevelVar{}
	level.Set(slog.LevelDebug)
	resolver := &IPResolver{
		logger: NewPluginLogger("test", level),
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
			req, _ := http.NewRequest("GET", "/", nil)
			req.Header.Set(XRealIP, tt.headerValue)

			result, err := resolver.handleXRealIP(req)

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
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Add(XRealIP, "203.0.113.10")
		req.Header.Add(XRealIP, "203.0.113.11")

		_, err := resolver.handleXRealIP(req)
		if err == nil {
			t.Errorf("Expected error for multiple X-Real-IP headers")
		}
	})
}

func TestIPResolver_handleCFIP(t *testing.T) {
	level := &slog.LevelVar{}
	level.Set(slog.LevelDebug)
	resolver := &IPResolver{
		logger: NewPluginLogger("test", level),
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
			req, _ := http.NewRequest("GET", "/", nil)
			req.Header.Set(CfConnectingIP, tt.headerValue)

			result, err := resolver.handleCFIP(req)

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

	// Test multiple CF-Connecting-IP headers (should fail)
	t.Run("Multiple CF-Connecting-IP headers", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Add(CfConnectingIP, "203.0.113.10")
		req.Header.Add(CfConnectingIP, "203.0.113.11")

		_, err := resolver.handleCFIP(req)
		if err == nil {
			t.Errorf("Expected error for multiple CF-Connecting-IP headers")
		}
	})
}

func TestIPResolver_getSrcIP(t *testing.T) {
	level := &slog.LevelVar{}
	level.Set(slog.LevelDebug)
	resolver := &IPResolver{
		logger: NewPluginLogger("test", level),
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
			req, _ := http.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr

			result, err := resolver.getSrcIP(req)

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
