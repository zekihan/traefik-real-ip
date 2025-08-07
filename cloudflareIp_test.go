//nolint:staticcheck // no reason
package traefik_real_ip

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestIPResolver_getCloudFlareIPFromURL(t *testing.T) {
	level := &slog.LevelVar{}
	level.Set(slog.LevelDebug)
	logger := NewPluginLogger("test", level)
	resolver := &IPResolver{logger: logger}

	tests := []struct {
		name           string
		responseBody   string
		statusCode     int
		expectedIPsLen int
		expectError    bool
	}{
		{
			name: "successful IPv4 response",
			responseBody: `173.245.48.0/20
103.21.244.0/22
103.22.200.0/22`,
			statusCode:     200,
			expectedIPsLen: 3,
			expectError:    false,
		},
		{
			name: "successful IPv6 response",
			responseBody: `2400:cb00::/32
2606:4700::/32
2803:f800::/32`,
			statusCode:     200,
			expectedIPsLen: 3,
			expectError:    false,
		},
		{
			name:           "empty response",
			responseBody:   "",
			statusCode:     200,
			expectedIPsLen: 0,
			expectError:    false,
		},
		{
			name: "response with empty lines",
			responseBody: `173.245.48.0/20

103.21.244.0/22
`,
			statusCode:     200,
			expectedIPsLen: 2,
			expectError:    false,
		},
		{
			name:           "HTTP error response",
			responseBody:   "Not Found",
			statusCode:     404,
			expectedIPsLen: 0,
			expectError:    true,
		},
		{
			name: "invalid CIDR format",
			responseBody: `173.245.48.0/20
invalid-cidr
103.21.244.0/22`,
			statusCode:  200,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tt.statusCode)

					_, err := w.Write([]byte(tt.responseBody))
					if err != nil {
						t.Fatalf("Failed to write response: %v", err)
					}
				}),
			)
			defer server.Close()

			// Test the function
			ips, err := resolver.getCloudFlareIPFromURL(t.Context(), server.URL)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}

				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)

				return
			}

			if len(ips) != tt.expectedIPsLen {
				t.Errorf("Expected %d IPs, got %d", tt.expectedIPsLen, len(ips))
			}

			// Validate that all returned IPs are valid IPNet
			for i, ipNet := range ips {
				if ipNet == nil {
					t.Errorf("IP at index %d is nil", i)
				}
			}
		})
	}
}

func TestIPResolver_getCloudFlareIPs(t *testing.T) {
	// Reset the singleton for testing
	cloudFlareIPsOnce = sync.Once{}
	cloudFlareIPsInstance = nil

	level := &slog.LevelVar{}
	level.Set(slog.LevelDebug)
	logger := NewPluginLogger("test", level)
	resolver := &IPResolver{logger: logger}

	// Create mock servers for IPv4 and IPv6
	ipv4Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		_, err := w.Write([]byte("173.245.48.0/20\n103.21.244.0/22"))
		if err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer ipv4Server.Close()

	ipv6Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		_, err := w.Write([]byte("2400:cb00::/32\n2606:4700::/32"))
		if err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer ipv6Server.Close()

	// This test would require modifying the actual URLs or dependency injection
	// For now, we'll test the singleton behavior with a mock
	t.Run("singleton behavior", func(t *testing.T) {
		// Reset singleton
		cloudFlareIPsOnce = sync.Once{}
		cloudFlareIPsInstance = []*net.IPNet{
			mustParseCIDR("192.168.1.0/24"),
			mustParseCIDR("10.0.0.0/8"),
		}

		// First call
		ips1 := resolver.getCloudFlareIPs(t.Context())
		// Second call should return the same instance
		ips2 := resolver.getCloudFlareIPs(t.Context())

		if len(ips1) != len(ips2) {
			t.Errorf("Singleton behavior failed: different lengths %d vs %d", len(ips1), len(ips2))
		}

		// Check that it's the same slice (same memory address)
		if &ips1[0] != &ips2[0] {
			t.Errorf("Singleton behavior failed: different instances returned")
		}
	})
}

func TestCIDRParsing(t *testing.T) {
	level := &slog.LevelVar{}
	level.Set(slog.LevelDebug)
	logger := NewPluginLogger("test", level)
	resolver := &IPResolver{logger: logger}

	validCIDRs := []string{
		"173.245.48.0/20",
		"103.21.244.0/22",
		"2400:cb00::/32",
		"192.168.1.0/24",
		"10.0.0.0/8",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		response := ""
		for _, cidr := range validCIDRs {
			response += cidr + "\n"
		}

		_, err := w.Write([]byte(response))
		if err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	ips, err := resolver.getCloudFlareIPFromURL(t.Context(), server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(ips) != len(validCIDRs) {
		t.Errorf("Expected %d parsed IPs, got %d", len(validCIDRs), len(ips))
	}

	// Verify that each IP network is correctly parsed
	for i, ipNet := range ips {
		if ipNet == nil {
			t.Errorf("IP network at index %d is nil", i)

			continue
		}

		// Test that we can get the network address
		networkAddr := ipNet.IP.String()
		if networkAddr == "" {
			t.Errorf("Empty network address for IP at index %d", i)
		}
	}
}

func TestHTTPErrorHandling(t *testing.T) {
	level := &slog.LevelVar{}
	level.Set(slog.LevelDebug)
	logger := NewPluginLogger("test", level)
	resolver := &IPResolver{logger: logger}

	errorTests := []struct {
		name       string
		statusCode int
	}{
		{"404 Not Found", 404},
		{"500 Internal Server Error", 500},
		{"403 Forbidden", 403},
	}

	for _, tt := range errorTests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tt.statusCode)

					_, err := w.Write([]byte("Error response"))
					if err != nil {
						t.Fatalf("Failed to write response: %v", err)
					}
				}),
			)
			defer server.Close()

			_, err := resolver.getCloudFlareIPFromURL(t.Context(), server.URL)
			if err == nil {
				t.Errorf("Expected error for status code %d but got none", tt.statusCode)
			}
		})
	}
}

// Helper function for testing
func mustParseCIDR(cidr string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}

	return ipNet
}
