//nolint:staticcheck,mnd // no reason
package traefik_real_ip

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestResolver(t *testing.T) *IPResolver {
	t.Helper()

	level := &slog.LevelVar{}
	level.Set(slog.LevelDebug)

	return &IPResolver{logger: NewPluginLogger("test", level)}
}

func runRemoteProviderResponseTests(
	t *testing.T,
	fetch func(context.Context, string) ([]*net.IPNet, error),
) {
	t.Helper()

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
			statusCode:     http.StatusOK,
			expectedIPsLen: 3,
			expectError:    false,
		},
		{
			name: "successful IPv6 response",
			responseBody: `2400:cb00::/32
2606:4700::/32
2803:f800::/32`,
			statusCode:     http.StatusOK,
			expectedIPsLen: 3,
			expectError:    false,
		},
		{
			name:           "empty response",
			responseBody:   "",
			statusCode:     http.StatusOK,
			expectedIPsLen: 0,
			expectError:    false,
		},
		{
			name: "response with empty lines",
			responseBody: `173.245.48.0/20

103.21.244.0/22
`,
			statusCode:     http.StatusOK,
			expectedIPsLen: 2,
			expectError:    false,
		},
		{
			name:           "HTTP error response",
			responseBody:   "Not Found",
			statusCode:     http.StatusNotFound,
			expectedIPsLen: 0,
			expectError:    true,
		},
		{
			name: "invalid CIDR format",
			responseBody: `173.245.48.0/20
invalid-cidr
103.21.244.0/22`,
			statusCode:  http.StatusOK,
			expectError: true,
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tc.statusCode)

					_, err := w.Write([]byte(tc.responseBody))
					if err != nil {
						t.Fatalf("Failed to write response: %v", err)
					}
				}),
			)
			defer server.Close()

			ips, err := fetch(t.Context(), server.URL)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}

				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)

				return
			}

			if len(ips) != tc.expectedIPsLen {
				t.Errorf("Expected %d IPs, got %d", tc.expectedIPsLen, len(ips))
			}

			for i, ipNet := range ips {
				if ipNet == nil {
					t.Errorf("IP at index %d is nil", i)
				}
			}
		})
	}
}

func runCIDRParsingTests(
	t *testing.T,
	fetch func(context.Context, string) ([]*net.IPNet, error),
) {
	t.Helper()

	validCIDRs := []string{
		"173.245.48.0/20",
		"103.21.244.0/22",
		"2400:cb00::/32",
		"192.168.1.0/24",
		"10.0.0.0/8",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		var response strings.Builder
		for _, cidr := range validCIDRs {
			response.WriteString(cidr + "\n")
		}

		_, err := w.Write([]byte(response.String()))
		if err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	ips, err := fetch(t.Context(), server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(ips) != len(validCIDRs) {
		t.Errorf("Expected %d parsed IPs, got %d", len(validCIDRs), len(ips))
	}

	for i, ipNet := range ips {
		if ipNet == nil {
			t.Errorf("IP network at index %d is nil", i)

			continue
		}

		if ipNet.IP.String() == "" {
			t.Errorf("Empty network address for IP at index %d", i)
		}
	}
}

func runHTTPErrorTests(
	t *testing.T,
	fetch func(context.Context, string) ([]*net.IPNet, error),
) {
	t.Helper()

	errorTests := []struct {
		name       string
		statusCode int
	}{
		{"404 Not Found", http.StatusNotFound},
		{"500 Internal Server Error", http.StatusInternalServerError},
		{"403 Forbidden", http.StatusForbidden},
	}

	for _, tt := range errorTests {
		errCase := tt
		t.Run(errCase.name, func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(errCase.statusCode)

					_, err := w.Write([]byte("Error response"))
					if err != nil {
						t.Fatalf("Failed to write response: %v", err)
					}
				}),
			)
			defer server.Close()

			_, err := fetch(t.Context(), server.URL)
			if err == nil {
				t.Errorf("Expected error for status code %d but got none", errCase.statusCode)
			}
		})
	}
}
