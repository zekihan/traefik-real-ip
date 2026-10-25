package traefik_real_ip

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func newTestResolver(t *testing.T) *IPResolver {
	t.Helper()

	return &IPResolver{
		logger:        NewPluginLogger(t.Context(), "test", LogLevelDebug),
		next:          nil,
		conf:          nil,
		name:          "",
		trustedIPNets: nil,
	}
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
			expectError:    true,
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
			name: "response with comments",
			responseBody: `# [DEPRECATION NOTICE] This interface stopped serving on 2026-07-31.
173.245.48.0/20
# Please migrate in time.
103.21.244.0/22`,
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
			expectError: true, expectedIPsLen: 0,
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

func TestBuildRequest_InvalidURL(t *testing.T) {
	resolver := newTestResolver(t)

	_, err := resolver.buildRequest(t.Context(), "test", "http://\x00invalid")
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

var errSimulatedRead = errors.New("simulated read error")

type errReader struct{}

func (errReader) Read(_ []byte) (int, error) {
	return 0, errSimulatedRead
}

func (errReader) Close() error {
	return nil
}

func TestReadResponseCIDRs_ReadError(t *testing.T) {
	resolver := newTestResolver(t)
	resp := &http.Response{
		Body:             io.NopCloser(errReader{}),
		Status:           "",
		StatusCode:       0,
		Proto:            "",
		ProtoMajor:       0,
		ProtoMinor:       0,
		Header:           nil,
		ContentLength:    0,
		TransferEncoding: nil,
		Close:            false,
		Uncompressed:     false,
		Trailer:          nil,
		Request:          nil,
		TLS:              nil,
	}

	_, err := resolver.readResponseCIDRs(t.Context(), resp, "test", "http://example.com")
	if err == nil {
		t.Fatal("expected error from bad body reader, got nil")
	}
}

func TestDoRequestWithRetry_ContextCancelled(t *testing.T) {
	// Server returns 500 to force a retry; the pre-canceled context fires on the delay.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	resolver := newTestResolver(t)

	// Build the request with a live context so client.Do can connect on attempt 0.
	req, err := resolver.buildRequest(t.Context(), "test", server.URL)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // pre-cancel so the retry delay fires immediately

	resp, err := resolver.doRequestWithRetry(ctx, req, "test", server.URL)
	if resp != nil {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			t.Logf("close body: %v", closeErr)
		}
	}

	if err == nil {
		t.Fatal("expected error from canceled context, got nil")
	}
}

func TestGetProviderIPs_FailedLoadsRemainRetryable(t *testing.T) {
	for _, firstBody := range []string{
		"", "# only comments\n", "invalid-cidr\n", "0.0.0.0/0\n",
		strings.Repeat("x", maxRemoteProviderLineBytes),
	} {
		t.Run(firstBody[:min(len(firstBody), 20)], func(t *testing.T) {
			var ready atomic.Bool

			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body := firstBody
					if ready.Load() {
						body = "198.51.100.0/24\n"
					}

					_, _ = io.WriteString(w, body)
				}),
			)
			defer server.Close()

			provider := remoteIPProvider{
				name:  "test",
				urls:  []string{server.URL},
				cache: new(remoteIPCache),
			}
			resolver := newTestResolver(t)

			ips, err := resolver.getProviderIPs(t.Context(), provider)
			if err == nil || len(ips) != 0 || len(provider.cache.ips) != 0 {
				t.Fatalf("invalid response published: %v, %v", ips, err)
			}

			ready.Store(true)

			ips, err = resolver.getProviderIPs(t.Context(), provider)
			if err != nil || len(ips) != 1 {
				t.Fatalf("retry did not recover: %v, %v", ips, err)
			}
		})
	}
}

func TestGetProviderIPs_ConcurrentPublication(t *testing.T) {
	var requests atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		// Canonical duplicates appear within and across URLs.
		_, _ = io.WriteString(w, "198.51.100.0/24\n198.51.100.1/24\n")
	}))
	defer server.Close()

	provider := remoteIPProvider{
		name:  "test",
		urls:  []string{server.URL, server.URL},
		cache: new(remoteIPCache),
	}
	resolver := newTestResolver(t)

	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			ips, err := resolver.getProviderIPs(t.Context(), provider)
			if err != nil || len(ips) != 1 || ips[0].String() != "198.51.100.0/24" {
				t.Errorf("unexpected snapshot: %v, %v", ips, err)
			}
		})
	}

	group.Wait()

	if got := requests.Load(); got != 2 {
		t.Fatalf("expected one complete load (two URLs), got %d requests", got)
	}
}

func TestGetProviderIPs_CanceledLoadRecovers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "198.51.100.0/24\n")
	}))
	defer server.Close()

	provider := remoteIPProvider{
		name:  "test",
		urls:  []string{server.URL},
		cache: new(remoteIPCache),
	}
	resolver := newTestResolver(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	ips, err := resolver.getProviderIPs(ctx, provider)
	if !errors.Is(err, context.Canceled) || len(ips) != 0 {
		t.Fatalf("expected cancellation, got %v, %v", ips, err)
	}

	ips, err = resolver.getProviderIPs(t.Context(), provider)
	if err != nil || len(ips) != 1 {
		t.Fatalf("retry did not recover: %v, %v", ips, err)
	}
}

type countingReader struct {
	reader io.Reader
	read   int
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	reader.read += count

	if errors.Is(err, io.EOF) {
		return count, io.EOF
	}

	if err != nil {
		return count, fmt.Errorf("counting response bytes: %w", err)
	}

	return count, nil
}

func TestReadResponseCIDRs_ByteLimits(t *testing.T) {
	valid := "198.51.100.0/24\n"

	atLimit := valid + strings.Repeat("\n", maxRemoteProviderBytes-len(valid))
	for _, test := range []struct {
		name      string
		body      string
		length    int64
		wantError bool
		wantRead  int
	}{
		{"declared oversized", valid, maxRemoteProviderBytes + 1, true, 0},
		{"streamed oversized", atLimit + "\n", -1, true, maxRemoteProviderBytes + 1},
		{"underreported length", atLimit + "\n", 1, true, maxRemoteProviderBytes + 1},
		{"exact byte limit", atLimit, -1, false, maxRemoteProviderBytes},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &countingReader{reader: strings.NewReader(test.body), read: 0}
			response := new(http.Response)
			response.Body = io.NopCloser(reader)
			response.ContentLength = test.length

			ips, err := newTestResolver(
				t,
			).readResponseCIDRs(t.Context(), response, "test", "fixture")
			if (err != nil) != test.wantError {
				t.Fatalf("unexpected error: %v", err)
			}

			if test.wantError && (len(ips) != 0 || !errors.Is(err, ErrRemoteIPProviderData)) {
				t.Fatalf("expected rejected data, got %v, %v", ips, err)
			}

			if reader.read != test.wantRead {
				t.Fatalf("expected %d bytes read, got %d", test.wantRead, reader.read)
			}
		})
	}
}

func TestReadResponseCIDRs_EntryAndLineLimits(t *testing.T) {
	var entries strings.Builder
	for index := range maxRemoteProviderCIDRs {
		fmt.Fprintf(&entries, "10.%d.%d.0/24\n", index/256, index%256)
	}

	for _, test := range []struct {
		name      string
		body      string
		wantCount int
		wantError bool
	}{
		{"maximum entries", entries.String(), maxRemoteProviderCIDRs, false},
		{"too many entries", entries.String() + "192.0.2.0/24\n", 0, true},
		{"too many duplicates", strings.Repeat("192.0.2.0/24\n", maxRemoteProviderCIDRs+1), 0, true},
		{"canonical duplicates", "192.0.2.0/24\n192.0.2.1/24\n", 1, false},
		{"overlong comment", "#" + strings.Repeat("x", maxRemoteProviderLineBytes) + "\n192.0.2.0/24", 0, true},
		{"overlong CIDR", strings.Repeat(" ", maxRemoteProviderLineBytes) + "192.0.2.0/24", 0, true},
		{"IPv6 default route", "::/0\n", 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := new(http.Response)
			response.Body = io.NopCloser(strings.NewReader(test.body))
			response.ContentLength = -1

			ips, err := newTestResolver(
				t,
			).readResponseCIDRs(t.Context(), response, "test", "fixture")
			if (err != nil) != test.wantError || len(ips) != test.wantCount {
				t.Fatalf(
					"expected count %d and error %t, got %d, %v",
					test.wantCount,
					test.wantError,
					len(ips),
					err,
				)
			}
		})
	}
}

func TestGetProviderIPs_AggregateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/extra" {
			_, _ = io.WriteString(w, "192.0.2.0/24\n")

			return
		}

		for index := range maxRemoteProviderCIDRs {
			fmt.Fprintf(w, "10.%d.%d.0/24\n", index/256, index%256)
		}
	}))
	defer server.Close()

	provider := remoteIPProvider{
		name:  "test",
		urls:  []string{server.URL, server.URL + "/extra"},
		cache: new(remoteIPCache),
	}

	ips, err := newTestResolver(t).getProviderIPs(t.Context(), provider)
	if !errors.Is(err, ErrRemoteIPProviderData) || len(ips) != 0 || len(provider.cache.ips) != 0 {
		t.Fatalf("aggregate limit did not prevent publication: %v, %v", ips, err)
	}
}

func TestGetProviderIPsFromURL_DecodedByteLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		writer := gzip.NewWriter(w)
		_, _ = io.WriteString(
			writer,
			"198.51.100.0/24\n"+strings.Repeat("\n", maxRemoteProviderBytes),
		)
		_ = writer.Close()
	}))
	defer server.Close()

	ips, err := newTestResolver(t).getProviderIPsFromURL(t.Context(), "test", server.URL)
	if !errors.Is(err, ErrRemoteIPProviderData) || len(ips) != 0 {
		t.Fatalf("oversized decoded body was accepted: %v, %v", ips, err)
	}
}
