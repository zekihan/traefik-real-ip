package traefik_real_ip

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestNew_EmptyEdgeOneProviderRecovers(t *testing.T) {
	var ready atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ready.Load() {
			_, _ = w.Write([]byte("198.51.100.0/24\n"))
		}
	}))
	defer server.Close()

	originalProvider := edgeOneProvider
	edgeOneProvider = remoteIPProvider{
		name:    originalProvider.name,
		sources: []remoteIPSource{{url: server.URL, ipVersion: anyIPVersion}},
		cache:   new(remoteIPCache),
	}

	t.Cleanup(func() { edgeOneProvider = originalProvider })

	cfg := CreateConfig()
	cfg.TrustLocal = false
	cfg.TrustCloudFlare = false
	cfg.TrustEdgeOne = true
	cfg.DenyUntrusted = true

	handler, err := New(t.Context(), http.NotFoundHandler(), cfg, "test")
	if handler != nil || !errors.Is(err, ErrGettingEdgeOneIPs) {
		t.Fatalf("expected failed initialization, got %T, %v", handler, err)
	}

	if len(edgeOneProvider.cache.ips) != 0 {
		t.Fatal("empty response was cached")
	}

	ready.Store(true)

	handler, err = New(t.Context(), http.NotFoundHandler(), cfg, "test")
	if err != nil {
		t.Fatal(err)
	}

	assertProviderRequest(t, handler, "198.51.100.1:1234", http.StatusNotFound)
	assertProviderRequest(t, handler, "203.0.113.1:1234", http.StatusForbidden)
}

func TestNew_PartialCloudflareProviderRecovers(t *testing.T) {
	var ready atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v4" {
			_, _ = w.Write([]byte("173.245.48.0/20\n"))

			return
		}

		if !ready.Load() {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		_, _ = w.Write([]byte("2400:cb00::/32\n"))
	}))
	defer server.Close()

	useCloudflareTestFeeds(t, server.URL+"/v4", server.URL+"/v6")

	cfg := CreateConfig()
	cfg.TrustLocal = false
	cfg.TrustCloudFlare = true
	cfg.DenyUntrusted = true

	handler, err := New(t.Context(), http.NotFoundHandler(), cfg, "test")
	if handler != nil || !errors.Is(err, ErrGettingCloudflareIPs) {
		t.Fatalf("expected failed initialization, got %T, %v", handler, err)
	}

	if len(cloudflareProvider.cache.ips) != 0 {
		t.Fatal("partial response was cached")
	}

	ready.Store(true)

	handler, err = New(t.Context(), http.NotFoundHandler(), cfg, "test")
	if err != nil {
		t.Fatal(err)
	}

	assertProviderRequest(t, handler, "173.245.48.1:1234", http.StatusNotFound)
	assertProviderRequest(t, handler, "[2400:cb00::1]:1234", http.StatusNotFound)
}

func TestNew_CloudflareProviderRejectsWrongAddressFamily(t *testing.T) {
	const (
		ipv4Ranges = "192.0.2.0/24\n"
		ipv6Ranges = "2001:db8::/32\n"
	)

	for _, test := range []struct {
		name string
		ipv4 string
		ipv6 string
	}{
		{"repeated IPv4 feed", ipv4Ranges, ipv4Ranges},
		{"IPv6 in IPv4 feed", ipv4Ranges + ipv6Ranges, ipv6Ranges},
		{"mapped IPv4 in IPv6 feed", ipv4Ranges, ipv6Ranges + "::ffff:192.0.2.0/120\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var ready atomic.Bool

			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					ipv4, ipv6 := test.ipv4, test.ipv6
					if ready.Load() {
						ipv4, ipv6 = ipv4Ranges, ipv6Ranges
					}

					if r.URL.Path == "/v4" {
						_, _ = io.WriteString(w, ipv4)

						return
					}

					_, _ = io.WriteString(w, ipv6)
				}),
			)
			t.Cleanup(server.Close)

			useCloudflareTestFeeds(t, server.URL+"/v4", server.URL+"/v6")

			cfg := CreateConfig()
			cfg.TrustLocal = false
			cfg.DenyUntrusted = true

			handler, err := New(t.Context(), http.NotFoundHandler(), cfg, "test")
			if handler != nil || !errors.Is(err, ErrGettingCloudflareIPs) ||
				!errors.Is(err, ErrRemoteIPProviderData) {
				t.Fatalf("expected address family mismatch, got %T, %v", handler, err)
			}

			if len(cloudflareProvider.cache.ips) != 0 {
				t.Fatal("wrong-family response was cached")
			}

			ready.Store(true)

			handler, err = New(t.Context(), http.NotFoundHandler(), cfg, "test")
			if err != nil {
				t.Fatal(err)
			}

			assertProviderRequest(t, handler, "192.0.2.1:1234", http.StatusNotFound)
			assertProviderRequest(t, handler, "[2001:db8::1]:1234", http.StatusNotFound)
		})
	}
}

func assertProviderRequest(t *testing.T, handler http.Handler, source string, status int) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = source
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != status {
		t.Fatalf("source %s: expected %d, got %d", source, status, recorder.Code)
	}
}

func TestNew_ScopedEdgeOneFeedRecovers(t *testing.T) {
	var ready atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if ready.Load() {
			_, _ = w.Write([]byte("198.51.100.0/24\n"))
		}
	}))
	defer server.Close()

	useEdgeOneTestFeed(t, server.URL)

	cfg := scopedEdgeOneConfig()

	handler, err := New(t.Context(), http.NotFoundHandler(), cfg, "scoped-edgeone")
	if handler != nil || !errors.Is(err, ErrGettingEdgeOneIPs) {
		t.Fatalf("expected failed initialization, got %T, %v", handler, err)
	}

	if len(edgeOneProvider.cache.ips) != 0 {
		t.Fatal("empty edgeone response was cached")
	}

	ready.Store(true)

	handler, err = New(t.Context(), http.NotFoundHandler(), cfg, "scoped-edgeone")
	if err != nil {
		t.Fatal(err)
	}

	status, headers := scopedEdgeRequest(
		t,
		handler,
		"198.51.100.1:1234",
		EoConnectingIP,
		"203.0.113.8",
	)
	if status != http.StatusOK {
		t.Fatalf("edgeone peer: %d", status)
	}

	if headers.Get(XRealIP) != "203.0.113.8" || headers.Get(XForwardedFor) != "203.0.113.8" {
		t.Fatalf("identity headers: %v", headers)
	}

	if headers.Get(EoConnectingIP) != "" {
		t.Fatalf("Eo-Connecting-Ip not stripped: %q", headers.Get(EoConnectingIP))
	}
}

func TestNew_ScopedEdgeOneIgnoresOtherHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("198.51.100.0/24\n"))
	}))
	defer server.Close()

	useEdgeOneTestFeed(t, server.URL)

	handler, err := New(
		t.Context(),
		http.NotFoundHandler(),
		scopedEdgeOneConfig(),
		"scoped-edgeone",
	)
	if err != nil {
		t.Fatal(err)
	}

	status, headers := scopedEdgeRequest(
		t,
		handler,
		"198.51.100.1:1234",
		XForwardedFor,
		"203.0.113.9",
	)
	if status != http.StatusOK || headers.Get(XRealIP) != "198.51.100.1" {
		t.Fatalf("xff from edgeone peer: status %d identity %q", status, headers.Get(XRealIP))
	}

	status, _ = scopedEdgeRequest(t, handler, "198.51.100.1:1234", EoConnectingIP, "not-an-ip")
	if status != http.StatusBadRequest {
		t.Fatalf("invalid eo header: %d", status)
	}

	status, headers = scopedEdgeRequest(
		t,
		handler,
		"203.0.113.9:1234",
		EoConnectingIP,
		"198.51.100.8",
	)
	if status != http.StatusOK || headers.Get(XRealIP) != "203.0.113.9" {
		t.Fatalf("non-edgeone peer: status %d identity %q", status, headers.Get(XRealIP))
	}
}

func scopedEdgeOneConfig() *Config {
	cfg := CreateConfig()
	cfg.ScopedTrust = true
	cfg.TrustLocal = false
	cfg.TrustCloudFlare = false
	cfg.TrustEdgeOne = true

	return cfg
}

func useEdgeOneTestFeed(t *testing.T, url string) {
	t.Helper()

	originalProvider := edgeOneProvider
	edgeOneProvider = remoteIPProvider{
		name:    originalProvider.name,
		sources: []remoteIPSource{{url: url, ipVersion: anyIPVersion}},
		cache:   new(remoteIPCache),
	}

	t.Cleanup(func() { edgeOneProvider = originalProvider })
}

func scopedEdgeRequest(
	t *testing.T,
	handler http.Handler,
	remote, header, value string,
) (int, http.Header) {
	t.Helper()

	var got http.Header

	resolver, ok := handler.(*IPResolver)
	if !ok {
		t.Fatal("handler is not an IPResolver")
	}

	resolver.next = http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		got = req.Header.Clone()
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = remote

	if header != "" {
		req.Header.Set(header, value)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	return recorder.Code, got
}

func TestNew_ScopedCloudflareFeedFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	useCloudflareTestFeeds(t, server.URL+"/v4", server.URL+"/v6")

	cfg := CreateConfig()
	cfg.ScopedTrust = true
	cfg.TrustLocal = false
	cfg.TrustCloudFlare = true
	cfg.TrustEdgeOne = false

	handler, err := New(t.Context(), http.NotFoundHandler(), cfg, "scoped-cloudflare")
	if handler != nil || !errors.Is(err, ErrGettingCloudflareIPs) {
		t.Fatalf("expected failed initialization, got %T, %v", handler, err)
	}

	if len(cloudflareProvider.cache.ips) != 0 {
		t.Fatal("failed cloudflare load was cached")
	}
}

func TestNew_MappedDefaultRouteRejected(t *testing.T) {
	var ready atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if ready.Load() {
			_, _ = w.Write([]byte("::ffff:198.51.100.0/120\n"))
		} else {
			_, _ = w.Write([]byte("198.51.100.0/24\n::ffff:203.0.113.1/96\n"))
		}
	}))
	defer server.Close()

	originalProvider := edgeOneProvider
	edgeOneProvider = remoteIPProvider{
		name:    originalProvider.name,
		sources: []remoteIPSource{{url: server.URL, ipVersion: anyIPVersion}},
		cache:   new(remoteIPCache),
	}

	t.Cleanup(func() { edgeOneProvider = originalProvider })

	cfg := CreateConfig()
	cfg.TrustLocal = false
	cfg.TrustCloudFlare = false
	cfg.TrustEdgeOne = true
	cfg.DenyUntrusted = true

	var assertedIP string

	next := http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		assertedIP = req.Header.Get(XRealIP)
	})

	handler, err := New(t.Context(), next, cfg, "test")
	if handler != nil {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
		req.RemoteAddr = "203.0.113.1:1234"
		req.Header.Set(EoConnectingIP, "192.0.2.66")

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		t.Errorf("default route initialized middleware: arbitrary peer got %d, identity %q",
			recorder.Code, assertedIP)
	}

	if !errors.Is(err, ErrRemoteIPProviderData) || !errors.Is(err, ErrGettingEdgeOneIPs) {
		t.Fatalf("expected provider validation failure, got %v", err)
	}

	if len(edgeOneProvider.cache.ips) != 0 {
		t.Fatal("invalid snapshot was cached")
	}

	ready.Store(true)

	handler, err = New(t.Context(), http.NotFoundHandler(), cfg, "test")
	if err != nil {
		t.Fatal(err)
	}

	assertProviderRequest(t, handler, "198.51.100.1:1234", http.StatusNotFound)
	assertProviderRequest(t, handler, "203.0.113.1:1234", http.StatusForbidden)
}
