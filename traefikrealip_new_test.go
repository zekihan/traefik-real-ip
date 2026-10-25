package traefik_real_ip

import (
	"errors"
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
		name: originalProvider.name, urls: []string{server.URL}, cache: new(remoteIPCache),
	}

	t.Cleanup(func() { edgeOneProvider = originalProvider })

	cfg := CreateConfig()
	cfg.ThrustLocal = false
	cfg.ThrustCloudFlare = false
	cfg.ThrustEdgeOne = true
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

	originalProvider := cloudflareProvider
	cloudflareProvider = remoteIPProvider{
		name:  originalProvider.name,
		urls:  []string{server.URL + "/v4", server.URL + "/v6"},
		cache: new(remoteIPCache),
	}

	t.Cleanup(func() { cloudflareProvider = originalProvider })

	cfg := CreateConfig()
	cfg.ThrustLocal = false
	cfg.ThrustCloudFlare = true
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
