package traefik_real_ip

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestNew_EmptyEdgeOneProviderDoesNotFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	originalProvider := edgeOneProvider
	originalInstance := edgeOneIPsInstance

	var localOnce sync.Once

	edgeOneIPsInstance = nil
	edgeOneProvider = remoteIPProvider{
		name:  originalProvider.name,
		urls:  []string{server.URL},
		once:  &localOnce,
		cache: &edgeOneIPsInstance,
	}

	defer func() {
		edgeOneProvider = originalProvider
		edgeOneIPsInstance = originalInstance
	}()

	cfg := CreateConfig()
	cfg.ThrustLocal = false
	cfg.ThrustCloudFlare = false
	cfg.ThrustEdgeOne = true

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(t.Context(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New returned unexpected error: %v", err)
	}

	resolver, ok := handler.(*IPResolver)
	if !ok {
		t.Fatalf("expected *IPResolver, got %T", handler)
	}

	if len(resolver.trustedIPNets) != 0 {
		t.Fatalf("expected no trusted IPs, got %d", len(resolver.trustedIPNets))
	}
}

func TestNew_PartialCloudflareProviderDataDoesNotFail(t *testing.T) {
	ipv4Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		_, err := w.Write([]byte("173.245.48.0/20"))
		if err != nil {
			t.Fatalf("Failed to write IPv4 response: %v", err)
		}
	}))
	defer ipv4Server.Close()

	ipv6Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ipv6Server.Close()

	originalProvider := cloudflareProvider
	originalInstance := cloudFlareIPsInstance

	var localOnce sync.Once

	cloudFlareIPsInstance = nil
	cloudflareProvider = remoteIPProvider{
		name:  originalProvider.name,
		urls:  []string{ipv4Server.URL, ipv6Server.URL},
		once:  &localOnce,
		cache: &cloudFlareIPsInstance,
	}

	defer func() {
		cloudflareProvider = originalProvider
		cloudFlareIPsInstance = originalInstance
	}()

	cfg := CreateConfig()
	cfg.ThrustLocal = false
	cfg.ThrustCloudFlare = true
	cfg.ThrustEdgeOne = false

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(t.Context(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New returned unexpected error: %v", err)
	}

	resolver, ok := handler.(*IPResolver)
	if !ok {
		t.Fatalf("expected *IPResolver, got %T", handler)
	}

	if len(resolver.trustedIPNets) != 1 {
		t.Fatalf("expected one trusted IP, got %d", len(resolver.trustedIPNets))
	}

	_, expectedNet, err := net.ParseCIDR("173.245.48.0/20")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}

	if resolver.trustedIPNets[0].String() != expectedNet.String() {
		t.Fatalf("expected trusted IP %s, got %s", expectedNet, resolver.trustedIPNets[0])
	}
}
