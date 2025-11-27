//nolint:staticcheck // no reason
package traefik_real_ip

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestIPResolver_getEdgeOneIPFromURL(t *testing.T) {
	resolver := newTestResolver(t)
	runRemoteProviderResponseTests(t, resolver.getEdgeOneIPFromURL)
}

func TestIPResolver_getEdgeOneIPs(t *testing.T) {
	level := &slog.LevelVar{}
	level.Set(slog.LevelDebug)
	logger := NewPluginLogger("test", level)
	resolver := &IPResolver{logger: logger}

	ipv4Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		if _, err := w.Write([]byte("198.51.100.0/24")); err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer ipv4Server.Close()

	ipv6Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		if _, err := w.Write([]byte("2001:db8::/32")); err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer ipv6Server.Close()

	originalProvider := edgeOneProvider
	originalOnce := edgeOneIPsOnce
	originalInstance := edgeOneIPsInstance

	edgeOneIPsInstance = nil
	edgeOneIPsOnce = sync.Once{}
	edgeOneProvider = remoteIPProvider{
		name:  originalProvider.name,
		urls:  []string{ipv4Server.URL, ipv6Server.URL},
		once:  &edgeOneIPsOnce,
		cache: &edgeOneIPsInstance,
	}

	defer func() {
		edgeOneProvider = originalProvider
		edgeOneIPsOnce = originalOnce
		edgeOneIPsInstance = originalInstance
	}()

	t.Run("singleton behavior", func(t *testing.T) {
		edgeOneIPsOnce = sync.Once{}
		edgeOneIPsInstance = nil

		ips1 := resolver.getEdgeOneIPs(t.Context())
		ips2 := resolver.getEdgeOneIPs(t.Context())

		if len(ips1) != len(ips2) {
			t.Errorf("Singleton behavior failed: different lengths %d vs %d", len(ips1), len(ips2))
		}

		if len(ips1) != 2 {
			t.Errorf("Expected 2 IPs from mock provider, got %d", len(ips1))
		}

		if len(ips1) > 0 && &ips1[0] != &ips2[0] {
			t.Errorf("Singleton behavior failed: different instances returned")
		}
	})
}

func TestCIDRParsing_EdgeOne(t *testing.T) {
	resolver := newTestResolver(t)
	runCIDRParsingTests(t, resolver.getEdgeOneIPFromURL)
}

func TestHTTPErrorHandling_EdgeOne(t *testing.T) {
	resolver := newTestResolver(t)
	runHTTPErrorTests(t, resolver.getEdgeOneIPFromURL)
}
