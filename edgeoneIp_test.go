package traefik_real_ip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIPResolver_getEdgeOneIPFromURL(t *testing.T) {
	resolver := newTestResolver(t)
	runRemoteProviderResponseTests(t, resolver.getEdgeOneIPFromURL)
}

func TestIPResolver_getEdgeOneIPs(t *testing.T) {
	logger := NewPluginLogger(t.Context(), "test", LogLevelDebug)
	resolver := &IPResolver{logger: logger, next: nil, conf: nil, name: "", trustedIPNets: nil}

	ipv4Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		_, err := w.Write([]byte("198.51.100.0/24"))
		if err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer ipv4Server.Close()

	ipv6Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		_, err := w.Write([]byte("2001:db8::/32"))
		if err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer ipv6Server.Close()

	originalProvider := edgeOneProvider

	edgeOneProvider = remoteIPProvider{
		name:  originalProvider.name,
		urls:  []string{ipv4Server.URL, ipv6Server.URL},
		cache: new(remoteIPCache),
	}

	defer func() {
		edgeOneProvider = originalProvider
	}()

	t.Run("singleton behavior", func(t *testing.T) {
		ips1, err := resolver.getEdgeOneIPs(t.Context())
		if err != nil {
			t.Fatal(err)
		}

		ips2, err := resolver.getEdgeOneIPs(t.Context())
		if err != nil {
			t.Fatal(err)
		}

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
