package traefik_real_ip

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestIPResolver_getCloudFlareIPFromURL(t *testing.T) {
	resolver := newTestResolver(t)
	runRemoteProviderResponseTests(t, resolver.getCloudFlareIPFromURL)
}

func TestIPResolver_getCloudFlareIPs(t *testing.T) {
	logger := NewPluginLogger(t.Context(), "test", LogLevelDebug)
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

	originalProvider := cloudflareProvider
	originalInstance := cloudFlareIPsInstance
	// Use a local once so we don't mutate the package-level sync.Once
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

	// This test would require modifying the actual URLs or dependency injection
	// reset localOnce and cache for this subtest
	localOnce = sync.Once{}

	t.Run("singleton behavior", func(t *testing.T) {
		cloudFlareIPsInstance = nil

		ips1 := resolver.getCloudFlareIPs(t.Context())
		ips2 := resolver.getCloudFlareIPs(t.Context())

		if len(ips1) != len(ips2) {
			t.Errorf("Singleton behavior failed: different lengths %d vs %d", len(ips1), len(ips2))
		}

		if len(ips1) != 4 {
			t.Errorf("Expected 4 IPs from mock provider, got %d", len(ips1))
		}

		// Check that it's the same slice (same memory address)
		if &ips1[0] != &ips2[0] {
			t.Errorf("Singleton behavior failed: different instances returned")
		}
	})
}

func TestCIDRParsing_Cloudflare(t *testing.T) {
	resolver := newTestResolver(t)
	runCIDRParsingTests(t, resolver.getCloudFlareIPFromURL)
}

func TestHTTPErrorHandling_Cloudflare(t *testing.T) {
	resolver := newTestResolver(t)
	runHTTPErrorTests(t, resolver.getCloudFlareIPFromURL)
}
