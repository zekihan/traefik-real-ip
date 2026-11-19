package traefik_real_ip

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func useCloudflareTestFeeds(t *testing.T, ipv4URL, ipv6URL string) {
	t.Helper()

	fixtureURLs := map[string]string{cloudflareIPv4URL: ipv4URL, cloudflareIPv6URL: ipv6URL}
	originalProvider := cloudflareProvider

	sources := slices.Clone(originalProvider.sources)
	for index := range sources {
		url, ok := fixtureURLs[sources[index].url]
		if !ok {
			t.Fatalf("no fixture for Cloudflare feed %s", sources[index].url)
		}

		sources[index].url = url
	}

	cloudflareProvider = remoteIPProvider{
		name: originalProvider.name, sources: sources, cache: new(remoteIPCache),
	}

	t.Cleanup(func() { cloudflareProvider = originalProvider })
}

func TestIPResolver_getCloudFlareIPFromURL(t *testing.T) {
	resolver := newTestResolver(t)
	runRemoteProviderResponseTests(t, resolver.getCloudFlareIPFromURL)
}

func TestIPResolver_getCloudFlareIPs(t *testing.T) {
	logger := NewPluginLogger(t.Context(), "test", LogLevelDebug)
	resolver := &IPResolver{logger: logger, next:

	// Create mock servers for IPv4 and IPv6
	nil, conf: nil, name: "", trustedIPNets: nil, scoped: nil}

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

	useCloudflareTestFeeds(t, ipv4Server.URL, ipv6Server.URL)

	t.Run("singleton behavior", func(t *testing.T) {
		ips1, err := resolver.getCloudFlareIPs(t.Context())
		if err != nil {
			t.Fatal(err)
		}

		ips2, err := resolver.getCloudFlareIPs(t.Context())
		if err != nil {
			t.Fatal(err)
		}

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
