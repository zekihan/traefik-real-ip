package traefik_real_ip

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPrivateClientTrustPolicy(t *testing.T) {
	tests := []struct {
		name          string
		peer          string
		client        string
		chain         string
		wantIP        string
		proxyCIDRs    []string
		wantStatus    int
		trustLocal    bool
		clientTrusted bool
	}{
		{
			name:          "broad local trust rejects ambiguous private client",
			peer:          "10.0.0.1",
			client:        "10.20.0.10",
			chain:         "10.20.0.10, 10.0.0.2",
			wantIP:        "",
			proxyCIDRs:    nil,
			wantStatus:    http.StatusBadRequest,
			trustLocal:    true,
			clientTrusted: true,
		},
		{
			name:          "explicit IPv4 proxies preserve private boundary despite forged prefix",
			peer:          "10.0.0.1",
			client:        "10.20.0.10",
			chain:         "203.0.113.66, 10.20.0.10, 10.0.0.2",
			wantIP:        "10.20.0.10",
			proxyCIDRs:    []string{"10.0.0.1/32", "10.0.0.2/32"},
			wantStatus:    http.StatusOK,
			trustLocal:    false,
			clientTrusted: false,
		},
		{
			name:          "broad IPv6 local trust rejects ambiguous private client",
			peer:          "fd00::1",
			client:        "fd20::10",
			chain:         "fd20::10, fd00::2",
			wantIP:        "",
			proxyCIDRs:    nil,
			wantStatus:    http.StatusBadRequest,
			trustLocal:    true,
			clientTrusted: true,
		},
		{
			name:          "explicit IPv6 proxies preserve private boundary despite forged prefix",
			peer:          "fd00::1",
			client:        "fd20::10",
			chain:         "2001:db8::66, fd20::10, fd00::2",
			wantIP:        "fd20::10",
			proxyCIDRs:    []string{"fd00::1/128", "fd00::2/128"},
			wantStatus:    http.StatusOK,
			trustLocal:    false,
			clientTrusted: false,
		},
		{
			name:          "all explicitly trusted proxies still fail closed",
			peer:          "10.0.0.1",
			client:        "10.0.0.2",
			chain:         "10.0.0.2",
			wantIP:        "",
			proxyCIDRs:    []string{"10.0.0.1/32", "10.0.0.2/32"},
			wantStatus:    http.StatusBadRequest,
			trustLocal:    false,
			clientTrusted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := CreateConfig()
			// Broad-trust cases match the existing middleware policy; providers use offline
			// fixtures.
			cfg.ThrustCloudFlare = tt.trustLocal
			cfg.ThrustEdgeOne = false
			cfg.ThrustLocal = tt.trustLocal

			cfg.TrustedIPs = append([]string{}, tt.proxyCIDRs...)
			if !tt.trustLocal {
				cfg.XForwardedForMode = XForwardedForModeReplace
			}

			called := false
			next := http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
				called = true

				if req.Header.Get(XRealIP) != tt.wantIP ||
					req.Header.Get(XForwardedFor) != tt.wantIP {
					t.Errorf("expected private client %s, got headers %v", tt.wantIP, req.Header)
				}
			})

			handler, err := New(t.Context(), next, cfg, "private-client-fixture")
			if err != nil {
				t.Fatal(err)
			}

			resolver, ok := handler.(*IPResolver)
			if !ok {
				t.Fatalf("expected *IPResolver, got %T", handler)
			}

			if got := resolver.isTrustedIP(
				t.Context(),
				net.ParseIP(tt.client),
			); got != tt.clientTrusted {
				t.Fatalf(
					"client proxy-trust classification: got %t, want %t",
					got,
					tt.clientTrusted,
				)
			}

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			req.RemoteAddr = net.JoinHostPort(tt.peer, "12345")
			req.Header.Set(XForwardedFor, tt.chain)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			if recorder.Code != tt.wantStatus || called != (tt.wantStatus == http.StatusOK) {
				t.Fatalf(
					"status %d, downstream called %t; want status %d",
					recorder.Code,
					called,
					tt.wantStatus,
				)
			}

			if tt.wantStatus == http.StatusBadRequest &&
				recorder.Body.String() != "invalid client IP headers\n" {
				t.Fatalf("unexpected error response: %q", recorder.Body.String())
			}
		})
	}
}
