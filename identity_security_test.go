package traefik_real_ip

import (
	"bytes"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInvalidIdentityHeadersAreBounded(t *testing.T) {
	for _, header := range []string{CfConnectingIP, EoConnectingIP, XRealIP, XForwardedFor} {
		for _, level := range []slog.Level{slog.LevelInfo, slog.LevelDebug} {
			t.Run(header+level.String(), func(t *testing.T) {
				for _, size := range []int{1, 1 << 20} {
					checkInvalidIdentityHeader(t, header, level, size)
				}
			})
		}
	}
}

func checkInvalidIdentityHeader(t *testing.T, header string, level slog.Level, size int) {
	t.Helper()

	var logs bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{
		Level: level, ReplaceAttr: replaceAttr, AddSource: false,
	}))

	_, trustedNet, err := net.ParseCIDR("192.0.2.1/32")
	if err != nil {
		t.Fatal(err)
	}

	resolver := &IPResolver{
		logger: &PluginLogger{logger: logger, pluginName: "test"},
		conf:   nil, name: "test",
		trustedIPNets: []*net.IPNet{trustedNet}, scoped: nil,
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("invalid identity reached downstream handler")
		}),
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "192.0.2.1:12345"
	req.Header.Set(header, strings.Repeat("!", size))

	recorder := httptest.NewRecorder()
	resolver.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest ||
		recorder.Body.String() != "invalid client IP headers\n" {
		t.Fatalf(
			"unexpected response: %d %q",
			recorder.Code,
			recorder.Body.String(),
		)
	}

	if logs.Len() > 2048 || strings.Contains(logs.String(), "!") ||
		strings.Contains(logs.String(), "exceptionStacktrace") {
		t.Fatalf("unbounded or unsafe diagnostics: length %d", logs.Len())
	}

	if level == slog.LevelInfo && logs.Len() != 0 {
		t.Fatalf(
			"expected validation diagnostics only at debug level, got %q",
			logs.String(),
		)
	}

	if level == slog.LevelDebug &&
		!strings.Contains(logs.String(), "Invalid identity header") {
		t.Fatal("expected bounded validation diagnostics at debug level")
	}
}

func TestForwardedIdentityThroughMiddleware(t *testing.T) {
	_, trustedNet, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}

	for _, mode := range []string{XForwardedForModeAppend, XForwardedForModeReplace} {
		t.Run(mode, func(t *testing.T) {
			called := false
			conf := CreateConfig()
			conf.XForwardedForMode = mode
			resolver := &IPResolver{
				logger: newTestResolver(t).logger,
				conf:   conf, name: "test",
				trustedIPNets: []*net.IPNet{trustedNet}, scoped: nil,
				next: http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
					called = true

					if got := req.Header.Get(XRealIP); got != "203.0.113.10" {
						t.Errorf("attacker prefix selected: %s", got)
					}

					if mode == XForwardedForModeReplace &&
						req.Header.Get(XForwardedFor) != "203.0.113.10" {
						t.Errorf(
							"replace mode retained input chain: %s",
							req.Header.Get(XForwardedFor),
						)
					}
				}),
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			req.RemoteAddr = "192.0.2.1:12345"
			req.Header.Set(XForwardedFor, "198.51.100.66, 203.0.113.10, 192.0.2.2")
			resolver.ServeHTTP(httptest.NewRecorder(), req)

			if !called {
				t.Fatal("valid trusted suffix did not reach downstream handler")
			}
		})
	}
}

func TestAppendXForwardedForDeduplicatesResolvedIP(t *testing.T) {
	cfg := CreateConfig()
	cfg.TrustLocal = false
	cfg.TrustCloudFlare = false
	cfg.TrustEdgeOne = false
	cfg.TrustedIPs = []string{"192.0.2.0/24"}
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	})

	handler, err := New(t.Context(), next, cfg, "test")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, chain, wantIP, wantChain string
	}{
		{
			name:      "expanded IPv6 client",
			chain:     "2001:0DB8:0:0:0:0:0:7",
			wantIP:    "2001:db8::7",
			wantChain: "2001:db8::7",
		},
		{
			name:      "mapped IPv4 client with other hops",
			chain:     "2001:0DB8::9, ::203.0.113.10, ::FFFF:203.0.113.10, 192.0.2.2",
			wantIP:    "203.0.113.10",
			wantChain: "203.0.113.10, 2001:0DB8::9, ::203.0.113.10, 192.0.2.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			req.RemoteAddr = "192.0.2.1:12345"
			req.Header.Set(XForwardedFor, tt.chain)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			if recorder.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
			}

			if got := req.Header.Get(XRealIP); got != tt.wantIP {
				t.Errorf("X-Real-IP = %q, want %q", got, tt.wantIP)
			}

			if got := req.Header.Values(XForwardedFor); len(got) != 1 || got[0] != tt.wantChain {
				t.Errorf("X-Forwarded-For = %q, want [%q]", got, tt.wantChain)
			}
		})
	}
}
