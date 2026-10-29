package traefik_real_ip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAbortRetryPreservesPrivateClientIdentity(t *testing.T) {
	for _, client := range []string{"10.20.0.10", "fd20::10"} {
		t.Run(client, func(t *testing.T) {
			cfg := CreateConfig()
			cfg.ThrustLocal = false
			cfg.ThrustCloudFlare = false
			cfg.TrustedIPs = []string{"192.0.2.0/24"}
			calls := 0
			next := http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
				calls++
				if got := req.Header.Get(XRealIP); got != client {
					t.Errorf("invocation %d: client identity = %s, want %s", calls, got, client)
				}

				if calls < 3 {
					panic(http.ErrAbortHandler)
				}
			})

			handler, err := New(t.Context(), next, cfg, "retry-identity")
			if err != nil {
				t.Fatal(err)
			}

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			req.RemoteAddr = "192.0.2.1:12345"
			req.Header.Set(XForwardedFor, "203.0.113.66, "+client+", 192.0.2.2")
			handler.ServeHTTP(httptest.NewRecorder(), req)

			if calls != 3 {
				t.Fatalf("downstream invocations = %d, want 3", calls)
			}
		})
	}
}
