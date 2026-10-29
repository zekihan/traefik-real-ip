//nolint:exhaustruct_v5,prealloc // Table cases specify only relevant fields.
package traefik_real_ip_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	plugin "github.com/zekihan/traefik-real-ip"
)

func TestSocketPeerZones(t *testing.T) {
	scoped := (&net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 12345, Zone: "eth0"}).String()

	tests := []struct {
		name, remote, header, value, wantIP, wantTrusted string
		trusted                                          []string
		local, deny                                      bool
		status                                           int
	}{
		{
			name:        "local trusted proxy",
			remote:      scoped,
			local:       true,
			header:      plugin.XRealIP,
			value:       "2001:0db8::10",
			wantIP:      "2001:db8::10",
			wantTrusted: "yes",
			status:      200,
		},
		{
			name:        "explicit trusted range",
			remote:      scoped,
			trusted:     []string{"fe80::/10"},
			deny:        true,
			header:      plugin.XForwardedFor,
			value:       "203.0.113.10",
			wantIP:      "203.0.113.10",
			wantTrusted: "yes",
			status:      200,
		},
		{
			name:        "untrusted ignores headers",
			remote:      scoped,
			header:      plugin.XRealIP,
			value:       "203.0.113.10",
			wantIP:      "fe80::1",
			wantTrusted: "no",
			status:      200,
		},
		{name: "untrusted denied", remote: scoped, deny: true, status: 403},
		{
			name:        "local peer without header",
			remote:      scoped,
			local:       true,
			wantIP:      "fe80::1",
			wantTrusted: "yes",
			status:      200,
		},
		{name: "IPv4", remote: "192.0.2.1:80", wantIP: "192.0.2.1", wantTrusted: "no", status: 200},
		{
			name:        "global IPv6",
			remote:      "[2001:0db8::1]:80",
			wantIP:      "2001:db8::1",
			wantTrusted: "no",
			status:      200,
		},
		{name: "missing port", remote: "fe80::1%eth0", status: 400},
		{name: "invalid IPv6", remote: "[not-ip%eth0]:80", status: 400},
		{name: "empty zone", remote: "[fe80::1%]:80", status: 400},
		{name: "IPv4 zone", remote: "[192.0.2.1%eth0]:80", status: 400},
	}
	for _, header := range []string{plugin.CfConnectingIP, plugin.EoConnectingIP, plugin.XRealIP, plugin.XForwardedFor} {
		tests = append(tests, struct {
			name, remote, header, value, wantIP, wantTrusted string
			trusted                                          []string
			local, deny                                      bool
			status                                           int
		}{name: "zone in " + header, remote: scoped, local: true, header: header, value: "fe80::2%eth0", status: 400})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := plugin.CreateConfig()
			cfg.ThrustLocal = tt.local
			cfg.ThrustCloudFlare = false
			cfg.ThrustEdgeOne = false
			cfg.TrustedIPs = tt.trusted
			cfg.DenyUntrusted = tt.deny
			cfg.XForwardedForMode = plugin.XForwardedForModeReplace
			called := false

			handler, err := plugin.New(
				t.Context(),
				http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }),
				cfg,
				"test",
			)
			if err != nil {
				t.Fatal(err)
			}

			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"http://localhost/",
				http.NoBody,
			)

			req.RemoteAddr = tt.remote
			if tt.header != "" {
				req.Header.Set(tt.header, tt.value)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.status || called != (tt.status == http.StatusOK) {
				t.Fatalf("status = %d, next called = %v; want %d", rr.Code, called, tt.status)
			}

			if tt.status == http.StatusOK {
				for key, want := range map[string]string{
					plugin.XRealIP: tt.wantIP, plugin.XForwardedFor: tt.wantIP,
					plugin.XIsTrusted: tt.wantTrusted,
				} {
					if got := req.Header.Get(key); got != want {
						t.Errorf("%s = %q, want %q", key, got, want)
					}
				}
			}
		})
	}
}
