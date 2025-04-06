package traefik_real_ip_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	traefikrealip "github.com/zekihan/traefik-real-ip"
)

func TestIPResolver_ServeHTTP(t *testing.T) {
	testCases := []struct {
		desc            string
		remote          string
		reqHeaders      map[string]string
		expectedHeaders map[string]string
		expectedStatus  int
		trustedIPs      []string
	}{
		{
			desc:       "No headers",
			remote:     "1.2.3.4",
			reqHeaders: map[string]string{},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "1.2.3.4",
				traefikrealip.XIsTrusted:    "no",
				traefikrealip.XForwardedFor: "1.2.3.4",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "CF-Connecting-IP",
			remote: "103.21.244.23",
			reqHeaders: map[string]string{
				traefikrealip.CfConnectingIP: "1.2.3.4",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "1.2.3.4",
				traefikrealip.XIsTrusted:    "yes",
				traefikrealip.XForwardedFor: "1.2.3.4",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "X-Real-IP",
			remote: "10.0.0.1",
			reqHeaders: map[string]string{
				traefikrealip.XRealIP: "1.2.3.4",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "1.2.3.4",
				traefikrealip.XIsTrusted:    "yes",
				traefikrealip.XForwardedFor: "1.2.3.4",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "X-Forwarded-For",
			remote: "10.0.0.1",
			reqHeaders: map[string]string{
				traefikrealip.XForwardedFor: "1.2.3.4",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "1.2.3.4",
				traefikrealip.XIsTrusted:    "yes",
				traefikrealip.XForwardedFor: "1.2.3.4",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "X-Forwarded-For with multiple IPs",
			remote: "10.0.0.1",
			reqHeaders: map[string]string{
				traefikrealip.XForwardedFor: "1.2.3.4, 1.1.1.1",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "1.2.3.4",
				traefikrealip.XIsTrusted:    "yes",
				traefikrealip.XForwardedFor: "1.2.3.4, 1.1.1.1",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "X-Forwarded-For with private IP",
			remote: "10.0.0.1",
			reqHeaders: map[string]string{
				traefikrealip.XForwardedFor: "192.168.1.1, 1.2.3.4",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "1.2.3.4",
				traefikrealip.XIsTrusted:    "yes",
				traefikrealip.XForwardedFor: "1.2.3.4, 192.168.1.1",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "X-Forwarded-For with private IP",
			remote: "10.0.0.1",
			reqHeaders: map[string]string{
				traefikrealip.XForwardedFor:  "1.2.3.4, 192.168.1.1",
				traefikrealip.CfConnectingIP: "1.2.3.4",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "1.2.3.4",
				traefikrealip.XIsTrusted:    "yes",
				traefikrealip.XForwardedFor: "1.2.3.4, 192.168.1.1",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "Local CF-Connecting-IP",
			remote: "10.0.0.1",
			reqHeaders: map[string]string{
				traefikrealip.CfConnectingIP: "1.2.3.4",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "1.2.3.4",
				traefikrealip.XIsTrusted:    "yes",
				traefikrealip.XForwardedFor: "1.2.3.4",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "CF-Connecting-IP not trusted",
			remote: "5.6.7.8",
			reqHeaders: map[string]string{
				traefikrealip.CfConnectingIP: "1.2.3.4",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "5.6.7.8",
				traefikrealip.XIsTrusted:    "no",
				traefikrealip.XForwardedFor: "5.6.7.8",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "X-Real-IP not trusted",
			remote: "5.6.7.8",
			reqHeaders: map[string]string{
				traefikrealip.XRealIP: "1.2.3.4",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "5.6.7.8",
				traefikrealip.XIsTrusted:    "no",
				traefikrealip.XForwardedFor: "5.6.7.8",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "X-Forwarded-For not trusted",
			remote: "5.6.7.8",
			reqHeaders: map[string]string{
				traefikrealip.XForwardedFor: "1.2.3.4",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "5.6.7.8",
				traefikrealip.XIsTrusted:    "no",
				traefikrealip.XForwardedFor: "5.6.7.8",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "All headers present, but not trusted",
			remote: "5.6.7.8",
			reqHeaders: map[string]string{
				traefikrealip.CfConnectingIP: "1.2.3.4",
				traefikrealip.XRealIP:        "1.2.3.5",
				traefikrealip.XForwardedFor:  "1.2.3.6",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "5.6.7.8",
				traefikrealip.XIsTrusted:    "no",
				traefikrealip.XForwardedFor: "5.6.7.8",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "Invalid CF-Connecting-IP",
			remote: "10.0.0.1",
			reqHeaders: map[string]string{
				traefikrealip.CfConnectingIP: "invalid",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "10.0.0.1",
				traefikrealip.XIsTrusted:    "yes",
				traefikrealip.XForwardedFor: "10.0.0.1",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			desc:   "Invalid X-Real-IP",
			remote: "10.0.0.1",
			reqHeaders: map[string]string{
				traefikrealip.XRealIP: "invalid",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "10.0.0.1",
				traefikrealip.XIsTrusted:    "yes",
				traefikrealip.XForwardedFor: "10.0.0.1",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			desc:   "Invalid X-Forwarded-For",
			remote: "10.0.0.1",
			reqHeaders: map[string]string{
				traefikrealip.XForwardedFor: "invalid",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "10.0.0.1",
				traefikrealip.XIsTrusted:    "yes",
				traefikrealip.XForwardedFor: "10.0.0.1",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			desc:   "Invalid X-Forwarded-For with multiple IPs",
			remote: "10.0.0.1",
			reqHeaders: map[string]string{
				traefikrealip.XForwardedFor: "1.2.3.4, invalid",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "1.2.3.4",
				traefikrealip.XIsTrusted:    "yes",
				traefikrealip.XForwardedFor: "1.2.3.4, invalid",
			},
			expectedStatus: http.StatusOK,
		},
	}
	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			cfg := traefikrealip.CreateConfig()
			cfg.TrustedIPs = test.trustedIPs

			ctx := context.Background()
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

			handler, err := traefikrealip.New(ctx, next, cfg, "traefikrealip")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.RemoteAddr = test.remote + ":12345"

			for key, value := range test.reqHeaders {
				req.Header.Set(key, value)
			}

			handler.ServeHTTP(recorder, req)

			if recorder.Result().StatusCode != test.expectedStatus {
				t.Errorf("expected status %d, got %d. Body: [%s]", test.expectedStatus, recorder.Result().StatusCode, recorder.Body.String())
				return
			}

			if test.expectedStatus != http.StatusOK {
				return
			}

			for key, expectedValue := range test.expectedHeaders {
				assertHeader(t, req, key, expectedValue)
			}
		})
	}
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()
	headerValues := req.Header.Values(key)
	if len(headerValues) == 0 {
		t.Errorf("missing header: %s", key)
		return
	}
	if headerValues[0] != expected {
		t.Errorf("expected header %s to be %s, got %s", key, expected, strings.Join(headerValues, ", "))
	}
}
