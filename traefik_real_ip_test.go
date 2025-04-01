package traefik_real_ip_test

import (
	"context"
	"github.com/zekihan/traefik-real-ip"
	"github.com/zekihan/traefik-real-ip/helpers"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIPResolver_ServeHTTP(t *testing.T) {
	testCases := []struct {
		desc            string
		remote          string
		reqHeaders      map[string]string
		expectedHeaders map[string]string
		expectedStatus  int
	}{
		{
			desc:       "No headers",
			remote:     "1.2.3.4",
			reqHeaders: map[string]string{},
			expectedHeaders: map[string]string{
				helpers.X_REAL_IP:       "1.2.3.4",
				helpers.X_IS_TRUSTED:    "no",
				helpers.X_FORWARDED_FOR: "1.2.3.4",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:       "No headers ipv6",
			remote:     "[1001:3984:3989::1]",
			reqHeaders: map[string]string{},
			expectedHeaders: map[string]string{
				helpers.X_REAL_IP:       "1001:3984:3989::1",
				helpers.X_IS_TRUSTED:    "no",
				helpers.X_FORWARDED_FOR: "1001:3984:3989::1",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:            "Invalid RemoteAddr",
			remote:          "103.21.244",
			reqHeaders:      map[string]string{},
			expectedHeaders: map[string]string{},
			expectedStatus:  http.StatusBadRequest,
		},
		{
			desc:   "CF Origin",
			remote: "103.21.244.23",
			reqHeaders: map[string]string{
				helpers.CF_CONNECTING_IP: "1.2.3.4",
			},
			expectedHeaders: map[string]string{
				helpers.X_REAL_IP:       "1.2.3.4",
				helpers.X_IS_TRUSTED:    "yes",
				helpers.X_FORWARDED_FOR: "1.2.3.4",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "X-Real-IP",
			remote: "1.1.1.1",
			reqHeaders: map[string]string{
				helpers.X_REAL_IP: "1.2.3.4",
			},
			expectedHeaders: map[string]string{
				helpers.X_REAL_IP:       "1.2.3.4",
				helpers.X_IS_TRUSTED:    "no",
				helpers.X_FORWARDED_FOR: "1.2.3.4",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "X-Forwarded-For",
			remote: "1.1.1.1",
			reqHeaders: map[string]string{
				helpers.X_FORWARDED_FOR: "1.2.3.4",
			},
			expectedHeaders: map[string]string{
				helpers.X_REAL_IP:       "1.2.3.4",
				helpers.X_IS_TRUSTED:    "no",
				helpers.X_FORWARDED_FOR: "1.2.3.4",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "X-Forwarded-For with multiple IPs",
			remote: "1.1.1.1",
			reqHeaders: map[string]string{
				helpers.X_FORWARDED_FOR: "1.2.3.4, 1.1.1.1",
			},
			expectedHeaders: map[string]string{
				helpers.X_REAL_IP:       "1.2.3.4",
				helpers.X_IS_TRUSTED:    "no",
				helpers.X_FORWARDED_FOR: "1.2.3.4, 1.1.1.1",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "X-Forwarded-For with private IP",
			remote: "1.1.1.1",
			reqHeaders: map[string]string{
				helpers.X_FORWARDED_FOR: "192.168.1.1, 1.2.3.4",
			},
			expectedHeaders: map[string]string{
				helpers.X_REAL_IP:       "1.2.3.4",
				helpers.X_IS_TRUSTED:    "no",
				helpers.X_FORWARDED_FOR: "1.2.3.4, 192.168.1.1",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "X-Forwarded-For with private IP",
			remote: "1.1.1.1",
			reqHeaders: map[string]string{
				helpers.X_FORWARDED_FOR:  "1.2.3.4, 192.168.1.1",
				helpers.CF_CONNECTING_IP: "1.2.3.4",
			},
			expectedHeaders: map[string]string{
				helpers.X_REAL_IP:       "1.2.3.4",
				helpers.X_IS_TRUSTED:    "no",
				helpers.X_FORWARDED_FOR: "1.2.3.4, 192.168.1.1",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "ipv6 source ipv4",
			remote: "103.21.244.23",
			reqHeaders: map[string]string{
				helpers.CF_CONNECTING_IP: "1001:3984:3989::1",
			},
			expectedHeaders: map[string]string{
				helpers.X_REAL_IP:       "1001:3984:3989::1",
				helpers.X_IS_TRUSTED:    "yes",
				helpers.X_FORWARDED_FOR: "1001:3984:3989::1",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "ipv6 source ipv6",
			remote: "[1001:3984:3989::1]",
			reqHeaders: map[string]string{
				helpers.CF_CONNECTING_IP: "1001:3984:3989::1",
			},
			expectedHeaders: map[string]string{
				helpers.X_REAL_IP:       "1001:3984:3989::1",
				helpers.X_IS_TRUSTED:    "no",
				helpers.X_FORWARDED_FOR: "1001:3984:3989::1",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "Invalid CF-Connecting-IP",
			remote: "103.21.244.23",
			reqHeaders: map[string]string{
				helpers.CF_CONNECTING_IP: "1.2.3",
			},
			expectedHeaders: map[string]string{},
			expectedStatus:  http.StatusBadRequest,
		},
		{
			desc:   "Local CF-Connecting-IP",
			remote: "10.0.0.1",
			reqHeaders: map[string]string{
				helpers.CF_CONNECTING_IP: "1.2.3.4",
			},
			expectedHeaders: map[string]string{
				helpers.X_REAL_IP:       "1.2.3.4",
				helpers.X_IS_TRUSTED:    "yes",
				helpers.X_FORWARDED_FOR: "1.2.3.4",
			},
			expectedStatus: http.StatusOK,
		},
	}
	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			cfg := traefik_real_ip.CreateConfig()

			ctx := context.Background()
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

			handler, err := traefik_real_ip.New(ctx, next, cfg, "traefikrealip")
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
				t.Errorf("expected status %d, got %d. Body: [%s]", test.expectedStatus, recorder.Result().StatusCode, string(recorder.Body.Bytes()))
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
		t.Errorf("expected header %s to be %s, got %s", key, expected, headerValues[0])
	}
}
