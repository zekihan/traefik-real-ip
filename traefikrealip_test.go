package traefik_real_ip_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	traefikrealip "github.com/zekihan/traefik-real-ip"
)

type testCase struct {
	reqHeaders      map[string]string
	expectedHeaders map[string]string
	desc            string
	remote          string
	trustedIPs      []string
	expectedStatus  int
}

func setupTest(
	t *testing.T,
	test *testCase,
) (*httptest.ResponseRecorder, *http.Request, http.Handler) {
	t.Helper()

	cfg := traefikrealip.CreateConfig()
	cfg.TrustedIPs = test.trustedIPs

	ctx := t.Context()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := traefikrealip.New(ctx, next, cfg, "traefikrealip")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"http://localhost",
		http.NoBody,
	)
	if err != nil {
		t.Fatal(err)
	}

	req.RemoteAddr = test.remote + ":12345"

	for key, value := range test.reqHeaders {
		req.Header.Set(key, value)
	}

	return recorder, req, handler
}

func validateTestResult(
	t *testing.T,
	test *testCase,
	recorder *httptest.ResponseRecorder,
	req *http.Request,
) {
	t.Helper()

	if recorder.Result().StatusCode != test.expectedStatus {
		t.Errorf(
			"expected status %d, got %d. Body: [%s]",
			test.expectedStatus,
			recorder.Result().StatusCode,
			recorder.Body.String(),
		)

		return
	}

	if test.expectedStatus != http.StatusOK {
		return
	}

	for key, expectedValue := range test.expectedHeaders {
		assertHeader(t, req, key, expectedValue)
	}
}

func TestIPResolver_BasicCases(t *testing.T) {
	testCases := []*testCase{
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
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			recorder, req, handler := setupTest(t, test)
			handler.ServeHTTP(recorder, req)
			validateTestResult(t, test, recorder, req)
		})
	}
}

func TestIPResolver_CloudflareHeaders(t *testing.T) {
	testCases := []*testCase{
		{
			desc:   "Cf-Connecting-Ip",
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
			desc:   "Local Cf-Connecting-Ip",
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
			desc:   "Cf-Connecting-Ip not trusted",
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
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			recorder, req, handler := setupTest(t, test)
			handler.ServeHTTP(recorder, req)
			validateTestResult(t, test, recorder, req)
		})
	}
}

func TestIPResolver_EdgeOneHeaders(t *testing.T) {
	testCases := []*testCase{
		{
			desc:       "Eo-Connecting-Ip",
			remote:     "198.51.100.10",
			trustedIPs: []string{"198.51.100.0/24"},
			reqHeaders: map[string]string{
				traefikrealip.EoConnectingIP: "1.2.3.4",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "1.2.3.4",
				traefikrealip.XIsTrusted:    "yes",
				traefikrealip.XForwardedFor: "1.2.3.4",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "Local Eo-Connecting-Ip",
			remote: "10.0.0.1",
			reqHeaders: map[string]string{
				traefikrealip.EoConnectingIP: "1.2.3.4",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "1.2.3.4",
				traefikrealip.XIsTrusted:    "yes",
				traefikrealip.XForwardedFor: "1.2.3.4",
			},
			expectedStatus: http.StatusOK,
		},
		{
			desc:   "Eo-Connecting-Ip not trusted",
			remote: "5.6.7.8",
			reqHeaders: map[string]string{
				traefikrealip.EoConnectingIP: "1.2.3.4",
			},
			expectedHeaders: map[string]string{
				traefikrealip.XRealIP:       "5.6.7.8",
				traefikrealip.XIsTrusted:    "no",
				traefikrealip.XForwardedFor: "5.6.7.8",
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			recorder, req, handler := setupTest(t, test)
			handler.ServeHTTP(recorder, req)
			validateTestResult(t, test, recorder, req)
		})
	}
}

func TestIPResolver_StandardHeaders(t *testing.T) {
	testCases := []*testCase{
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
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			recorder, req, handler := setupTest(t, test)
			handler.ServeHTTP(recorder, req)
			validateTestResult(t, test, recorder, req)
		})
	}
}

func TestIPResolver_ForwardedForHeaders(t *testing.T) {
	testCases := []*testCase{
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
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			recorder, req, handler := setupTest(t, test)
			handler.ServeHTTP(recorder, req)
			validateTestResult(t, test, recorder, req)
		})
	}
}

func TestIPResolver_MultipleHeaders(t *testing.T) {
	testCases := []*testCase{
		{
			desc:   "X-Forwarded-For with private IP and Cf-Connecting-Ip",
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
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			recorder, req, handler := setupTest(t, test)
			handler.ServeHTTP(recorder, req)
			validateTestResult(t, test, recorder, req)
		})
	}
}

func TestIPResolver_InvalidHeaders(t *testing.T) {
	testCases := []*testCase{
		{
			desc:   "Invalid Cf-Connecting-Ip",
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
		t.Run(test.desc, func(t *testing.T) {
			recorder, req, handler := setupTest(t, test)
			handler.ServeHTTP(recorder, req)
			validateTestResult(t, test, recorder, req)
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
		t.Errorf(
			"expected header %s to be %s, got %s",
			key,
			expected,
			strings.Join(headerValues, ", "),
		)
	}
}
