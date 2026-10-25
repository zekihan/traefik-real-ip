package traefik_real_ip

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNew_PanicPolicy(t *testing.T) {
	if got := CreateConfig().PanicPolicy; got != PanicPolicyLegacyRetry {
		t.Fatalf("default policy = %q, want legacy compatibility", got)
	}

	for _, policy := range []string{"", PanicPolicyLegacyRetry, PanicPolicyPropagate, "invalid"} {
		t.Run(policy, func(t *testing.T) {
			cfg := new(Config)
			cfg.PanicPolicy = policy

			handler, err := New(t.Context(), http.NotFoundHandler(), cfg, "test")
			if policy == "invalid" {
				if !errors.Is(err, ErrInvalidPanicPolicy) || handler != nil {
					t.Fatalf("invalid policy: handler = %v, error = %v", handler, err)
				}

				return
			}

			if err != nil || handler == nil {
				t.Fatalf("valid policy: handler = %v, error = %v", handler, err)
			}

			recorder := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			req.RemoteAddr = "192.0.2.1:1234"
			handler.ServeHTTP(recorder, req)

			if recorder.Code != http.StatusNotFound {
				t.Errorf("normal downstream response = %d, want 404", recorder.Code)
			}
		})
	}
}

func TestPanicPolicy_PropagateOriginalValue(t *testing.T) {
	cases := map[string]any{
		"string panic":             "synthetic panic",
		"reflected abort":          reflect.ValueOf(http.ErrAbortHandler),
		"reflected ordinary panic": reflect.ValueOf(errTestPlainPanic),
	}

	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				calls++

				panic(value)
			})
			resolver := newPanicResolver(t, next)
			resolver.conf.PanicPolicy = PanicPolicyPropagate
			recorder := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			req.RemoteAddr = "192.0.2.1:1234"

			var recovered any

			func() {
				defer func() { recovered = recover() }()

				resolver.ServeHTTP(recorder, req)
			}()

			if recovered != value || calls != 1 || recorder.Body.Len() != 0 {
				t.Errorf("panic=%v calls=%d body=%q, want original panic, one call and no response",
					recovered, calls, recorder.Body.String())
			}
		})
	}
}

type replayScenario struct {
	panicValue  error
	name        string
	readLimit   int64
	retryCount  int
	legacyCalls int
	partial     bool
	cancel      bool
	repeated    bool
}

type replayResult struct {
	panicValue  any
	recorder    *httptest.ResponseRecorder
	bodies      []string
	canceled    []bool
	calls       int
	sideEffects int
}

func TestPanicPolicy_RequestReplay(t *testing.T) {
	tests := []replayScenario{
		{
			panicValue:  errTestPlainPanic,
			name:        "consumed POST ordinary panic",
			readLimit:   0,
			retryCount:  0,
			legacyCalls: 2,
			partial:     false,
			cancel:      false,
			repeated:    false,
		},
		{
			panicValue:  http.ErrAbortHandler,
			name:        "consumed POST abort",
			readLimit:   0,
			retryCount:  0,
			legacyCalls: 2,
			partial:     false,
			cancel:      false,
			repeated:    false,
		},
		{
			panicValue:  errTestPlainPanic,
			name:        "partially consumed POST",
			readLimit:   3,
			retryCount:  0,
			legacyCalls: 2,
			partial:     false,
			cancel:      false,
			repeated:    false,
		},
		{
			panicValue:  errTestPlainPanic,
			name:        "partial response ordinary panic",
			readLimit:   0,
			retryCount:  0,
			legacyCalls: 2,
			partial:     true,
			cancel:      false,
			repeated:    false,
		},
		{
			panicValue:  http.ErrAbortHandler,
			name:        "partial response abort",
			readLimit:   0,
			retryCount:  0,
			legacyCalls: 2,
			partial:     true,
			cancel:      false,
			repeated:    false,
		},
		{
			panicValue:  errTestPlainPanic,
			name:        "canceled ordinary panic",
			readLimit:   0,
			retryCount:  0,
			legacyCalls: 2,
			partial:     false,
			cancel:      true,
			repeated:    false,
		},
		{
			panicValue:  http.ErrAbortHandler,
			name:        "canceled abort",
			readLimit:   0,
			retryCount:  0,
			legacyCalls: 2,
			partial:     false,
			cancel:      true,
			repeated:    false,
		},
		{
			panicValue:  http.ErrAbortHandler,
			name:        "repeated abort",
			readLimit:   0,
			retryCount:  0,
			legacyCalls: MaxRetryCount + 2,
			partial:     false,
			cancel:      false,
			repeated:    true,
		},
		{
			panicValue:  http.ErrAbortHandler,
			name:        "abort beyond retry limit",
			readLimit:   0,
			retryCount:  MaxRetryCount + 1,
			legacyCalls: 2,
			partial:     false,
			cancel:      false,
			repeated:    false,
		},
	}

	for _, test := range tests {
		for _, policy := range []string{"", PanicPolicyLegacyRetry, PanicPolicyPropagate} {
			t.Run(test.name+"/"+policy, func(t *testing.T) {
				got := runReplayScenario(t, test, policy)
				assertReplayResult(t, test, policy, got)
			})
		}
	}
}

func runReplayScenario(t *testing.T, test replayScenario, policy string) *replayResult {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	if test.retryCount > 0 {
		ctx = context.WithValue(ctx, RetryCountKey, test.retryCount)
	}

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/", strings.NewReader("payload"))
	req.RemoteAddr = "192.0.2.1:1234"
	result := new(replayResult)
	result.recorder = httptest.NewRecorder()
	resolver := newPanicResolver(t, replayHandler(t, test, result, cancel))
	resolver.conf.PanicPolicy = policy

	func() {
		defer func() { result.panicValue = recover() }()

		resolver.ServeHTTP(result.recorder, req)
	}()

	return result
}

func replayHandler(
	t *testing.T,
	test replayScenario,
	result *replayResult,
	cancel context.CancelFunc,
) http.Handler {
	t.Helper()

	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		result.calls++

		reader := io.Reader(req.Body)
		if test.readLimit > 0 {
			reader = io.LimitReader(reader, test.readLimit)
		}

		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("read synthetic body: %v", err)
		}

		result.bodies = append(result.bodies, string(body))
		// Model a committed downstream action before the panic.
		result.sideEffects++

		if test.cancel {
			cancel()
		}

		result.canceled = append(result.canceled, errors.Is(req.Context().Err(), context.Canceled))

		if result.calls == 1 && test.partial {
			rw.Header().Set("X-Started", "yes")
			rw.WriteHeader(http.StatusAccepted)
			_, _ = rw.Write([]byte("partial:"))
		}

		if result.calls == 1 || test.repeated {
			panic(test.panicValue)
		}

		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("completed"))
	})
}

func assertReplayResult(t *testing.T, test replayScenario, policy string, got *replayResult) {
	t.Helper()

	wantCalls := test.legacyCalls
	wantPanic := test.repeated
	wantBody := "completed"

	if policy == PanicPolicyPropagate {
		wantCalls, wantPanic, wantBody = 1, true, ""
	}

	if test.partial {
		wantBody = "partial:" + wantBody
	}

	if test.repeated {
		wantBody = ""
	}

	if got.calls != wantCalls || got.sideEffects != wantCalls {
		t.Errorf(
			"invocations = %d, side effects = %d; want %d",
			got.calls,
			got.sideEffects,
			wantCalls,
		)
	}

	var expectedPanic any
	if wantPanic {
		expectedPanic = test.panicValue
	}

	// Compare identity, rather than unwrapping errors: propagation must retain the panic value.
	if got.panicValue != expectedPanic {
		t.Errorf("panic = %v, want original %v", got.panicValue, expectedPanic)
	}

	assertReplayInput(t, test, got, wantCalls)

	wantStatus := http.StatusOK // Recorder's default; propagation writes no response.
	if test.partial {
		wantStatus = http.StatusAccepted
	}

	if got.recorder.Code != wantStatus || got.recorder.Body.String() != wantBody {
		t.Errorf(
			"response = %d %q, want %d %q",
			got.recorder.Code,
			got.recorder.Body.String(),
			wantStatus,
			wantBody,
		)
	}

	t.Logf(
		"policy=%q invocations=%d effects=%d bodies=%q panic=%v status=%d body=%q",
		policy,
		got.calls,
		got.sideEffects,
		got.bodies,
		got.panicValue,
		got.recorder.Code,
		got.recorder.Body.String(),
	)
}

func assertReplayInput(t *testing.T, test replayScenario, got *replayResult, wantCalls int) {
	t.Helper()

	wantBodies := make([]string, wantCalls)
	wantBodies[0] = "payload"

	if test.readLimit > 0 {
		wantBodies[0] = "pay"
		if wantCalls > 1 {
			wantBodies[1] = "loa"
		}
	}

	if !reflect.DeepEqual(got.bodies, wantBodies) {
		t.Errorf("consumed bodies = %q, want %q", got.bodies, wantBodies)
	}

	for _, canceled := range got.canceled {
		if canceled != test.cancel {
			t.Errorf("canceled = %v, want %v", canceled, test.cancel)
		}
	}
}

func TestPanicPolicy_PropagateHTTPResponse(t *testing.T) {
	for _, panicValue := range []error{errTestPlainPanic, http.ErrAbortHandler} {
		for _, partial := range []bool{false, true} {
			name := panicValue.Error() + "/" + map[bool]string{false: "unwritten", true: "flushed partial"}[partial]
			t.Run(name, func(t *testing.T) {
				checkPropagatedHTTPResponse(t, panicValue, partial)
			})
		}
	}
}

func checkPropagatedHTTPResponse(t *testing.T, panicValue error, partial bool) {
	t.Helper()

	var calls atomic.Int32

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		calls.Add(1)

		if partial {
			rw.Header().Set("Content-Length", "100")
			rw.WriteHeader(http.StatusAccepted)
			_, _ = rw.Write([]byte("partial:"))

			err := http.NewResponseController(rw).Flush()
			if err != nil {
				t.Errorf("flush synthetic response: %v", err)
			}
		}

		panic(panicValue)
	})
	resolver := newPanicResolver(t, next)
	resolver.conf.PanicPolicy = PanicPolicyPropagate
	server := httptest.NewUnstartedServer(resolver)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Start()

	defer server.Close()

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		server.URL,
		strings.NewReader("payload"),
	)
	req.RequestURI = ""

	response, err := server.Client().Do(req)
	if response != nil {
		defer func() {
			closeErr := response.Body.Close()
			if closeErr != nil {
				t.Errorf("close synthetic response: %v", closeErr)
			}
		}()
	}

	assertHTTPResponse(t, partial, response, err)

	if got := calls.Load(); got != 1 {
		t.Errorf("downstream invocations = %d, want 1", got)
	}
}

func assertHTTPResponse(t *testing.T, partial bool, response *http.Response, err error) {
	t.Helper()

	if !partial {
		if err == nil || response != nil {
			t.Error("expected connection abort and no response before headers")
		}

		return
	}

	if err != nil {
		t.Fatalf("read partial response headers: %v", err)
	}

	body, readErr := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusAccepted || string(body) != "partial:" ||
		!errors.Is(readErr, io.ErrUnexpectedEOF) {
		t.Errorf(
			"response = %d %q %v, want 202 partial body and unexpected EOF",
			response.StatusCode,
			body,
			readErr,
		)
	}
}
