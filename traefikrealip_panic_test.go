package traefik_real_ip

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

var (
	errTestPanicValue     = errors.New("test panic error")
	errTestReflectedValue = errors.New("reflected error")
	errTestPlainPanic     = errors.New("test panic")
)

func TestGetPanicError(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		err := getPanicError(nil)
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("error type returns same error", func(t *testing.T) {
		err := getPanicError(errTestPanicValue)
		if !errors.Is(err, errTestPanicValue) {
			t.Errorf("expected %v, got %v", errTestPanicValue, err)
		}
	})

	t.Run("reflect.Value of error extracts error", func(t *testing.T) {
		orig := errTestReflectedValue
		rv := reflect.ValueOf(orig)

		err := getPanicError(rv)
		if err == nil {
			t.Fatal("expected non-nil error")
		}

		if err.Error() != orig.Error() {
			t.Errorf("expected %q, got %q", orig.Error(), err.Error())
		}
	})

	t.Run("unknown type returns ErrPanic wrapper", func(t *testing.T) {
		err := getPanicError("some panic string")
		if err == nil {
			t.Fatal("expected non-nil error")
		}

		if !errors.Is(err, ErrPanic) {
			t.Errorf("expected ErrPanic wrapper, got %v", err)
		}
	})
}

func newPanicResolver(t *testing.T, next http.Handler) *IPResolver {
	t.Helper()

	return &IPResolver{
		logger:        NewPluginLogger(t.Context(), "test", LogLevelDebug),
		conf:          &Config{DenyUntrusted: false},
		name:          "test",
		trustedIPNets: nil,
		next:          next,
	}
}

func TestHandlePanic_PlainError(t *testing.T) {
	callCount := 0
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		callCount++
		if callCount == 1 {
			panic(errTestPlainPanic)
		}

		rw.WriteHeader(http.StatusOK)
	})

	resolver := newPanicResolver(t, next)

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"http://localhost",
		http.NoBody,
	)
	req.RemoteAddr = "1.2.3.4:1234"
	recorder := httptest.NewRecorder()

	resolver.ServeHTTP(recorder, req)

	if callCount != 2 {
		t.Errorf("expected next called 2 times, got %d", callCount)
	}

	if recorder.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", recorder.Code)
	}
}

func TestHandlePanic_AbortHandlerRetry(t *testing.T) {
	callCount := 0
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		callCount++
		if callCount == 1 {
			panic(http.ErrAbortHandler)
		}

		rw.WriteHeader(http.StatusOK)
	})

	resolver := newPanicResolver(t, next)

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"http://localhost",
		http.NoBody,
	)
	req.RemoteAddr = "1.2.3.4:1234"
	recorder := httptest.NewRecorder()

	resolver.ServeHTTP(recorder, req)

	if callCount != 2 {
		t.Errorf("expected next called 2 times, got %d", callCount)
	}

	if recorder.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", recorder.Code)
	}
}

func TestHandlePanic_AbortHandlerMaxRetryExceeded(t *testing.T) {
	callCount := 0
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		callCount++
		if callCount == 1 {
			panic(http.ErrAbortHandler)
		}

		rw.WriteHeader(http.StatusOK)
	})

	resolver := newPanicResolver(t, next)

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"http://localhost",
		http.NoBody,
	)
	req.RemoteAddr = "1.2.3.4:1234"
	req = req.WithContext(context.WithValue(req.Context(), RetryCountKey, MaxRetryCount+1))
	recorder := httptest.NewRecorder()

	resolver.ServeHTTP(recorder, req)

	if callCount != 2 {
		t.Errorf("expected next called 2 times, got %d", callCount)
	}

	if recorder.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", recorder.Code)
	}
}
