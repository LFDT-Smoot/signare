package httpinfra

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func TestMaxBytesMiddleware_RejectsOversizedBody(t *testing.T) {
	const limit int64 = 16

	var readErr error
	var readLen int
	handler := MaxBytesMiddleware(limit)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		readLen = len(body)
		readErr = err
	}))

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("a", int(limit)*4)))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if readErr == nil {
		t.Fatalf("expected a read error for an oversized body, got nil")
	}
	var maxBytesErr *http.MaxBytesError
	if !errors.As(readErr, &maxBytesErr) {
		t.Fatalf("expected *http.MaxBytesError, got %T: %v", readErr, readErr)
	}
	if int64(readLen) > limit {
		t.Fatalf("read %d bytes, exceeds limit %d: the whole payload was buffered", readLen, limit)
	}
}

// TestMaxBytesMiddleware_RejectsOversizedBodyThroughRouter wires the middleware around a mux router
// whose handler decodes JSON from r.Body exactly as the generated REST handlers do, confirming an
// oversized REST body is rejected at decode time while an under-limit body decodes cleanly.
func TestMaxBytesMiddleware_RejectsOversizedBodyThroughRouter(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}

	var decodeErr error
	router := mux.NewRouter()
	router.HandleFunc("/things", func(_ http.ResponseWriter, r *http.Request) {
		var p payload
		decodeErr = json.NewDecoder(r.Body).Decode(&p)
	}).Methods(http.MethodPost)

	const limit int64 = 32
	handler := MaxBytesMiddleware(limit)(router)

	oversized := `{"name":"` + strings.Repeat("a", int(limit)*4) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/things", strings.NewReader(oversized))
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if decodeErr == nil {
		t.Fatalf("expected decode to fail for an oversized body, got nil")
	}
	var maxBytesErr *http.MaxBytesError
	if !errors.As(decodeErr, &maxBytesErr) {
		t.Fatalf("expected *http.MaxBytesError, got %T: %v", decodeErr, decodeErr)
	}

	decodeErr = errors.New("handler not run")
	req = httptest.NewRequest(http.MethodPost, "/things", strings.NewReader(`{"name":"ok"}`))
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if decodeErr != nil {
		t.Fatalf("unexpected decode error for an under-limit body: %v", decodeErr)
	}
}

func TestMaxBytesMiddleware_AllowsUnderLimitBody(t *testing.T) {
	const limit int64 = 1024
	const body = "hello world"

	var got string
	var readErr error
	handler := MaxBytesMiddleware(limit)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		got = string(b)
		readErr = err
	}))

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if readErr != nil {
		t.Fatalf("unexpected error for an under-limit body: %v", readErr)
	}
	if got != body {
		t.Fatalf("got body %q, want %q", got, body)
	}
}

func TestMaxBytesMiddleware_ZeroLimitLeavesBodyUnbounded(t *testing.T) {
	var readErr error
	handler := MaxBytesMiddleware(0)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("a", 1<<16)))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if readErr != nil {
		t.Fatalf("expected no limit to be enforced for a zero limit, got %v", readErr)
	}
}
