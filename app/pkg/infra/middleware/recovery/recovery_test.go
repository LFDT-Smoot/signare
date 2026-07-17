package recovery_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger-labs/signare/app/pkg/infra/httpinfra"
	"github.com/hyperledger-labs/signare/app/pkg/infra/middleware/recovery"

	"github.com/stretchr/testify/require"
)

// stubResponseHandler records whether the error path was invoked and writes the
// error code so the recorded response can be asserted on.
type stubResponseHandler struct {
	errorCalled bool
	received    *httpinfra.HTTPError
}

func (s *stubResponseHandler) HandleErrorResponse(_ context.Context, w http.ResponseWriter, receivedError *httpinfra.HTTPError) {
	s.errorCalled = true
	s.received = receivedError
	w.WriteHeader(receivedError.Code())
}

func (s *stubResponseHandler) HandleSuccessResponse(_ context.Context, _ http.ResponseWriter, _ httpinfra.ResponseInfo, _ any) {
}

func TestRecoveryMiddleware_RecoversPanic(t *testing.T) {
	stub := &stubResponseHandler{}
	mw, err := recovery.ProvideRecoveryMiddleware(recovery.RecoveryMiddlewareOptions{ResponseHandler: stub})
	require.NoError(t, err)

	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})
	handler := mw.Handle(panicking)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)

	require.NotPanics(t, func() {
		handler.ServeHTTP(rec, req)
	})
	require.True(t, stub.errorCalled)
	require.Equal(t, http.StatusInternalServerError, stub.received.Code())
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	// The stack trace must never be written to the client.
	require.NotContains(t, rec.Body.String(), "boom")
}

func TestRecoveryMiddleware_SkipsErrorResponseAfterPartialWrite(t *testing.T) {
	stub := &stubResponseHandler{}
	mw, err := recovery.ProvideRecoveryMiddleware(recovery.RecoveryMiddlewareOptions{ResponseHandler: stub})
	require.NoError(t, err)

	partialThenPanic := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
		panic("boom")
	})
	handler := mw.Handle(partialThenPanic)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)

	require.NotPanics(t, func() {
		handler.ServeHTTP(rec, req)
	})
	// A response was already partially written, so the backstop must not write again.
	require.False(t, stub.errorCalled)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "partial", rec.Body.String())
}

func TestRecoveryMiddleware_PassesThroughWhenNoPanic(t *testing.T) {
	stub := &stubResponseHandler{}
	mw, err := recovery.ProvideRecoveryMiddleware(recovery.RecoveryMiddlewareOptions{ResponseHandler: stub})
	require.NoError(t, err)

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	handler := mw.Handle(ok)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	handler.ServeHTTP(rec, req)

	require.False(t, stub.errorCalled)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "ok", rec.Body.String())
}

func TestProvideRecoveryMiddleware_RequiresResponseHandler(t *testing.T) {
	_, err := recovery.ProvideRecoveryMiddleware(recovery.RecoveryMiddlewareOptions{})
	require.Error(t, err)
}
