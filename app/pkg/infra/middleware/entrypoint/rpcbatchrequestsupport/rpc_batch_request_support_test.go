package rpcbatchrequestsupport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/infra/httpinfra"
)

type fakeResponseHandler struct {
	errorCalled bool
	lastError   *httpinfra.HTTPError
}

func (f *fakeResponseHandler) HandleErrorResponse(_ context.Context, w http.ResponseWriter, receivedError *httpinfra.HTTPError) {
	f.errorCalled = true
	f.lastError = receivedError
	w.WriteHeader(http.StatusBadRequest)
}

func (f *fakeResponseHandler) HandleSuccessResponse(_ context.Context, _ http.ResponseWriter, _ httpinfra.ResponseInfo, _ interface{}) {
}

func batchBody(t *testing.T, n int) []byte {
	t.Helper()
	batch := make([]RPCRequest, n)
	for i := range batch {
		batch[i] = RPCRequest{RPCVersion: "2.0", Method: "eth_blockNumber", ID: i}
	}
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshalling batch of %d: %v", n, err)
	}
	return body
}

func TestFanOutRPCBatchRequest_RejectsOversizedBatch(t *testing.T) {
	handler := &fakeResponseHandler{}
	middleware := &RPCBatchRequestSupportMiddleware{responseHandler: handler}

	nextCalls := 0
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalls++ })

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(batchBody(t, maxBatchElements+1)))
	middleware.FanOutRPCBatchRequest(next).ServeHTTP(httptest.NewRecorder(), req)

	if !handler.errorCalled {
		t.Fatalf("expected an error response for a batch exceeding %d elements", maxBatchElements)
	}
	if nextCalls != 0 {
		t.Fatalf("next handler invoked %d times, expected 0 for a rejected batch", nextCalls)
	}
	wantMsg := fmt.Sprintf("batch request exceeds the maximum of %d elements", maxBatchElements)
	if got := handler.lastError.Error(); got != wantMsg {
		t.Fatalf("client message = %q, want %q", got, wantMsg)
	}
}

func TestFanOutRPCBatchRequest_RejectsEmptyBatch(t *testing.T) {
	handler := &fakeResponseHandler{}
	middleware := &RPCBatchRequestSupportMiddleware{responseHandler: handler}

	nextCalls := 0
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalls++ })

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("[]")))
	middleware.FanOutRPCBatchRequest(next).ServeHTTP(httptest.NewRecorder(), req)

	if !handler.errorCalled {
		t.Fatalf("expected an error response for an empty batch")
	}
	if nextCalls != 0 {
		t.Fatalf("next handler invoked %d times, expected 0 for an empty batch", nextCalls)
	}
	if got, want := handler.lastError.Error(), "batch request must contain at least one element"; got != want {
		t.Fatalf("client message = %q, want %q", got, want)
	}
}

func TestFanOutRPCBatchRequest_FansOutValidBatch(t *testing.T) {
	handler := &fakeResponseHandler{}
	middleware := &RPCBatchRequestSupportMiddleware{responseHandler: handler}

	nextCalls := 0
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalls++ })

	const n = 3
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(batchBody(t, n)))
	middleware.FanOutRPCBatchRequest(next).ServeHTTP(httptest.NewRecorder(), req)

	if handler.errorCalled {
		t.Fatalf("unexpected error response for a valid batch: %+v", handler.lastError)
	}
	if nextCalls != n {
		t.Fatalf("next handler invoked %d times, expected %d", nextCalls, n)
	}
}

// TestFanOutRPCBatchRequest_BoundedByMaxBytesMiddleware exercises the headline vector: an oversized
// body must be rejected at the pre-authentication batch read once MaxBytesMiddleware wraps the body,
// without the whole payload being buffered or fanned out.
func TestFanOutRPCBatchRequest_BoundedByMaxBytesMiddleware(t *testing.T) {
	handler := &fakeResponseHandler{}
	middleware := &RPCBatchRequestSupportMiddleware{responseHandler: handler}

	nextCalls := 0
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalls++ })

	const limit int64 = 64
	wrapped := httpinfra.MaxBytesMiddleware(limit)(middleware.FanOutRPCBatchRequest(next))

	oversized := RPCRequest{
		RPCVersion: "2.0",
		Method:     "eth_call",
		ID:         1,
		Params:     json.RawMessage(`"` + strings.Repeat("a", int(limit)*4) + `"`),
	}
	body, err := json.Marshal(oversized)
	if err != nil {
		t.Fatalf("marshalling oversized request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	wrapped.ServeHTTP(httptest.NewRecorder(), req)

	if !handler.errorCalled {
		t.Fatalf("expected an oversized body to be rejected before fan-out")
	}
	if nextCalls != 0 {
		t.Fatalf("next handler invoked %d times, expected 0 for an oversized body", nextCalls)
	}
	if got := handler.lastError.Error(); got != bodyTooLargeMessage {
		t.Fatalf("client message = %q, want %q", got, bodyTooLargeMessage)
	}
}
