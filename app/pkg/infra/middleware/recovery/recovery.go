// Package recovery provides a protocol-agnostic middleware that recovers panics
// in the request handling chain and returns a clean error response instead of
// leaking a stack trace or dropping the connection.
package recovery

import (
	"errors"
	"net/http"
	"runtime/debug"

	"github.com/hyperledger-labs/signare/app/pkg/commons/logger"
	"github.com/hyperledger-labs/signare/app/pkg/infra/httpinfra"
)

// Handle wraps the next handler with a deferred recover. A recovered panic is
// logged server-side together with its stack trace and translated into a clean
// error response via the configured HTTPResponseHandler. The stack trace is
// never written to the client. If the wrapped handler already wrote part of a
// response before panicking, the error response is skipped to avoid corrupting
// what was already sent (a partial response cannot be unwritten).
func (m *RecoveryMiddleware) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &recordingResponseWriter{ResponseWriter: w}
		defer func() {
			if rec := recover(); rec != nil {
				ctx := r.Context()
				logger.LogEntry(ctx).Errorf("recovered from panic serving request: %v\n%s", rec, debug.Stack())
				if rw.wrote {
					return
				}
				m.responseHandler.HandleErrorResponse(ctx, rw, httpinfra.NewHTTPError(httpinfra.StatusInternal))
			}
		}()
		next.ServeHTTP(rw, r)
	})
}

// recordingResponseWriter tracks whether the wrapped handler has written any
// part of the response so the recovery handler can avoid a double write.
type recordingResponseWriter struct {
	http.ResponseWriter
	wrote bool
}

func (w *recordingResponseWriter) WriteHeader(statusCode int) {
	w.wrote = true
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *recordingResponseWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}

// RecoveryMiddleware recovers panics in the request handling chain.
type RecoveryMiddleware struct {
	responseHandler httpinfra.HTTPResponseHandler
}

// RecoveryMiddlewareOptions are the set of fields to create a RecoveryMiddleware.
type RecoveryMiddlewareOptions struct {
	// ResponseHandler exposes functionality to handle the error response when a panic is recovered.
	ResponseHandler httpinfra.HTTPResponseHandler
}

// ProvideRecoveryMiddleware provides an instance of a RecoveryMiddleware.
func ProvideRecoveryMiddleware(options RecoveryMiddlewareOptions) (*RecoveryMiddleware, error) {
	if options.ResponseHandler == nil {
		return nil, errors.New("mandatory 'ResponseHandler' not provided")
	}
	return &RecoveryMiddleware{
		responseHandler: options.ResponseHandler,
	}, nil
}
