package httpinfra

import (
	"net/http"
)

// MaxBytesMiddleware returns a middleware that bounds the request body to limit bytes by wrapping
// it in http.MaxBytesReader. Once a downstream reader exceeds limit, its Read returns an error and
// no more than ~limit bytes are buffered, preventing unbounded allocation from an oversized body.
//
// It is intended to be the outermost wrapper around an entrypoint's handler so that every downstream
// read, including reads that happen before authentication, is bounded. A limit of zero or less leaves
// the body unbounded.
func MaxBytesMiddleware(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if limit > 0 && r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}
