package rpccontextdefinition_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hyperledger-labs/signare/app/pkg/infra/httpinfra"
	"github.com/hyperledger-labs/signare/app/pkg/infra/middleware/authentication/contextdefinition/rpccontextdefinition"
	"github.com/hyperledger-labs/signare/app/pkg/infra/rpcinfra"

	"github.com/stretchr/testify/require"
)

// newMiddlewareWithRealHandler builds an RPCContextDefinition backed by the real response handler so
// the error responses it emits can be inspected, plus a router carrying the registered method and the
// POST-only "/" route named like the real publisher.
func newMiddlewareWithRealHandler(t *testing.T) *rpccontextdefinition.RPCContextDefinition {
	t.Helper()

	router := rpcinfra.ProvideDefaultRPCRouter(rpcinfra.DefaultRPCRouterOptions{})
	require.NoError(t, router.RegisterRPCHandlerFunc(registeredMethod, nil))
	router.Router().HandleFunc("/", router.HandleRPCRequest).Methods(http.MethodPost).Name(rpcRouteName)

	handler, err := httpinfra.ProvideDefaultHTTPResponseHandler(httpinfra.DefaultHTTPResponseHandlerOptions{
		HTTPMetrics: httpinfra.DefaultHTTPMetrics{},
	})
	require.NoError(t, err)

	middleware, err := rpccontextdefinition.ProvideRPCContextDefinitionFromHeaders(rpccontextdefinition.RPCContextDefinitionOptions{
		ResponseHandler: handler,
		RPCRouter:       router,
	})
	require.NoError(t, err)
	return middleware
}

func failingNext(t *testing.T) http.Handler {
	return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler must not run when DefineAction fails")
	})
}

// TestDefineAction_NoMatch_ReturnsNotFound checks the RPC twin of the HTTP no-match fix: a request that
// does not match the registered route yields an explicit 404 with a body rather than an empty 200, and
// does not invoke the next handler. A GET against the POST-only route produces a method mismatch.
func TestDefineAction_NoMatch_ReturnsNotFound(t *testing.T) {
	middleware := newMiddlewareWithRealHandler(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	middleware.DefineAction(failingNext(t)).ServeHTTP(rr, req)

	require.Equal(t, http.StatusNotFound, rr.Code)
	require.NotEmpty(t, rr.Body.String(), "no-match must not produce an empty body")
}

// TestDefineAction_BodyReadError_GenericForbidden checks the body-read error path on a matched route is
// denied with the constant generic message rather than the raw parse error.
func TestDefineAction_BodyReadError_GenericForbidden(t *testing.T) {
	middleware := newMiddlewareWithRealHandler(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{ not valid json"))
	middleware.DefineAction(failingNext(t)).ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
	var resp httpinfra.ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, "request not authorized", resp.Details.Message)
}
