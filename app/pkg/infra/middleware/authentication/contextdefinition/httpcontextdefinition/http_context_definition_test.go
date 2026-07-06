package httpcontextdefinition_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger-labs/signare/app/pkg/infra/httpinfra"
	"github.com/hyperledger-labs/signare/app/pkg/infra/middleware/authentication/contextdefinition/httpcontextdefinition"
	"github.com/hyperledger-labs/signare/app/pkg/infra/requestcontext"

	"github.com/stretchr/testify/require"
)

func newContextDefinition(t *testing.T, router httpinfra.HTTPRouter) *httpcontextdefinition.HTTPContextDefinition {
	t.Helper()

	handler, err := httpinfra.ProvideDefaultHTTPResponseHandler(httpinfra.DefaultHTTPResponseHandlerOptions{
		HTTPMetrics: httpinfra.DefaultHTTPMetrics{},
	})
	require.NoError(t, err)

	definition, err := httpcontextdefinition.ProvideHTTPContextDefinition(httpcontextdefinition.HTTPContextDefinitionOptions{
		HTTPRouter:      router,
		ResponseHandler: handler,
	})
	require.NoError(t, err)
	return definition
}

// TestDefineAction_NoMatch_ReturnsNotFound checks a router no-match yields an explicit 404 with a body
// rather than the previous bare empty 200, and does not invoke the next handler.
func TestDefineAction_NoMatch_ReturnsNotFound(t *testing.T) {
	router := httpinfra.ProvideHTTPRouter() // empty router: nothing matches
	definition := newContextDefinition(t, router)

	nextCalled := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true })

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/no-such-route", nil)
	definition.DefineAction(next).ServeHTTP(rr, req)

	require.False(t, nextCalled, "next handler must not run on a router no-match")
	require.Equal(t, http.StatusNotFound, rr.Code)
	require.NotEmpty(t, rr.Body.String(), "no-match must not produce an empty body")
}

// TestDefineAction_Match_SetsActionAndCallsNext is a happy-path regression guard: a matched route sets
// the action in context and the request proceeds.
func TestDefineAction_Match_SetsActionAndCallsNext(t *testing.T) {
	router := httpinfra.ProvideHTTPRouter()
	const actionName = "test.action"
	require.NoError(t, router.RegisterHandlerFunc(httpinfra.HandlerMatchOptions{
		Path:    "/resource",
		Methods: []string{http.MethodGet},
		Action:  actionName,
	}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))

	definition := newContextDefinition(t, router)

	var capturedAction *string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		action, err := requestcontext.ActionFromContext(r.Context())
		require.NoError(t, err)
		capturedAction = action
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	definition.DefineAction(next).ServeHTTP(rr, req)

	require.NotNil(t, capturedAction, "DefineAction must invoke the next handler on a match")
	require.Equal(t, actionName, *capturedAction)
}
