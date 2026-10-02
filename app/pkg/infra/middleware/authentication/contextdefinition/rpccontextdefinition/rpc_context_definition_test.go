package rpccontextdefinition_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/adapters/metricsout"
	"github.com/lfdt-smoot/signare/app/pkg/commons/metricrecorder"
	"github.com/lfdt-smoot/signare/app/pkg/infra/httpinfra"
	"github.com/lfdt-smoot/signare/app/pkg/infra/middleware/authentication/contextdefinition/rpccontextdefinition"
	"github.com/lfdt-smoot/signare/app/pkg/infra/requestcontext"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra/rpcerrors"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/require"
)

const (
	registeredMethod = "eth_accounts"
	rpcRouteName     = "rpc.method"
)

// noopResponseHandler is a minimal HTTPResponseHandler for the tests that only inspect the action a
// registered method is given.
type noopResponseHandler struct{}

func (noopResponseHandler) HandleErrorResponse(context.Context, http.ResponseWriter, *httpinfra.HTTPError) {
}

func (noopResponseHandler) HandleSuccessResponse(context.Context, http.ResponseWriter, httpinfra.ResponseInfo, interface{}) {
}

// newMiddleware builds an RPCContextDefinition backed by a router that has the registered method and
// the "/" route named like the real publisher (rpc_api_publisher.go).
func newMiddleware(t *testing.T) *rpccontextdefinition.RPCContextDefinition {
	t.Helper()

	router := rpcinfra.ProvideDefaultRPCRouter(rpcinfra.DefaultRPCRouterOptions{})
	require.NoError(t, router.RegisterRPCHandlerFunc(registeredMethod, nil))
	router.Router().HandleFunc("/", router.HandleRPCRequest).Methods(http.MethodPost).Name(rpcRouteName)

	middleware, err := rpccontextdefinition.ProvideRPCContextDefinitionFromHeaders(rpccontextdefinition.RPCContextDefinitionOptions{
		ResponseHandler: noopResponseHandler{},
		RPCRouter:       router,
	})
	require.NoError(t, err)
	return middleware
}

// runDefineAction runs DefineAction for a JSON-RPC request with the given method and returns the
// context the middleware passed to the next handler.
func runDefineAction(t *testing.T, middleware *rpccontextdefinition.RPCContextDefinition, method string) context.Context {
	t.Helper()

	var captured context.Context
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		captured = r.Context()
	})

	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "id": 1})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	middleware.DefineAction(next).ServeHTTP(httptest.NewRecorder(), req)
	require.NotNil(t, captured, "DefineAction did not invoke the next handler")
	return captured
}

func actionOf(t *testing.T, ctx context.Context) string {
	t.Helper()

	action, err := requestcontext.ActionFromContext(ctx)
	require.NoError(t, err)
	require.NotNil(t, action)
	return *action
}

// TestDefineAction_RegisteredMethod_PreservesMethodLabel confirms a registered method keeps its
// per-method action so legitimate observability is preserved.
func TestDefineAction_RegisteredMethod_PreservesMethodLabel(t *testing.T) {
	middleware := newMiddleware(t)

	action := actionOf(t, runDefineAction(t, middleware, registeredMethod))
	require.Equal(t, rpcRouteName+"."+registeredMethod, action)
}

// TestDefineAction_UnregisteredMethod_AnswersMethodNotFound confirms an unregistered method is answered
// with -32601 carrying the caller's request ID, and never reaches authorization, which would refuse it
// as Unauthorized.
func TestDefineAction_UnregisteredMethod_AnswersMethodNotFound(t *testing.T) {
	middleware := newMiddlewareWithRPCHandler(t)

	rr := runUnregistered(t, middleware, "eth_importAccount", 7)

	require.Equal(t, http.StatusOK, rr.Code)
	var response struct {
		ID    any `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	require.Equal(t, int(rpcerrors.MethodNotFoundErrorCode), response.Error.Code)
	require.Equal(t, string(rpcerrors.MethodNotFoundErrorMsg), response.Error.Message)
	require.Equal(t, float64(7), response.ID)
}

// TestForbiddenAccessCounter_NoSeriesForUnregisteredMethods is a regression guard on metric
// cardinality. Many distinct client-chosen methods must not create a forbidden_access_count series
// each: they are answered before an action exists, so none is labelled with the method.
func TestForbiddenAccessCounter_NoSeriesForUnregisteredMethods(t *testing.T) {
	middleware := newMiddlewareWithRPCHandler(t)
	for i := 0; i < 1000; i++ {
		runUnregistered(t, middleware, fmt.Sprintf("evil_method_%d", i), i)
	}

	require.Zero(t, forbiddenAccessSeriesMatching(t, "evil_method_"),
		"no client-chosen method may become a forbidden_access_count label")
}

// newMiddlewareWithRPCHandler builds an RPCContextDefinition backed by the real JSON-RPC response
// handler and real metrics, so the response and the metric series an unregistered method produces
// are the ones the server produces.
func newMiddlewareWithRPCHandler(t *testing.T) *rpccontextdefinition.RPCContextDefinition {
	t.Helper()

	adapter, err := metricsout.NewTestMetricsRecorderAdapter()
	require.NoError(t, err)
	recorder, err := metricrecorder.ProvideDefaultMetricRecorder(metricrecorder.DefaultMetricRecorderOptions{MetricsRecorderAdapter: adapter})
	require.NoError(t, err)
	metrics, err := httpinfra.ProvideDefaultHTTPMetrics(httpinfra.DefaultHTTPMetricsOptions{MetricRecorder: recorder})
	require.NoError(t, err)
	responseHandler, err := rpcinfra.ProvideDefaultRPCInfraResponseHandler(rpcinfra.DefaultRPCInfraResponseHandlerOptions{HTTPMetrics: metrics})
	require.NoError(t, err)

	router := rpcinfra.ProvideDefaultRPCRouter(rpcinfra.DefaultRPCRouterOptions{})
	require.NoError(t, router.RegisterRPCHandlerFunc(registeredMethod, nil))
	router.Router().HandleFunc("/", router.HandleRPCRequest).Methods(http.MethodPost).Name(rpcRouteName)

	middleware, err := rpccontextdefinition.ProvideRPCContextDefinitionFromHeaders(rpccontextdefinition.RPCContextDefinitionOptions{
		ResponseHandler: responseHandler,
		RPCRouter:       router,
	})
	require.NoError(t, err)
	return middleware
}

// runUnregistered sends an unregistered method through DefineAction, with the request ID in the
// context as the batch entrypoint puts it there, and fails if the next handler runs.
func runUnregistered(t *testing.T, middleware *rpccontextdefinition.RPCContextDefinition, method string, id int) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "id": id})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), requestcontext.RPCRequestIDKey, any(float64(id))))

	rr := httptest.NewRecorder()
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatalf("an unregistered method %q must not reach the next handler", method)
	})
	middleware.DefineAction(next).ServeHTTP(rr, req)
	return rr
}

// forbiddenAccessSeriesMatching scrapes the Prometheus default registry and counts the
// forbidden_access_count series whose labels contain fragment.
func forbiddenAccessSeriesMatching(t *testing.T, fragment string) int {
	t.Helper()

	rr := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	prefix := metricsout.DefaultTestMetricsNamespace + "_forbidden_access_count{"
	count := 0
	for _, line := range strings.Split(rr.Body.String(), "\n") {
		if strings.HasPrefix(line, prefix) && strings.Contains(line, fragment) {
			count++
		}
	}
	return count
}
