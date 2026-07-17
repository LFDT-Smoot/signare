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

	"github.com/hyperledger-labs/signare/app/pkg/adapters/metricsout"
	"github.com/hyperledger-labs/signare/app/pkg/commons/metricrecorder"
	"github.com/hyperledger-labs/signare/app/pkg/infra/httpinfra"
	"github.com/hyperledger-labs/signare/app/pkg/infra/middleware/authentication/contextdefinition/rpccontextdefinition"
	"github.com/hyperledger-labs/signare/app/pkg/infra/requestcontext"
	"github.com/hyperledger-labs/signare/app/pkg/infra/rpcinfra"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/require"
)

const (
	registeredMethod = "eth_accounts"
	rpcRouteName     = "rpc.method"
)

// noopResponseHandler is a minimal HTTPResponseHandler. DefineAction only invokes it on malformed
// requests, which these tests do not exercise.
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

// TestDefineAction_UnregisteredMethod_FallsBackToRouteName confirms an unregistered, client-supplied
// method is not folded into the action: it falls back to the bounded route name.
func TestDefineAction_UnregisteredMethod_FallsBackToRouteName(t *testing.T) {
	middleware := newMiddleware(t)

	action := actionOf(t, runDefineAction(t, middleware, "attacker_supplied_method"))
	require.Equal(t, rpcRouteName, action)
}

// TestForbiddenAccessCounter_BoundedSeriesForDistinctMethods is a regression guard. It drives
// many distinct, arbitrary client methods through DefineAction and the 403 metric, then asserts the
// real forbidden_access_count vector holds a single bounded series rather than one series per method.
func TestForbiddenAccessCounter_BoundedSeriesForDistinctMethods(t *testing.T) {
	adapter, err := metricsout.NewTestMetricsRecorderAdapter()
	require.NoError(t, err)
	recorder, err := metricrecorder.ProvideDefaultMetricRecorder(metricrecorder.DefaultMetricRecorderOptions{MetricsRecorderAdapter: adapter})
	require.NoError(t, err)
	metrics, err := httpinfra.ProvideDefaultHTTPMetrics(httpinfra.DefaultHTTPMetricsOptions{MetricRecorder: recorder})
	require.NoError(t, err)

	middleware := newMiddleware(t)
	for i := 0; i < 1000; i++ {
		ctx := runDefineAction(t, middleware, fmt.Sprintf("evil_method_%d", i))
		metrics.IncrementForbiddenAccessCounter(ctx)
	}

	require.Equal(t, 1, forbiddenAccessSeriesCount(t),
		"distinct client methods must collapse onto a single bounded forbidden_access_count series")
}

// forbiddenAccessSeriesCount scrapes the Prometheus default registry and counts the distinct
// forbidden_access_count series (one line per unique label set).
func forbiddenAccessSeriesCount(t *testing.T) int {
	t.Helper()

	rr := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	prefix := metricsout.DefaultTestMetricsNamespace + "_forbidden_access_count{"
	count := 0
	for _, line := range strings.Split(rr.Body.String(), "\n") {
		if strings.HasPrefix(line, prefix) {
			count++
		}
	}
	return count
}
