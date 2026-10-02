package rpccontextdefinition_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/adapters/metricsout"
	"github.com/lfdt-smoot/signare/app/pkg/commons/metricrecorder"
	"github.com/lfdt-smoot/signare/app/pkg/infra/httpinfra"
	"github.com/lfdt-smoot/signare/app/pkg/infra/middleware/authentication/contextdefinition/rpccontextdefinition"
	"github.com/lfdt-smoot/signare/app/pkg/infra/middleware/entrypoint/rpcbatchrequestsupport"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra/rpcerrors"

	"github.com/stretchr/testify/require"
)

// TestBatch_UnregisteredMethodAnsweredBesideRegisteredOne drives a two-element batch through the real
// fan-out, DefineAction and router dispatch. The unknown element must get -32601 with its own ID while
// the known one still reaches its handler and gets its result.
func TestBatch_UnregisteredMethodAnsweredBesideRegisteredOne(t *testing.T) {
	adapter, err := metricsout.NewTestMetricsRecorderAdapter()
	require.NoError(t, err)
	recorder, err := metricrecorder.ProvideDefaultMetricRecorder(metricrecorder.DefaultMetricRecorderOptions{MetricsRecorderAdapter: adapter})
	require.NoError(t, err)
	metrics, err := httpinfra.ProvideDefaultHTTPMetrics(httpinfra.DefaultHTTPMetricsOptions{MetricRecorder: recorder})
	require.NoError(t, err)
	responseHandler, err := rpcinfra.ProvideDefaultRPCInfraResponseHandler(rpcinfra.DefaultRPCInfraResponseHandlerOptions{HTTPMetrics: metrics})
	require.NoError(t, err)

	router := rpcinfra.ProvideDefaultRPCRouter(rpcinfra.DefaultRPCRouterOptions{DefaultRPCInfraResponseHandler: responseHandler, HTTPMetrics: metrics})
	require.NoError(t, router.RegisterRPCHandlerFunc(registeredMethod, func(_ context.Context, r rpcinfra.RPCRequest) (any, *rpcerrors.RPCError) {
		return &rpcinfra.RPCResponse{RPCVersion: rpcinfra.SupportedRPCVersion, ID: r.ID, Result: []string{"listed"}}, nil
	}))
	router.Router().HandleFunc("/", router.HandleRPCRequest).Methods(http.MethodPost).Name(rpcRouteName)

	fanOut, err := rpcbatchrequestsupport.ProvideRPCBatchRequestSupportMiddleware(rpcbatchrequestsupport.RPCBatchRequestSupportMiddlewareOptions{
		ResponseHandler: responseHandler,
		RPCRouter:       router,
	})
	require.NoError(t, err)
	defineAction, err := rpccontextdefinition.ProvideRPCContextDefinitionFromHeaders(rpccontextdefinition.RPCContextDefinitionOptions{
		ResponseHandler: responseHandler,
		RPCRouter:       router,
	})
	require.NoError(t, err)
	chain := fanOut.FanOutRPCBatchRequest(defineAction.DefineAction(http.HandlerFunc(router.HandleRPCRequest)))

	body := `[{"jsonrpc":"2.0","method":"eth_importAccount","params":[],"id":"a"},{"jsonrpc":"2.0","method":"` + registeredMethod + `","params":[],"id":"b"}]`
	rr := httptest.NewRecorder()
	chain.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body)))
	require.Equal(t, http.StatusOK, rr.Code)

	type response struct {
		ID     string   `json:"id"`
		Result []string `json:"result"`
		Error  *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	byID := map[string]response{}
	decoder := json.NewDecoder(rr.Body)
	for decoder.More() {
		var r response
		require.NoError(t, decoder.Decode(&r))
		byID[r.ID] = r
	}
	require.Len(t, byID, 2, "each batch element must get its own response")
	require.NotNil(t, byID["a"].Error)
	require.Equal(t, int(rpcerrors.MethodNotFoundErrorCode), byID["a"].Error.Code)
	require.Nil(t, byID["b"].Error)
	require.Equal(t, []string{"listed"}, byID["b"].Result)
}
