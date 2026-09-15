package rpcinfra_test

import (
	"context"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra/rpcerrors"

	"github.com/stretchr/testify/require"
)

// TestRPCAPIPublisher_RegisteredMethodsMatchSupportedMethods pins SupportedMethods to what the router
// actually serves. The RBAC coverage tests and the validator's exemption list both treat that slice as
// the set of published methods, but ProvideJSONRPCMethods registers each handler by hand rather than
// iterating it, so a method registered without being listed would be published and RBAC-checked while
// invisible to every one of those checks, and denied for every user with nothing failing.
func TestRPCAPIPublisher_RegisteredMethodsMatchSupportedMethods(t *testing.T) {
	router := rpcinfra.ProvideDefaultRPCRouter(rpcinfra.DefaultRPCRouterOptions{})

	_, err := rpcinfra.ProvideJSONRPCMethods(rpcinfra.JSONRPCAPIPublisherOptions{
		RPCRouter: router,
		Handler:   stubJSONRPCAPIHandler{},
	})
	require.NoError(t, err)

	require.ElementsMatch(t, rpcinfra.SupportedMethods, router.Methods(),
		"the methods registered by ProvideJSONRPCMethods and SupportedMethods have diverged")
}

// stubJSONRPCAPIHandler satisfies JSONRPCAPIHandler without reaching a use case. Adding a method to
// that interface stops this compiling, which is the intent: the author is sent to the registration
// list and to SupportedMethods together.
type stubJSONRPCAPIHandler struct{}

func (stubJSONRPCAPIHandler) HandleGenerateAccount(_ context.Context, _ rpcinfra.RPCRequest) (any, *rpcerrors.RPCError) {
	return nil, nil
}

func (stubJSONRPCAPIHandler) HandleImportAccount(_ context.Context, _ rpcinfra.RPCRequest) (any, *rpcerrors.RPCError) {
	return nil, nil
}

func (stubJSONRPCAPIHandler) HandleRemoveAccount(_ context.Context, _ rpcinfra.RPCRequest) (any, *rpcerrors.RPCError) {
	return nil, nil
}

func (stubJSONRPCAPIHandler) HandleListAccounts(_ context.Context, _ rpcinfra.RPCRequest) (any, *rpcerrors.RPCError) {
	return nil, nil
}

func (stubJSONRPCAPIHandler) HandleSignTX(_ context.Context, _ rpcinfra.RPCRequest) (any, *rpcerrors.RPCError) {
	return nil, nil
}

func (stubJSONRPCAPIHandler) HandleSignTypedData(_ context.Context, _ rpcinfra.RPCRequest) (any, *rpcerrors.RPCError) {
	return nil, nil
}

func (stubJSONRPCAPIHandler) HandlePersonalSign(_ context.Context, _ rpcinfra.RPCRequest) (any, *rpcerrors.RPCError) {
	return nil, nil
}

var _ rpcinfra.JSONRPCAPIHandler = (*stubJSONRPCAPIHandler)(nil)
