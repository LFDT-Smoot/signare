package rpcinfra

import (
	"context"
	"errors"

	"github.com/lfdt-smoot/signare/app/pkg/infra/requestcontext"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra/rpcerrors"
)

// JSONRPCAPIHandler handles the set of operations that are supported by the RPC protocol
type JSONRPCAPIHandler interface {
	// HandleGenerateAccount handles the generation of an Ethereum account.
	HandleGenerateAccount(ctx context.Context, r RPCRequest) (any, *rpcerrors.RPCError)
	// HandleImportAccount handles the import of an Ethereum account.
	HandleImportAccount(ctx context.Context, r RPCRequest) (any, *rpcerrors.RPCError)
	// HandleRemoveAccount handles the removal of an Ethereum account.
	HandleRemoveAccount(ctx context.Context, r RPCRequest) (any, *rpcerrors.RPCError)
	// HandleListAccounts handles the listing of all the Ethereum accounts in an Application.
	HandleListAccounts(ctx context.Context, r RPCRequest) (any, *rpcerrors.RPCError)
	// HandleSignTX handles the signature of a transaction with an Ethereum account.
	HandleSignTX(ctx context.Context, r RPCRequest) (any, *rpcerrors.RPCError)
	// HandleSignTypedData handles the signature of EIP-712 typed data with an Ethereum account.
	HandleSignTypedData(ctx context.Context, r RPCRequest) (any, *rpcerrors.RPCError)
	// HandlePersonalSign handles the EIP-191 signature of an arbitrary message with an Ethereum account.
	HandlePersonalSign(ctx context.Context, r RPCRequest) (any, *rpcerrors.RPCError)
}

func (handler *DefaultJSONRPCAPIHandler) HandleGenerateAccount(ctx context.Context, r RPCRequest) (any, *rpcerrors.RPCError) {
	reqParams := GenerateAccountRequestParams{}
	applicationID, err := requestcontext.ApplicationFromContext(ctx)
	if err != nil {
		return nil, rpcerrors.NewInternalFromErr(err)
	}
	reqParams.ApplicationID = *applicationID

	out, rpcErr := handler.adapter.AdaptGenerateAccount(ctx, reqParams)
	if rpcErr != nil {
		return nil, rpcErr
	}
	return &RPCResponse{
		RPCVersion: SupportedRPCVersion,
		ID:         r.ID,
		Result:     out,
	}, nil
}

func (handler *DefaultJSONRPCAPIHandler) HandleImportAccount(ctx context.Context, r RPCRequest) (any, *rpcerrors.RPCError) {
	reqParams := ImportAccountRequestParams{}
	if err := ProcessParams(r.Params, &reqParams); err != nil {
		return nil, err
	}
	err := reqParams.ValidateParams()
	if err != nil {
		return nil, rpcerrors.NewInvalidParamsFromErr(err)
	}

	applicationID, err := requestcontext.ApplicationFromContext(ctx)
	if err != nil {
		return nil, rpcerrors.NewInternalFromErr(err)
	}
	reqParams.ApplicationID = *applicationID

	out, rpcErr := handler.adapter.AdaptImportAccount(ctx, reqParams)
	if rpcErr != nil {
		return nil, rpcErr
	}
	return &RPCResponse{
		RPCVersion: SupportedRPCVersion,
		ID:         r.ID,
		Result:     out,
	}, nil
}

func (handler *DefaultJSONRPCAPIHandler) HandleRemoveAccount(ctx context.Context, r RPCRequest) (any, *rpcerrors.RPCError) {
	reqParams := RemoveAccountRequestParams{}
	if err := ProcessParams(r.Params, &reqParams); err != nil {
		return nil, err
	}
	err := reqParams.ValidateParams()
	if err != nil {
		return nil, rpcerrors.NewInvalidParamsFromErr(err)
	}

	applicationID, err := requestcontext.ApplicationFromContext(ctx)
	if err != nil {
		return nil, rpcerrors.NewInternalFromErr(err)
	}
	reqParams.ApplicationID = *applicationID

	out, rpcErr := handler.adapter.AdaptRemoveAccount(ctx, reqParams)
	if rpcErr != nil {
		return nil, rpcErr
	}
	return &RPCResponse{
		RPCVersion: SupportedRPCVersion,
		ID:         r.ID,
		Result:     out,
	}, nil
}

func (handler *DefaultJSONRPCAPIHandler) HandleListAccounts(ctx context.Context, r RPCRequest) (any, *rpcerrors.RPCError) {
	reqParams := ListAccountsRequestParams{}
	applicationID, err := requestcontext.ApplicationFromContext(ctx)
	if err != nil {
		return nil, rpcerrors.NewInternalFromErr(err)
	}
	reqParams.ApplicationID = *applicationID

	out, rpcErr := handler.adapter.AdaptListAccounts(ctx, reqParams)
	if rpcErr != nil {
		return nil, rpcErr
	}
	return &RPCResponse{
		RPCVersion: SupportedRPCVersion,
		ID:         r.ID,
		Result:     out,
	}, nil
}

func (handler *DefaultJSONRPCAPIHandler) HandleSignTX(ctx context.Context, r RPCRequest) (any, *rpcerrors.RPCError) {
	reqParams := SignTXRequestParams{}
	if err := ProcessParams(r.Params, &reqParams); err != nil {
		return nil, err
	}
	err := reqParams.ValidateParams()
	if err != nil {
		return nil, rpcerrors.NewInvalidParamsFromErr(err)
	}

	applicationID, err := requestcontext.ApplicationFromContext(ctx)
	if err != nil {
		return nil, rpcerrors.NewInternalFromErr(err)
	}
	reqParams.ApplicationID = *applicationID

	out, rpcErr := handler.adapter.AdaptSignTx(ctx, reqParams)
	if rpcErr != nil {
		return nil, rpcErr
	}
	return &RPCResponse{
		RPCVersion: SupportedRPCVersion,
		ID:         r.ID,
		Result:     out,
	}, nil
}

func (handler *DefaultJSONRPCAPIHandler) HandleSignTypedData(ctx context.Context, r RPCRequest) (any, *rpcerrors.RPCError) {
	reqParams := SignTypedDataRequestParams{}
	if err := ProcessParams(r.Params, &reqParams); err != nil {
		return nil, err
	}
	if err := reqParams.ValidateParams(); err != nil {
		return nil, rpcerrors.NewInvalidParamsFromErr(err)
	}

	applicationID, err := requestcontext.ApplicationFromContext(ctx)
	if err != nil {
		return nil, rpcerrors.NewInternalFromErr(err)
	}
	reqParams.ApplicationID = *applicationID

	out, rpcErr := handler.adapter.AdaptSignTypedData(ctx, reqParams)
	if rpcErr != nil {
		return nil, rpcErr
	}
	return &RPCResponse{
		RPCVersion: SupportedRPCVersion,
		ID:         r.ID,
		Result:     out,
	}, nil
}

func (handler *DefaultJSONRPCAPIHandler) HandlePersonalSign(ctx context.Context, r RPCRequest) (any, *rpcerrors.RPCError) {
	reqParams := PersonalSignRequestParams{}
	if err := ProcessParams(r.Params, &reqParams); err != nil {
		return nil, err
	}
	if err := reqParams.ValidateParams(); err != nil {
		return nil, rpcerrors.NewInvalidParamsFromErr(err)
	}

	applicationID, err := requestcontext.ApplicationFromContext(ctx)
	if err != nil {
		return nil, rpcerrors.NewInternalFromErr(err)
	}
	reqParams.ApplicationID = *applicationID

	out, rpcErr := handler.adapter.AdaptPersonalSign(ctx, reqParams)
	if rpcErr != nil {
		return nil, rpcErr
	}
	return &RPCResponse{
		RPCVersion: SupportedRPCVersion,
		ID:         r.ID,
		Result:     out,
	}, nil
}

// DefaultJSONRPCAPIHandlerOptions are the attributes to build a DefaultJSONRPCAPIHandler
type DefaultJSONRPCAPIHandlerOptions struct {
	// Adapter  adapts the set of operations that are supported by the RPC protocol
	Adapter JSONRPCAPIAdapter
}

// DefaultJSONRPCAPIHandler is the default JSONRPCAPIHandler
type DefaultJSONRPCAPIHandler struct {
	adapter JSONRPCAPIAdapter
}

// NewDefaultJSONRPCAPIHandler creates a new DefaultJSONRPCAPIHandler from the provided options
func NewDefaultJSONRPCAPIHandler(options DefaultJSONRPCAPIHandlerOptions) (*DefaultJSONRPCAPIHandler, error) {
	if options.Adapter == nil {
		return nil, errors.New("mandatory 'Adapter' not provided")
	}

	return &DefaultJSONRPCAPIHandler{
		adapter: options.Adapter,
	}, nil
}

var _ JSONRPCAPIHandler = (*DefaultJSONRPCAPIHandler)(nil)
