package rpcinfra

import (
	"context"

	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra/rpcerrors"
)

// JSONRPCAPIAdapter adapts the set of operations that are supported by the RPC protocol
type JSONRPCAPIAdapter interface {
	// AdaptGenerateAccount adapts the generation of an Ethereum account.
	AdaptGenerateAccount(ctx context.Context, data GenerateAccountRequestParams) (*string, *rpcerrors.RPCError)
	// AdaptImportAccount adapts the import of an Ethereum account.
	AdaptImportAccount(ctx context.Context, data ImportAccountRequestParams) (*string, *rpcerrors.RPCError)
	// AdaptRemoveAccount adapts the removal of an Ethereum account.
	AdaptRemoveAccount(ctx context.Context, data RemoveAccountRequestParams) (*string, *rpcerrors.RPCError)
	// AdaptListAccounts adapts the listing of all the Ethereum accounts in an Application.
	AdaptListAccounts(ctx context.Context, data ListAccountsRequestParams) ([]string, *rpcerrors.RPCError)
	// AdaptSignTx adapts the signature of a transaction with an Ethereum account.
	AdaptSignTx(ctx context.Context, data SignTXRequestParams) (*string, *rpcerrors.RPCError)
	// AdaptSignTypedData adapts the signature of EIP-712 typed data with an Ethereum account.
	AdaptSignTypedData(ctx context.Context, data SignTypedDataRequestParams) (*string, *rpcerrors.RPCError)
	// AdaptPersonalSign adapts the EIP-191 signature of an arbitrary message with an Ethereum account.
	AdaptPersonalSign(ctx context.Context, data PersonalSignRequestParams) (*string, *rpcerrors.RPCError)
}
