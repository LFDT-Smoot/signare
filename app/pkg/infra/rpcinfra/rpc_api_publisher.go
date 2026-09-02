package rpcinfra

import (
	"errors"
)

// JSON-RPC supported methods by the signare. These are exported so that authorization (the RPC
// policy enforcement point) and the RBAC coverage test reference the same identifiers instead of
// re-declaring the method strings, which would drift out of sync on a rename.
const (
	GenerateAccountMethod = "eth_generateAccount"
	ImportAccountMethod   = "eth_importAccount"
	RemoveAccountMethod   = "eth_removeAccount"
	ListAccountsMethod    = "eth_accounts"
	SignTransactionMethod = "eth_signTransaction"
	SignTypedDataMethod   = "eth_signTypedData"
	PersonalSignMethod    = "personal_sign"
)

// SupportedMethods lists every JSON-RPC method the signare publishes. It is the single source of
// truth for the set of methods and is used by the RBAC coverage invariant test to assert that each
// method is a registered, grantable action.
var SupportedMethods = []string{
	GenerateAccountMethod,
	ImportAccountMethod,
	RemoveAccountMethod,
	ListAccountsMethod,
	SignTransactionMethod,
	SignTypedDataMethod,
	PersonalSignMethod,
}

// JSONRPCAPIPublisherOptions options to create a JSONRPCAPIRoutesPublished.
type JSONRPCAPIPublisherOptions struct {
	RPCRouter RPCRouter
	Handler   JSONRPCAPIHandler
}

// JSONRPCAPIRoutesPublished type for the JSON-RPC API published routes.
type JSONRPCAPIRoutesPublished int

// ProvideJSONRPCMethods creates a new JSONRPCAPIRoutesPublished.
func ProvideJSONRPCMethods(options JSONRPCAPIPublisherOptions) (JSONRPCAPIRoutesPublished, error) {
	if options.RPCRouter == nil {
		return 0, errors.New("mandatory 'RPCRouter' not provided")
	}
	if options.Handler == nil {
		return 0, errors.New("mandatory 'Handler' not provided")
	}

	// Register RPC handlers
	var err error
	err = options.RPCRouter.RegisterRPCHandlerFunc(GenerateAccountMethod, options.Handler.HandleGenerateAccount)
	if err != nil {
		return 0, err
	}
	err = options.RPCRouter.RegisterRPCHandlerFunc(ImportAccountMethod, options.Handler.HandleImportAccount)
	if err != nil {
		return 0, err
	}
	err = options.RPCRouter.RegisterRPCHandlerFunc(RemoveAccountMethod, options.Handler.HandleRemoveAccount)
	if err != nil {
		return 0, err
	}
	err = options.RPCRouter.RegisterRPCHandlerFunc(ListAccountsMethod, options.Handler.HandleListAccounts)
	if err != nil {
		return 0, err
	}
	err = options.RPCRouter.RegisterRPCHandlerFunc(SignTransactionMethod, options.Handler.HandleSignTX)
	if err != nil {
		return 0, err
	}
	err = options.RPCRouter.RegisterRPCHandlerFunc(SignTypedDataMethod, options.Handler.HandleSignTypedData)
	if err != nil {
		return 0, err
	}
	err = options.RPCRouter.RegisterRPCHandlerFunc(PersonalSignMethod, options.Handler.HandlePersonalSign)
	if err != nil {
		return 0, err
	}

	// HTTP Handler
	options.RPCRouter.Router().HandleFunc("/", options.RPCRouter.HandleRPCRequest).Methods("POST").Name("rpc.method")

	return 0, nil
}
