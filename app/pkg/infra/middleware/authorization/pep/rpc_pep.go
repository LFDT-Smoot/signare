package pep

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/lfdt-smoot/signare/app/pkg/commons/logger"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/infra/httpinfra"
	"github.com/lfdt-smoot/signare/app/pkg/infra/requestcontext"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra"
	"github.com/lfdt-smoot/signare/app/pkg/utils"
)

// accountSigningMethods maps each account-signing RPC method to whether the account it signs with is
// carried in the request's `address` param (true) or its `from` param (false). Authorization must read
// the same field the signing path reads, otherwise a caller could be authorized for one account while
// signing with another. Keying off the publisher's method constants keeps this in lockstep with the
// registered methods if one is ever renamed.
var accountSigningMethods = map[string]bool{
	rpcinfra.SignTransactionMethod: false, // eth_signTransaction signs with `from`
	rpcinfra.SignTypedDataMethod:   true,  // eth_signTypedData signs with `address`
	rpcinfra.PersonalSignMethod:    true,  // personal_sign signs with `address`
}

// accountSigningField reports whether the action must pass per-account authorization and, if so,
// whether the signing account is carried in the `address` param. The action is the composed
// `rpc.method.<method>` (or the bare method), matched against the method as a whole dotted segment so a
// method whose name merely embeds another (e.g. a hypothetical eth_signTransactionBatch) is not caught.
func accountSigningField(actionID string) (usesAddressParam bool, requiresAuthorization bool) {
	for method, usesAddress := range accountSigningMethods {
		if actionID == method || strings.HasSuffix(actionID, "."+method) {
			return usesAddress, true
		}
	}
	return false, false
}

// AuthorizeAccount checks if a user is authorized to use an account when performing an account
// signing action (any method listed in accountSigningMethods).
func (policyEnforcementPoint *RPCPolicyEnforcementPoint) AuthorizeAccount(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		user, err := requestcontext.UserFromContext(ctx)
		if err != nil {
			policyEnforcementPoint.responseHandler.HandleErrorResponse(ctx, w, httpinfra.NewHTTPErrorFromError(ctx, err, httpinfra.StatusPermissionDenied).SetMessage("user is not set in the request"))
			return
		}
		application, err := requestcontext.ApplicationFromContext(ctx)
		if err != nil {
			policyEnforcementPoint.responseHandler.HandleErrorResponse(ctx, w, httpinfra.NewHTTPErrorFromError(ctx, err, httpinfra.StatusPermissionDenied).SetMessage("application is not set in the request"))
			return
		}
		actionID, err := requestcontext.ActionFromContext(ctx)
		if err != nil {
			policyEnforcementPoint.responseHandler.HandleErrorResponse(ctx, w, httpinfra.NewHTTPErrorFromError(ctx, err, httpinfra.StatusPermissionDenied).SetMessage("action is not set in the request"))
			return
		}

		usesAddressParam, requiresAuthorization := accountSigningField(*actionID)
		if !requiresAuthorization {
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		var authorizeAccountRPCBody AuthorizeAccountRPCBody
		err = utils.ReadAndResetCloser(&r.Body, &authorizeAccountRPCBody)
		if err != nil {
			policyEnforcementPoint.responseHandler.HandleErrorResponse(r.Context(), w, httpinfra.NewHTTPErrorFromError(ctx, err, httpinfra.StatusInvalidArgument))
			return
		}

		addr, err := getAddressFromParamsArray(ctx, authorizeAccountRPCBody, usesAddressParam)
		if err != nil {
			addr, err = getAddressFromParamsObject(ctx, authorizeAccountRPCBody, usesAddressParam)
			if err != nil {
				policyEnforcementPoint.responseHandler.HandleErrorResponse(r.Context(), w, httpinfra.NewHTTPErrorFromError(ctx, err, httpinfra.StatusInvalidArgument))
				return
			}
		}

		authorizeAccountInput := AuthorizeAccountUserInput{
			UserID:        *user,
			ApplicationID: *application,
			Address:       *addr,
		}
		_, err = policyEnforcementPoint.accountUserPolicyDecisionPointAdapter.AuthorizeAccountUser(ctx, authorizeAccountInput)
		if err != nil {
			//TODO should this be logged here since the error will be logged in the HandleErrorResponse method?
			logger.LogEntry(ctx).Errorf("user [%s] is not authorized to use request's account [%s]", authorizeAccountInput.UserID, authorizeAccountInput.Address.String())
			policyEnforcementPoint.responseHandler.HandleErrorResponse(ctx, w, httpinfra.NewForbiddenHTTPError(ctx, err))
			return
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getAddressFromParamsArray(ctx context.Context, params AuthorizeAccountRPCBody, usesAddressParam bool) (*address.Address, error) {
	var rpcAddress []AuthorizeAccountRPCParams
	err := json.Unmarshal(params.Params, &rpcAddress)
	if err != nil {
		return nil, err
	}
	if len(rpcAddress) == 0 {
		return nil, errors.New("no account params provided")
	}
	signer := rpcAddress[0].signerAddress(usesAddressParam)
	addr, err := address.NewFromHexString(signer)
	if err != nil {
		logger.LogEntry(ctx).Errorf("invalid account address: %s", signer)
		return nil, err
	}
	return &addr, nil
}

func getAddressFromParamsObject(ctx context.Context, params AuthorizeAccountRPCBody, usesAddressParam bool) (*address.Address, error) {
	var rpcAddress AuthorizeAccountRPCParams
	err := json.Unmarshal(params.Params, &rpcAddress)
	if err != nil {
		return nil, err
	}
	signer := rpcAddress.signerAddress(usesAddressParam)
	addr, err := address.NewFromHexString(signer)
	if err != nil {
		logger.LogEntry(ctx).Errorf("invalid account address: %s", signer)
		return nil, err
	}
	return &addr, nil
}

// RPCPolicyEnforcementPointOptions are the set of fields to create an RPCPolicyEnforcementPoint
type RPCPolicyEnforcementPointOptions struct {
	// ResponseHandler exposes functionality to handle HTTP responses
	ResponseHandler httpinfra.HTTPResponseHandler
	// UserPolicyDecisionPointPort is a port to adapt authorization checks
	UserPolicyDecisionPointAdapter UserPolicyDecisionPointPort
	// AccountUserPolicyDecisionPointPort is a port to adapt account usage authorization checks
	AccountUserPolicyDecisionPointAdapter AccountUserPolicyDecisionPointPort
}

// RPCPolicyEnforcementPoint checks if the user is authorized to perform a given action
type RPCPolicyEnforcementPoint struct {
	responseHandler                       httpinfra.HTTPResponseHandler
	userPolicyDecisionPointAdapter        UserPolicyDecisionPointPort
	accountUserPolicyDecisionPointAdapter AccountUserPolicyDecisionPointPort
}

// ProvideRPCPolicyEnforcementPoint provides an instance of an RPCPolicyEnforcementPoint
func ProvideRPCPolicyEnforcementPoint(options RPCPolicyEnforcementPointOptions) (*RPCPolicyEnforcementPoint, error) {
	if options.ResponseHandler == nil {
		return nil, errors.New("mandatory 'ResponseHandler' not provided")
	}
	if options.UserPolicyDecisionPointAdapter == nil {
		return nil, errors.New("mandatory 'UserPolicyDecisionPointAdapter' not provided")
	}
	if options.AccountUserPolicyDecisionPointAdapter == nil {
		return nil, errors.New("mandatory 'AccountUserPolicyDecisionPointAdapter' not provided")
	}

	return &RPCPolicyEnforcementPoint{
		responseHandler:                       options.ResponseHandler,
		userPolicyDecisionPointAdapter:        options.UserPolicyDecisionPointAdapter,
		accountUserPolicyDecisionPointAdapter: options.AccountUserPolicyDecisionPointAdapter,
	}, nil
}
