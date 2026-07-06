package pep_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hyperledger-labs/signare/app/pkg/infra/httpinfra"
	"github.com/hyperledger-labs/signare/app/pkg/infra/middleware/authorization/pep"
	"github.com/hyperledger-labs/signare/app/pkg/infra/requestcontext"

	"github.com/stretchr/testify/require"
)

// TestAuthorizeAccount_Denied_GenericForbiddenNoIdentifierLeak checks a denied account authorization
// returns the constant generic 403 message and leaks neither the user id, the application id, nor the
// account address (the pre-fix body echoed the application and user ids).
func TestAuthorizeAccount_Denied_GenericForbiddenNoIdentifierLeak(t *testing.T) {
	const (
		userID  = "owner"
		appID   = "app1"
		address = "0x970e8128ab834e8eac17ab8e3812f010678cf791"
	)

	handler, err := httpinfra.ProvideDefaultHTTPResponseHandler(httpinfra.DefaultHTTPResponseHandlerOptions{
		HTTPMetrics: httpinfra.DefaultHTTPMetrics{},
	})
	require.NoError(t, err)

	point, err := pep.ProvideRPCPolicyEnforcementPoint(pep.RPCPolicyEnforcementPointOptions{
		ResponseHandler:                       handler,
		UserPolicyDecisionPointAdapter:        fakeUserPDP{},
		AccountUserPolicyDecisionPointAdapter: fakeAccountPDP{err: errors.New("user [owner] is not authorized to use request's account [app1/owner]")},
	})
	require.NoError(t, err)

	body := `{"method":"eth_signTransaction","id":1,"params":[{"from":"` + address + `"}]}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	ctx := context.WithValue(req.Context(), requestcontext.UserContextKey, userID)
	ctx = context.WithValue(ctx, requestcontext.ApplicationContextKey, appID)
	ctx = context.WithValue(ctx, requestcontext.ActionContextKey, "eth_signTransaction")
	req = req.WithContext(ctx)

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler must not run on a denied request")
	})

	rr := httptest.NewRecorder()
	point.AuthorizeAccount(next).ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
	responseBody := rr.Body.String()
	require.NotContains(t, responseBody, userID, "denied response must not leak the user id")
	require.NotContains(t, responseBody, appID, "denied response must not leak the application id")
	require.NotContains(t, responseBody, address, "denied response must not leak the account address")

	var resp httpinfra.ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, "request not authorized", resp.Details.Message)
}

// capturingAccountPDP records the account address it was asked to authorize.
type capturingAccountPDP struct {
	gotAddress string
	err        error
}

func (f *capturingAccountPDP) AuthorizeAccountUser(_ context.Context, input pep.AuthorizeAccountUserInput) (*pep.AuthorizeAccountUserOutput, error) {
	f.gotAddress = input.Address.String()
	return &pep.AuthorizeAccountUserOutput{}, f.err
}

// TestAuthorizeAccount_SignTypedData_AuthorizesAddressField checks that eth_signTypedData is subject
// to per-account authorization and that the signer account is read from the [address] param (not [from]).
func TestAuthorizeAccount_SignTypedData_AuthorizesAddressField(t *testing.T) {
	const (
		userID  = "owner"
		appID   = "app1"
		account = "0x970e8128ab834e8eac17ab8e3812f010678cf791"
	)

	handler, err := httpinfra.ProvideDefaultHTTPResponseHandler(httpinfra.DefaultHTTPResponseHandlerOptions{
		HTTPMetrics: httpinfra.DefaultHTTPMetrics{},
	})
	require.NoError(t, err)

	capture := &capturingAccountPDP{}
	point, err := pep.ProvideRPCPolicyEnforcementPoint(pep.RPCPolicyEnforcementPointOptions{
		ResponseHandler:                       handler,
		UserPolicyDecisionPointAdapter:        fakeUserPDP{},
		AccountUserPolicyDecisionPointAdapter: capture,
	})
	require.NoError(t, err)

	body := `{"method":"eth_signTypedData","id":1,"params":[{"address":"` + account + `","typedData":{}}]}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	ctx := context.WithValue(req.Context(), requestcontext.UserContextKey, userID)
	ctx = context.WithValue(ctx, requestcontext.ApplicationContextKey, appID)
	ctx = context.WithValue(ctx, requestcontext.ActionContextKey, "rpc.method.eth_signTypedData")
	req = req.WithContext(ctx)

	nextRan := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextRan = true
	})

	rr := httptest.NewRecorder()
	point.AuthorizeAccount(next).ServeHTTP(rr, req)

	require.True(t, nextRan, "an authorized typed data request must be served")
	require.Equal(t, http.StatusOK, rr.Code)
	require.Truef(t, strings.EqualFold(account, capture.gotAddress), "expected authorization on account %s, got %s", account, capture.gotAddress)
}

// TestAuthorizeAccount_SignTypedData_DeniedWhenUnauthorized is the regression guard for the exposure
// fix: before eth_signTypedData was authorized, an unauthorized caller would have been served. It must
// now be rejected with the generic 403 and the next handler must not run.
func TestAuthorizeAccount_SignTypedData_DeniedWhenUnauthorized(t *testing.T) {
	const account = "0x970e8128ab834e8eac17ab8e3812f010678cf791"

	handler, err := httpinfra.ProvideDefaultHTTPResponseHandler(httpinfra.DefaultHTTPResponseHandlerOptions{
		HTTPMetrics: httpinfra.DefaultHTTPMetrics{},
	})
	require.NoError(t, err)

	point, err := pep.ProvideRPCPolicyEnforcementPoint(pep.RPCPolicyEnforcementPointOptions{
		ResponseHandler:                       handler,
		UserPolicyDecisionPointAdapter:        fakeUserPDP{},
		AccountUserPolicyDecisionPointAdapter: fakeAccountPDP{err: errors.New("user is not authorized to use request's account")},
	})
	require.NoError(t, err)

	body := `{"method":"eth_signTypedData","id":1,"params":[{"address":"` + account + `","typedData":{}}]}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	ctx := context.WithValue(req.Context(), requestcontext.UserContextKey, "owner")
	ctx = context.WithValue(ctx, requestcontext.ApplicationContextKey, "app1")
	ctx = context.WithValue(ctx, requestcontext.ActionContextKey, "rpc.method.eth_signTypedData")
	req = req.WithContext(ctx)

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler must not run on a denied request")
	})

	rr := httptest.NewRecorder()
	point.AuthorizeAccount(next).ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
}

// TestAuthorizeAccount_SignTypedData_AuthorizesTheSignedAccountNotFrom is the regression guard for the
// authorization-diversion bug. eth_signTypedData signs with the `address` param, so authorization must
// key off `address` even when a `from` is also present. Otherwise a caller authorized for `from` could
// have the PEP approve `from` while the request signs with a different, unauthorized `address`.
func TestAuthorizeAccount_SignTypedData_AuthorizesTheSignedAccountNotFrom(t *testing.T) {
	const (
		fromAccount   = "0x970e8128ab834e8eac17ab8e3812f010678cf791"
		signedAccount = "0x53d284357ec70ce289d6d64134dfac8e511c8a3d"
	)

	handler, err := httpinfra.ProvideDefaultHTTPResponseHandler(httpinfra.DefaultHTTPResponseHandlerOptions{
		HTTPMetrics: httpinfra.DefaultHTTPMetrics{},
	})
	require.NoError(t, err)

	capture := &capturingAccountPDP{}
	point, err := pep.ProvideRPCPolicyEnforcementPoint(pep.RPCPolicyEnforcementPointOptions{
		ResponseHandler:                       handler,
		UserPolicyDecisionPointAdapter:        fakeUserPDP{},
		AccountUserPolicyDecisionPointAdapter: capture,
	})
	require.NoError(t, err)

	body := `{"method":"eth_signTypedData","id":1,"params":[{"from":"` + fromAccount + `","address":"` + signedAccount + `","typedData":{}}]}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	ctx := context.WithValue(req.Context(), requestcontext.UserContextKey, "owner")
	ctx = context.WithValue(ctx, requestcontext.ApplicationContextKey, "app1")
	ctx = context.WithValue(ctx, requestcontext.ActionContextKey, "rpc.method.eth_signTypedData")
	req = req.WithContext(ctx)

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	rr := httptest.NewRecorder()
	point.AuthorizeAccount(next).ServeHTTP(rr, req)

	require.Truef(t, strings.EqualFold(signedAccount, capture.gotAddress),
		"authorization must key off the signed account (address=%s), got %s", signedAccount, capture.gotAddress)
	require.Falsef(t, strings.EqualFold(fromAccount, capture.gotAddress),
		"authorization must not key off the [from] field for typed data")
}
