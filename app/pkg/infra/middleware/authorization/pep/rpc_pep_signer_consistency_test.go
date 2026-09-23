package pep_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/infra/httpinfra"
	"github.com/lfdt-smoot/signare/app/pkg/infra/middleware/authorization/pep"
	"github.com/lfdt-smoot/signare/app/pkg/infra/middleware/entrypoint/rpcbatchrequestsupport"
	"github.com/lfdt-smoot/signare/app/pkg/infra/requestcontext"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra/rpcerrors"

	"github.com/stretchr/testify/require"
)

const (
	authorizedAccountAddress = "0x970e8128ab834e8eac17ab8e3812f010678cf791"
	otherAccountAddress      = "0x1234567890123456789012345678901234567890"
)

// capturingAdapter records the account each signing method hands on. Only the three signing methods
// are implemented; the rest are promoted from the embedded nil interface and would panic if the
// handler called them unexpectedly.
type capturingAdapter struct {
	rpcinfra.JSONRPCAPIAdapter
	gotAccount string
}

func (a *capturingAdapter) AdaptSignTx(_ context.Context, data rpcinfra.SignTXRequestParams) (*string, *rpcerrors.RPCError) {
	a.gotAccount = data.From
	return &signatureStub, nil
}

func (a *capturingAdapter) AdaptPersonalSign(_ context.Context, data rpcinfra.PersonalSignRequestParams) (*string, *rpcerrors.RPCError) {
	a.gotAccount = data.Address
	return &signatureStub, nil
}

func (a *capturingAdapter) AdaptSignTypedData(_ context.Context, data rpcinfra.SignTypedDataRequestParams) (*string, *rpcerrors.RPCError) {
	a.gotAccount = data.Address
	return &signatureStub, nil
}

var signatureStub = "0xsignature"

// signingMethod pairs an account-signing RPC method with the handler that serves it, so a test can
// drive the authorization path and the signing path from one request body.
type signingMethod struct {
	method string
	// accountKey is the params field naming the account the method signs with.
	accountKey string
	// siblingFields are the remaining params the method needs to decode, as a JSON fragment.
	siblingFields string
	// invoke runs the real JSON-RPC handler for this method and returns the account it handed to the
	// adapter, which is the account that would be signed with.
	invoke func(ctx context.Context, handler *rpcinfra.DefaultJSONRPCAPIHandler, request rpcinfra.RPCRequest) (any, *rpcerrors.RPCError)
}

func accountSigningMethods() []signingMethod {
	return []signingMethod{
		{
			method:        rpcinfra.SignTransactionMethod,
			accountKey:    "from",
			siblingFields: `"data":"0x","nonce":"0x1"`,
			invoke: func(ctx context.Context, h *rpcinfra.DefaultJSONRPCAPIHandler, r rpcinfra.RPCRequest) (any, *rpcerrors.RPCError) {
				return h.HandleSignTX(ctx, r)
			},
		},
		{
			method:        rpcinfra.PersonalSignMethod,
			accountKey:    "address",
			siblingFields: `"message":"0xdeadbeef"`,
			invoke: func(ctx context.Context, h *rpcinfra.DefaultJSONRPCAPIHandler, r rpcinfra.RPCRequest) (any, *rpcerrors.RPCError) {
				return h.HandlePersonalSign(ctx, r)
			},
		},
		{
			method:        rpcinfra.SignTypedDataMethod,
			accountKey:    "address",
			siblingFields: `"typedData":{"types":{"EIP712Domain":[]},"primaryType":"EIP712Domain","domain":{},"message":{}}`,
			invoke: func(ctx context.Context, h *rpcinfra.DefaultJSONRPCAPIHandler, r rpcinfra.RPCRequest) (any, *rpcerrors.RPCError) {
				return h.HandleSignTypedData(ctx, r)
			},
		},
	}
}

// signerAccount runs the real JSON-RPC handler over params and reports the account it passed to the
// adapter. Driving the handler rather than re-deriving its decode is the point: the test exists to
// catch the authorization path and the signing path disagreeing, so the signing side has to be the
// production one, not a restatement of it. It also puts ValidateParams in the path, which the handler
// calls and a bare ProcessParams does not.
func (m signingMethod) signerAccount(t *testing.T, params json.RawMessage) (string, error) {
	t.Helper()

	adapter := &capturingAdapter{}
	handler, err := rpcinfra.NewDefaultJSONRPCAPIHandler(rpcinfra.DefaultJSONRPCAPIHandlerOptions{Adapter: adapter})
	require.NoError(t, err)

	ctx := context.WithValue(context.Background(), requestcontext.ApplicationContextKey, "app1")
	if _, rpcErr := m.invoke(ctx, handler, rpcinfra.RPCRequest{Params: params}); rpcErr != nil {
		return "", rpcErr
	}
	return adapter.gotAccount, nil
}

// keyCasings returns the spellings of name that encoding/json resolves to the same struct field but
// that an exact map lookup does not.
func keyCasings(name string) []string {
	casings := []string{name, strings.ToUpper(name), strings.ToUpper(name[:1]) + name[1:]}
	mixed := []rune(name)
	for i := 1; i < len(mixed); i += 2 {
		mixed[i] = []rune(strings.ToUpper(string(mixed[i])))[0]
	}
	return append(casings, string(mixed))
}

// TestAuthorizeAccount_SignerIsTheAuthorizedAccount holds the property this middleware exists for:
// for any request body, the account authorization resolves is the account the handler signs with, or
// the request is refused outright. Never one account authorized and a different one signed.
//
// It is checked over every ordered pair of spellings of the signing-account key, because
// encoding/json resolves those to one struct field and keeps the last, while a map lookup keeps them
// apart and reads the exact key. Enumerating the pairs rather than a few chosen bodies is what makes
// the test independent of the decoding the implementation happens to use.
func TestAuthorizeAccount_SignerIsTheAuthorizedAccount(t *testing.T) {
	for _, method := range accountSigningMethods() {
		casings := keyCasings(method.accountKey)
		for _, form := range []string{"array", "object"} {
			for _, first := range casings {
				for _, second := range casings {
					if first == second {
						continue
					}
					name := fmt.Sprintf("%s/%s/%s_then_%s", method.method, form, first, second)
					t.Run(name, func(t *testing.T) {
						object := fmt.Sprintf(`{%q:%q,%q:%q,%s}`,
							first, otherAccountAddress, second, authorizedAccountAddress, method.siblingFields)
						params := object
						if form == "array" {
							params = "[" + object + "]"
						}
						body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":%s}`, method.method, params)

						authorized, status := authorizeAccountForTest(t, method.method, body)
						signer, signErr := method.signerAccount(t, json.RawMessage(params))

						if status != http.StatusOK {
							// Refused at the gate, which is the outcome this fix produces.
							require.Empty(t, authorized, "a refused request must not have authorized an account")
							return
						}
						require.NoError(t, signErr, "a request the gate allowed must decode for signing")
						require.Truef(t, strings.EqualFold(authorized, signer),
							"authorized %s but would sign with %s", authorized, signer)
					})
				}
			}
		}
	}
}

// TestAuthorizeAccount_SignerIsTheAuthorizedAccountForOneSpelling covers the half of the property
// that a body naming the account twice cannot reach: agreement on a request that is actually served.
// Every pair in the test above folds together and is refused at the gate, so its equality assertion
// never runs. These bodies name the account once, in each spelling in turn, so the request is allowed
// and both sides have to resolve it to the same account.
//
// It is also the case that caught the original bug from the other side: before the fix, an array-form
// body spelled [{"From":...}] authorized the account and then failed to sign, because the handler
// looked up the exact key "from".
func TestAuthorizeAccount_SignerIsTheAuthorizedAccountForOneSpelling(t *testing.T) {
	for _, method := range accountSigningMethods() {
		for _, form := range []string{"array", "object"} {
			for _, spelling := range keyCasings(method.accountKey) {
				t.Run(fmt.Sprintf("%s/%s/%s", method.method, form, spelling), func(t *testing.T) {
					object := fmt.Sprintf(`{%q:%q,%s}`, spelling, authorizedAccountAddress, method.siblingFields)
					params := object
					if form == "array" {
						params = "[" + object + "]"
					}
					body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":%s}`, method.method, params)

					authorized, status := authorizeAccountForTest(t, method.method, body)
					require.Equal(t, http.StatusOK, status, "a request naming the account once must be served")
					signer, signErr := method.signerAccount(t, json.RawMessage(params))
					require.NoError(t, signErr, "a request the gate allowed must decode for signing")

					require.Truef(t, strings.EqualFold(authorized, signer),
						"authorized %s but would sign with %s", authorized, signer)
					require.Truef(t, strings.EqualFold(authorizedAccountAddress, signer),
						"expected signing with %s, got %s", authorizedAccountAddress, signer)
				})
			}
		}
	}
}

// TestAuthorizeAccount_SignerIsTheAuthorizedAccountInABatch runs the same property over the batch
// entrypoint. FanOutRPCBatchRequest re-marshals each element before the authorization middleware sees
// it, and that round trip only preserves an ambiguous params object because RPCRequest.Params is
// json.RawMessage. Were it ever widened to any, Go would re-encode the params as a map with its keys
// sorted, silently changing which spelling the handler's decode keeps and reopening the bypass for
// batched requests. Nothing else pins that field's type.
func TestAuthorizeAccount_SignerIsTheAuthorizedAccountInABatch(t *testing.T) {
	for _, method := range accountSigningMethods() {
		t.Run(method.method, func(t *testing.T) {
			exact := method.accountKey
			folded := strings.ToUpper(exact[:1]) + exact[1:]
			params := fmt.Sprintf(`[{%q:%q,%q:%q,%s}]`,
				exact, otherAccountAddress, folded, authorizedAccountAddress, method.siblingFields)
			batch := fmt.Sprintf(`[{"jsonrpc":"2.0","id":1,"method":%q,"params":%s}]`, method.method, params)

			for _, element := range fanOutBatchForTest(t, batch) {
				authorized, status := authorizeAccountForTest(t, method.method, element)
				require.Equal(t, http.StatusBadRequest, status,
					"an ambiguous account param must be refused inside a batch too")
				require.Empty(t, authorized, "a refused request must not have authorized an account")
			}
		})
	}
}

// fanOutBatchForTest reproduces the decode-and-re-marshal that FanOutRPCBatchRequest performs on each
// element of a batch, so the test drives the same bytes the middleware chain would hand downstream.
func fanOutBatchForTest(t *testing.T, batch string) []string {
	t.Helper()

	var elements []rpcbatchrequestsupport.RPCRequest
	require.NoError(t, json.Unmarshal([]byte(batch), &elements))
	require.NotEmpty(t, elements)

	bodies := make([]string, 0, len(elements))
	for _, element := range elements {
		marshalled, err := json.Marshal(element)
		require.NoError(t, err)
		bodies = append(bodies, string(marshalled))
	}
	return bodies
}

// TestAuthorizeAccount_RejectsAmbiguousAccountParam pins the specific bypass: naming the signing
// account twice, once exactly and once in another casing, previously authorized the second spelling
// and signed with the first.
func TestAuthorizeAccount_RejectsAmbiguousAccountParam(t *testing.T) {
	for _, method := range accountSigningMethods() {
		t.Run(method.method, func(t *testing.T) {
			exact := method.accountKey
			folded := strings.ToUpper(exact[:1]) + exact[1:]
			params := fmt.Sprintf(`[{%q:%q,%q:%q,%s}]`,
				exact, otherAccountAddress, folded, authorizedAccountAddress, method.siblingFields)
			body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":%s}`, method.method, params)

			authorized, status := authorizeAccountForTest(t, method.method, body)
			require.Equal(t, http.StatusBadRequest, status, "an ambiguous account param must be refused")
			require.Empty(t, authorized, "a refused request must not have authorized an account")

			_, err := method.signerAccount(t, json.RawMessage(params))
			require.Error(t, err, "the signing path must refuse the same params")
		})
	}
}

// TestAuthorizeAccount_AcceptsBothParamForms guards the fix against over-rejecting: a well-formed
// request still works in the positional array form and the bare object form alike.
func TestAuthorizeAccount_AcceptsBothParamForms(t *testing.T) {
	for _, method := range accountSigningMethods() {
		for _, form := range []string{"array", "object"} {
			t.Run(method.method+"/"+form, func(t *testing.T) {
				object := fmt.Sprintf(`{%q:%q,%s}`, method.accountKey, authorizedAccountAddress, method.siblingFields)
				params := object
				if form == "array" {
					params = "[" + object + "]"
				}
				body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":%s}`, method.method, params)

				authorized, status := authorizeAccountForTest(t, method.method, body)
				require.Equal(t, http.StatusOK, status)
				require.Truef(t, strings.EqualFold(authorizedAccountAddress, authorized),
					"expected authorization on %s, got %s", authorizedAccountAddress, authorized)

				signer, err := method.signerAccount(t, json.RawMessage(params))
				require.NoError(t, err)
				require.Truef(t, strings.EqualFold(authorizedAccountAddress, signer),
					"expected signing with %s, got %s", authorizedAccountAddress, signer)
			})
		}
	}
}

// authorizeAccountForTest runs the account authorization middleware over body and reports the account
// it resolved along with the response status. An empty account means the request never reached the
// policy decision point.
func authorizeAccountForTest(t *testing.T, method, body string) (string, int) {
	t.Helper()

	responseHandler, err := httpinfra.ProvideDefaultHTTPResponseHandler(httpinfra.DefaultHTTPResponseHandlerOptions{
		HTTPMetrics: httpinfra.DefaultHTTPMetrics{},
	})
	require.NoError(t, err)

	capture := &capturingAccountPDP{}
	point, err := pep.ProvideRPCPolicyEnforcementPoint(pep.RPCPolicyEnforcementPointOptions{
		ResponseHandler:                       responseHandler,
		UserPolicyDecisionPointAdapter:        fakeUserPDP{},
		AccountUserPolicyDecisionPointAdapter: capture,
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	ctx := context.WithValue(req.Context(), requestcontext.UserContextKey, "owner")
	ctx = context.WithValue(ctx, requestcontext.ApplicationContextKey, "app1")
	ctx = context.WithValue(ctx, requestcontext.ActionContextKey, "rpc.method."+method)
	req = req.WithContext(ctx)

	recorder := httptest.NewRecorder()
	point.AuthorizeAccount(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(recorder, req)

	return capture.gotAddress, recorder.Code
}
