package pep_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger-labs/signare/app/pkg/infra/httpinfra"
	"github.com/hyperledger-labs/signare/app/pkg/infra/middleware/authorization/pep"
	"github.com/hyperledger-labs/signare/app/pkg/infra/requestcontext"
	signererrors "github.com/hyperledger-labs/signare/app/pkg/internal/errors"

	"github.com/stretchr/testify/require"
)

type fakeUserPDP struct {
	err error
}

func (f fakeUserPDP) AuthorizeUser(context.Context, pep.AuthorizeUserInput) (*pep.AuthorizeUserOutput, error) {
	return nil, f.err
}

type fakeAccountPDP struct {
	err error
}

func (f fakeAccountPDP) AuthorizeAccountUser(context.Context, pep.AuthorizeAccountUserInput) (*pep.AuthorizeAccountUserOutput, error) {
	return nil, f.err
}

// TestAuthorizeUser_Denied_GenericForbiddenNoIdentifierLeak checks a denied authorization returns the
// constant generic 403 message and does not echo the decision-point error (which embeds the user id).
// The fake mirrors the real decision-point error: a PreconditionFailed use-case error carrying a
// human-readable message with the user id, which the use-case sanitizer would not have scrubbed.
func TestAuthorizeUser_Denied_GenericForbiddenNoIdentifierLeak(t *testing.T) {
	handler, err := httpinfra.ProvideDefaultHTTPResponseHandler(httpinfra.DefaultHTTPResponseHandlerOptions{
		HTTPMetrics: httpinfra.DefaultHTTPMetrics{},
	})
	require.NoError(t, err)

	decisionPointErr := signererrors.PreconditionFailed().SetHumanReadableMessage("action not authorized for user [%s]", "owner")
	point, err := pep.ProvideHTTPPolicyEnforcementPoint(pep.HTTPPolicyEnforcementPointOptions{
		ResponseHandler:                       handler,
		UserPolicyDecisionPointAdapter:        fakeUserPDP{err: decisionPointErr},
		AccountUserPolicyDecisionPointAdapter: fakeAccountPDP{},
	})
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := context.WithValue(req.Context(), requestcontext.UserContextKey, "owner")
	ctx = context.WithValue(ctx, requestcontext.ActionContextKey, "some.action")
	req = req.WithContext(ctx)

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler must not run on a denied request")
	})
	point.AuthorizeUser(next).ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
	body := rr.Body.String()
	require.NotContains(t, body, "owner", "denied response must not leak the user id")

	var resp httpinfra.ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, "request not authorized", resp.Details.Message)
	require.NotEmpty(t, resp.Details.TraceableErrorId, "denied response must carry a traceable id linking to the server-side log")
}
