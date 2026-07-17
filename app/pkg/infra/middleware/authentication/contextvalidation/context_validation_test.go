package contextvalidation_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/infra/httpinfra"
	"github.com/lfdt-smoot/signare/app/pkg/infra/middleware/authentication/contextvalidation"
	"github.com/lfdt-smoot/signare/app/pkg/infra/requestcontext"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

// newValidation builds a RequestContextValidation backed by the real response handler so tests can
// inspect the encoded error body that a client would receive.
func newValidation(t *testing.T) *contextvalidation.RequestContextValidation {
	t.Helper()

	handler, err := httpinfra.ProvideDefaultHTTPResponseHandler(httpinfra.DefaultHTTPResponseHandlerOptions{
		HTTPMetrics: httpinfra.DefaultHTTPMetrics{},
	})
	require.NoError(t, err)

	validation, err := contextvalidation.ProvideRequestContextValidation(contextvalidation.RequestContextValidationOptions{
		ResponseHandler: handler,
	})
	require.NoError(t, err)
	return validation
}

func decodeError(t *testing.T, rr *httptest.ResponseRecorder) httpinfra.ErrorResponse {
	t.Helper()

	var resp httpinfra.ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	return resp
}

func failingNext(t *testing.T) http.Handler {
	return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler must not be called when validation fails")
	})
}

// TestValidateUser_MissingUser_GenericForbidden checks a request without a user in context is denied
// with the constant generic message rather than the internal context-lookup error.
func TestValidateUser_MissingUser_GenericForbidden(t *testing.T) {
	validation := newValidation(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	validation.ValidateUser(failingNext(t)).ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
	require.Equal(t, "request not authorized", decodeError(t, rr).Details.Message)
}

// TestValidateApplication_Mismatch_NoIdentifierLeak checks an application mismatch is denied with the
// generic message and that neither the path nor the header application id appears in the body.
func TestValidateApplication_Mismatch_NoIdentifierLeak(t *testing.T) {
	validation := newValidation(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/applications/secret-path-app/keys", nil)
	req = req.WithContext(context.WithValue(req.Context(), requestcontext.ApplicationContextKey, "secret-header-app"))
	req = mux.SetURLVars(req, map[string]string{"applicationId": "secret-path-app"})
	validation.ValidateApplication(failingNext(t)).ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
	body := rr.Body.String()
	require.NotContains(t, body, "secret-header-app", "denied response must not leak the header application id")
	require.NotContains(t, body, "secret-path-app", "denied response must not leak the path application id")
	require.Equal(t, "request not authorized", decodeError(t, rr).Details.Message)
}

// TestValidateAction_EmptyAction_ReferencesAction checks the empty-action message refers to the action
// and not, as before, to the user.
func TestValidateAction_EmptyAction_ReferencesAction(t *testing.T) {
	validation := newValidation(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), requestcontext.ActionContextKey, ""))
	validation.ValidateAction(failingNext(t)).ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
	require.Equal(t, "the action can't be empty", decodeError(t, rr).Details.Message)
}

// TestValidateAction_MissingAction_GenericForbidden checks a request without an action in context is
// denied with the constant generic message rather than the internal context-lookup error.
func TestValidateAction_MissingAction_GenericForbidden(t *testing.T) {
	validation := newValidation(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	validation.ValidateAction(failingNext(t)).ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
	require.Equal(t, "request not authorized", decodeError(t, rr).Details.Message)
}
