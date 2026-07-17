package httpinfra_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/hyperledger-labs/signare/app/pkg/infra/httpinfra"

	"github.com/stretchr/testify/require"
)

// TestNewForbiddenHTTPError_SanitizesMessageAndRetainsOriginal verifies the helper exposes only the
// constant generic message to the client while keeping the original error for server-side logging.
func TestNewForbiddenHTTPError_SanitizesMessageAndRetainsOriginal(t *testing.T) {
	originalErr := errors.New("action not authorized for user [owner]")

	httpErr := httpinfra.NewForbiddenHTTPError(context.Background(), originalErr)

	require.Equal(t, http.StatusForbidden, httpErr.Code())
	require.Equal(t, "request not authorized", httpErr.Error())
	require.False(t, strings.Contains(httpErr.Error(), "owner"), "client message must not leak identifiers")
	require.Equal(t, originalErr, httpErr.OriginalError(), "original error must be retained for server-side logging")
}
