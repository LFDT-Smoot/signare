package httpin

import (
	"context"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/infra/requestcontext"
)

// callerFromContext reads the authenticated principal that the authentication middleware placed in
// the request context, so use cases can apply caller-relative rules without reaching into HTTP.
//
// An absent application header is not an error: it legitimately means the caller is a signer-admin,
// for whom ApplicationID is empty by design. An absent user is, since ValidateUser rejects an empty
// user before any route handler runs, so its absence here means the middleware chain was
// misconfigured. That case is left to the use case, which refuses a caller with no id rather than
// treating it as "not self", so the guard cannot be disabled by a wiring mistake at this layer.
func callerFromContext(ctx context.Context) entities.Caller {
	caller := entities.Caller{}
	if userID, err := requestcontext.UserFromContext(ctx); err == nil && userID != nil {
		caller.ID = *userID
	}
	if applicationID, err := requestcontext.ApplicationFromContext(ctx); err == nil && applicationID != nil {
		caller.ApplicationID = *applicationID
	}
	return caller
}
