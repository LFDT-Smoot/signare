package httpin

import (
	"context"
	"testing"

	generatedhttpinfra "github.com/lfdt-smoot/signare/app/pkg/infra/generated/httpinfra"
	"github.com/lfdt-smoot/signare/app/pkg/infra/requestcontext"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/user"

	"github.com/stretchr/testify/require"
)

// capturingUserUseCase records the input the adapter builds, so the wiring between the request
// context and the use case can be asserted without a database.
type capturingUserUseCase struct {
	user.UserUseCase
	createInput user.CreateUserInput
	editInput   user.EditUserInput
}

func (c *capturingUserUseCase) CreateUser(_ context.Context, input user.CreateUserInput) (*user.CreateUserOutput, error) {
	c.createInput = input
	return &user.CreateUserOutput{}, nil
}

func (c *capturingUserUseCase) EditUser(_ context.Context, input user.EditUserInput) (*user.EditUserOutput, error) {
	c.editInput = input
	return &user.EditUserOutput{}, nil
}

func (c *capturingUserUseCase) ListAccounts(_ context.Context, _ user.ListAccountsInput) (*user.ListAccountsOutput, error) {
	return &user.ListAccountsOutput{}, nil
}

func contextWith(userID, applicationID string) context.Context {
	ctx := context.Background()
	if userID != "" {
		ctx = context.WithValue(ctx, requestcontext.UserContextKey, userID)
	}
	if applicationID != "" {
		ctx = context.WithValue(ctx, requestcontext.ApplicationContextKey, applicationID)
	}
	return ctx
}

// TestCallerFromContext covers the translation between the authenticated request context and the
// value the use case makes its decision on. Getting this wrong disables the self-service guard
// silently, so it is asserted directly rather than only through the use case.
func TestCallerFromContext(t *testing.T) {
	tests := []struct {
		name                 string
		userID               string
		applicationID        string
		wantCaller           user.Caller
		wantApplicationScope bool
	}{
		{
			name:                 "application-scoped caller carries both identifiers",
			userID:               "alice",
			applicationID:        "app1",
			wantCaller:           user.Caller{ID: "alice", ApplicationID: "app1"},
			wantApplicationScope: true,
		},
		{
			// A signer-admin reaches application routes without the application header, which is what
			// distinguishes them from an application-scoped caller.
			name:                 "administrator has no application",
			userID:               "root",
			wantCaller:           user.Caller{ID: "root"},
			wantApplicationScope: false,
		},
		{
			name:                 "absent identifiers yield the zero caller",
			wantCaller:           user.Caller{},
			wantApplicationScope: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			caller := callerFromContext(contextWith(test.userID, test.applicationID))

			require.Equal(t, test.wantCaller, caller)
			require.Equal(t, test.wantApplicationScope, caller.IsApplicationScoped())
		})
	}
}

// TestAdaptApplicationUsersCreate_PopulatesCaller and its Edit twin are the tripwire for the wiring
// itself. The use-case guard is well covered, but it is inert unless the adapter passes the caller
// in, and removing that one line per route is an easy thing to do during a refactor. Without these,
// the whole suite stays green while the vulnerability is fully restored.
func TestAdaptApplicationUsersCreate_PopulatesCaller(t *testing.T) {
	useCase := &capturingUserUseCase{}
	adapter, err := ProvideDefaultApplicationAPIAdapter(DefaultApplicationAPIAdapterOptions{UserUseCase: useCase})
	require.NoError(t, err)

	userID := "target"
	roles := []string{"transaction-signer"}
	_, httpErr := adapter.AdaptApplicationUsersCreate(contextWith("alice", "app1"), generatedhttpinfra.ApplicationUsersCreateRequest{
		ApplicationId: "app1",
		UserCreation: generatedhttpinfra.UserCreation{
			Meta: &generatedhttpinfra.ResourceMetaCreation{Id: &userID},
			Spec: &generatedhttpinfra.UserCreationSpec{Roles: &roles},
		},
	})
	require.Nil(t, httpErr)

	require.Equal(t, user.Caller{ID: "alice", ApplicationID: "app1"}, useCase.createInput.Caller,
		"CreateUser must receive the authenticated caller, otherwise the self-service guard is inert")
}

func TestAdaptApplicationUsersEdit_PopulatesCaller(t *testing.T) {
	useCase := &capturingUserUseCase{}
	adapter, err := ProvideDefaultApplicationAPIAdapter(DefaultApplicationAPIAdapterOptions{UserUseCase: useCase})
	require.NoError(t, err)

	resourceVersion := "1"
	roles := []string{"transaction-signer"}
	_, httpErr := adapter.AdaptApplicationUsersEdit(contextWith("alice", "app1"), generatedhttpinfra.ApplicationUsersEditRequest{
		ApplicationId: "app1",
		UserId:        "target",
		UserUpdate: generatedhttpinfra.UserUpdate{
			Meta: &generatedhttpinfra.ResourceMetaUpdate{ResourceVersion: &resourceVersion},
			Spec: &generatedhttpinfra.UserUpdateSpec{Roles: &roles},
		},
	})
	require.Nil(t, httpErr)

	require.Equal(t, user.Caller{ID: "alice", ApplicationID: "app1"}, useCase.editInput.Caller,
		"EditUser must receive the authenticated caller, otherwise the self-service guard is inert")
}
