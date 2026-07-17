package pdp_test

import (
	"context"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/authorization/pdp"

	"github.com/stretchr/testify/require"
)

// fakeUsersPIP returns a fixed set of roles for the application (user) branch.
type fakeUsersPIP struct {
	roles []string
}

func (f fakeUsersPIP) GetUserRoles(_ context.Context, _ pdp.GetUserRolesInput) (*pdp.GetUserRolesOutput, error) {
	return &pdp.GetUserRolesOutput{Roles: f.roles}, nil
}

// fakeAdminsPIP returns a fixed set of roles for the admin branch.
type fakeAdminsPIP struct {
	roles []string
}

func (f fakeAdminsPIP) GetAdminRoles(_ context.Context, _ pdp.GetAdminRolesInput) (*pdp.GetAdminRolesOutput, error) {
	return &pdp.GetAdminRolesOutput{Roles: f.roles}, nil
}

// fakeActionsPIP expands roles into actions using a static map, mirroring the YAML role-to-action mapping.
type fakeActionsPIP struct {
	actionsByRole map[string][]string
}

func (f fakeActionsPIP) ListActions(_ context.Context, input pdp.ListActionsInput) (*pdp.ListActionsOutput, error) {
	all := make([]string, 0)
	for _, r := range input.Roles {
		all = append(all, f.actionsByRole[r]...)
	}
	return &pdp.ListActionsOutput{Actions: *pdp.NewActions(all)}, nil
}

type fakeAccountsPIP struct{}

func (f fakeAccountsPIP) GetAccount(_ context.Context, _ pdp.GetAccountInput) (*pdp.GetAccountOutput, error) {
	return &pdp.GetAccountOutput{}, nil
}

// roleActions mirrors the relevant subset of the default role-to-action mapping, including the
// (mis-assigned) signer-admin -> admin.* expansion that the defense-in-depth guard must neutralize.
var roleActions = map[string][]string{
	"signer-admin":      {"admin.applications.create", "admin.users.create", "application.users.create"},
	"application-admin": {"application.users.create", "application.accounts.create"},
}

func newPDP(t *testing.T, users pdp.UsersPolicyInformationPort, admins pdp.AdminsPolicyInformationPort) *pdp.DefaultPolicyDecisionPointUseCase {
	t.Helper()
	useCase, err := pdp.ProvideDefaultPolicyDecisionPointUseCase(pdp.DefaultPolicyDecisionPointUseCaseOptions{
		AccountsPolicyInformationAdapter:  fakeAccountsPIP{},
		ActionsPolicyInformationPointPort: fakeActionsPIP{actionsByRole: roleActions},
		AdminsPolicyInformationAdapter:    admins,
		UsersPolicyInformationAdapter:     users,
	})
	require.NoError(t, err)
	return useCase
}

func ptr(s string) *string {
	return &s
}

func TestAuthorizeUser_ApplicationBranchDeniesAdminActions(t *testing.T) {
	ctx := context.Background()

	t.Run("signer-admin assigned to an application user cannot reach admin actions", func(t *testing.T) {
		useCase := newPDP(t, fakeUsersPIP{roles: []string{"signer-admin"}}, fakeAdminsPIP{})
		output, err := useCase.AuthorizeUser(ctx, pdp.AuthorizeUserInput{
			UserID:        "user-1",
			ApplicationID: ptr("application-1"),
			ActionID:      "admin.applications.create",
		})
		require.Error(t, err)
		require.True(t, errors.IsPreconditionFailed(err))
		require.Nil(t, output)
	})

	t.Run("application action is still authorized in the application branch", func(t *testing.T) {
		useCase := newPDP(t, fakeUsersPIP{roles: []string{"application-admin"}}, fakeAdminsPIP{})
		output, err := useCase.AuthorizeUser(ctx, pdp.AuthorizeUserInput{
			UserID:        "user-1",
			ApplicationID: ptr("application-1"),
			ActionID:      "application.users.create",
		})
		require.NoError(t, err)
		require.NotNil(t, output)
	})
}

func TestAuthorizeUser_AdminBranchUnchanged(t *testing.T) {
	ctx := context.Background()

	t.Run("admin without application header is authorized for admin actions", func(t *testing.T) {
		useCase := newPDP(t, fakeUsersPIP{}, fakeAdminsPIP{roles: []string{"signer-admin"}})
		output, err := useCase.AuthorizeUser(ctx, pdp.AuthorizeUserInput{
			UserID:   "admin-1",
			ActionID: "admin.applications.create",
		})
		require.NoError(t, err)
		require.NotNil(t, output)
	})

	t.Run("empty application header is treated as the admin branch", func(t *testing.T) {
		useCase := newPDP(t, fakeUsersPIP{}, fakeAdminsPIP{roles: []string{"signer-admin"}})
		output, err := useCase.AuthorizeUser(ctx, pdp.AuthorizeUserInput{
			UserID:        "admin-1",
			ApplicationID: ptr(""),
			ActionID:      "admin.applications.create",
		})
		require.NoError(t, err)
		require.NotNil(t, output)
	})
}
