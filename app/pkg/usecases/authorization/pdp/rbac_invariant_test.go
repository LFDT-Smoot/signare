package pdp

import (
	"strings"
	"testing"

	embedded "github.com/hyperledger-labs/signare/app"
	"github.com/hyperledger-labs/signare/app/pkg/usecases/authorization/role"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type rbacRole struct {
	ID          string   `yaml:"id"`
	Scope       string   `yaml:"scope"`
	Permissions []string `yaml:"permissions"`
}

type rbacRoles struct {
	Roles []rbacRole `yaml:"roles"`
}

type rbacPermission struct {
	ID      string   `yaml:"id"`
	Actions []string `yaml:"actions"`
}

type rbacPermissions struct {
	Permissions []rbacPermission `yaml:"permissions"`
}

// TestRBACInvariant_AdminExclusiveActionsAreInAdminNamespace pins the invariant that the
// application-branch guard in AuthorizeUser depends on: every action reachable only through
// admin-scoped roles lives under the adminActionPrefix namespace. The guard keys on the action
// namespace rather than role scope, so if a future privileged action were granted only to an
// admin-scoped role but placed under a different namespace, the guard would silently fail to block
// it. This test catches that drift at build time against the real embedded RBAC config.
func TestRBACInvariant_AdminExclusiveActionsAreInAdminNamespace(t *testing.T) {
	var roles rbacRoles
	rolesBytes, err := embedded.RBACFiles.ReadFile("include/rbac/roles.yaml")
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(rolesBytes, &roles))

	var permissions rbacPermissions
	permissionsBytes, err := embedded.RBACFiles.ReadFile("include/rbac/permissions.yaml")
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(permissionsBytes, &permissions))

	actionsByPermission := make(map[string][]string, len(permissions.Permissions))
	for _, p := range permissions.Permissions {
		actionsByPermission[p.ID] = p.Actions
	}

	adminActions := make(map[string]bool)
	applicationActions := make(map[string]bool)
	for _, r := range roles.Roles {
		target := applicationActions
		if role.Scope(r.Scope) == role.ScopeAdmin {
			target = adminActions
		}
		for _, permission := range r.Permissions {
			for _, action := range actionsByPermission[permission] {
				target[action] = true
			}
		}
	}

	for action := range adminActions {
		if applicationActions[action] {
			// Shared with an application-scoped role, so it is reachable in the application branch
			// by design and is not an admin-exclusive action.
			continue
		}
		require.Truef(t, strings.HasPrefix(action, adminActionPrefix),
			"admin-exclusive action %q is outside the %q namespace; the application-branch guard in AuthorizeUser would not block it",
			action, adminActionPrefix)
	}
}
