package rpcinfra_test

import (
	"testing"

	embedded "github.com/hyperledger-labs/signare/app"
	"github.com/hyperledger-labs/signare/app/pkg/infra/rpcinfra"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// rpcActionPrefix is the action namespace the RPC context definition composes for a registered
// method: the route name ("rpc.method") joined with the method name.
const rpcActionPrefix = "rpc.method."

type manualActionsFile struct {
	Actions []string `yaml:"actions"`
}

type rbacPermission struct {
	ID      string   `yaml:"id"`
	Actions []string `yaml:"actions"`
}

type rbacPermissionsFile struct {
	Permissions []rbacPermission `yaml:"permissions"`
}

// TestRBACCoverage_EveryPublishedMethodIsRegisteredAndGrantable guards against shipping an RPC method
// that is unreachable. The user-level policy decision point fails closed, so a method whose action is
// neither declared in actions-manual.yaml nor granted by any permission is denied for every user. This
// asserts each published method has both, catching the drift where a method is added to the publisher
// without its RBAC entries.
func TestRBACCoverage_EveryPublishedMethodIsRegisteredAndGrantable(t *testing.T) {
	manualBytes, err := embedded.RBACFiles.ReadFile("include/rbac/actions-manual.yaml")
	require.NoError(t, err)
	var manual manualActionsFile
	require.NoError(t, yaml.Unmarshal(manualBytes, &manual))
	registered := make(map[string]bool, len(manual.Actions))
	for _, action := range manual.Actions {
		registered[action] = true
	}

	permissionsBytes, err := embedded.RBACFiles.ReadFile("include/rbac/permissions.yaml")
	require.NoError(t, err)
	var permissions rbacPermissionsFile
	require.NoError(t, yaml.Unmarshal(permissionsBytes, &permissions))
	granted := make(map[string]bool)
	for _, permission := range permissions.Permissions {
		for _, action := range permission.Actions {
			granted[action] = true
		}
	}

	for _, method := range rpcinfra.SupportedMethods {
		action := rpcActionPrefix + method
		require.Truef(t, registered[action],
			"method %q is published but its action %q is missing from actions-manual.yaml", method, action)
		require.Truef(t, granted[action],
			"method %q is published but its action %q is granted by no permission, so it is denied for every user", method, action)
	}
}
