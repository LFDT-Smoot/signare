package rpcinfra_test

import (
	"strings"
	"testing"

	embedded "github.com/lfdt-smoot/signare/app"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra"

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

// TestRBACCoverage_ManualActionsNameOnlyPublishedMethods guards the reverse direction, which the
// rbac-validator cannot. That file is its exemption list from the API spec check, so an entry naming a
// method that does not exist clears that check and is caught only by the orphan-action check, which a
// grant in permissions.yaml then satisfies: exactly the shape a copy-paste into both files produces.
// Only the Go code knows which methods are published. With the test above this pins the file to
// SupportedMethods in both directions, so an exemption is legitimate only if it names a live method.
func TestRBACCoverage_ManualActionsNameOnlyPublishedMethods(t *testing.T) {
	manualBytes, err := embedded.RBACFiles.ReadFile("include/rbac/actions-manual.yaml")
	require.NoError(t, err)
	var manual manualActionsFile
	require.NoError(t, yaml.Unmarshal(manualBytes, &manual))

	published := make(map[string]bool, len(rpcinfra.SupportedMethods))
	for _, method := range rpcinfra.SupportedMethods {
		published[method] = true
	}

	for _, action := range manual.Actions {
		method, isRPCAction := strings.CutPrefix(action, rpcActionPrefix)
		require.Truef(t, isRPCAction,
			"action %q in actions-manual.yaml is outside the %q namespace; the file is the exemption list for the API spec check, so only RPC method actions belong in it",
			action, rpcActionPrefix)
		require.Truef(t, published[method],
			"action %q in actions-manual.yaml names method %q, which is not in SupportedMethods, so it is exempt from the API spec check without being published anywhere",
			action, method)
	}
}
