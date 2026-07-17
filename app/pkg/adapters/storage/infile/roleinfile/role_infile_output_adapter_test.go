package roleinfile_test

import (
	"context"
	"os"
	"path"
	"runtime"
	"testing"
	"testing/fstest"

	"github.com/lfdt-smoot/signare/app/pkg/adapters/storage/infile/roleinfile"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/authorization/role"

	"github.com/stretchr/testify/require"
)

const (
	defaultTestFilesPath = "testdata"
)

func NewDefaultRoleStorageInFileYAMLOutputAdapterForTest() (*roleinfile.DefaultRoleStorageInFile, error) {
	// get the location of the current file
	_, filename, _, _ := runtime.Caller(0)
	basePath := ""
	fileSystem := os.DirFS(path.Join(path.Dir(filename), defaultTestFilesPath))

	adapter, err := roleinfile.ProvideDefaultRoleStorageInFile(roleinfile.DefaultRoleStorageInFileOptions{
		FileSystem: fileSystem,
		BasePath:   basePath,
	})
	if err != nil {
		return nil, err
	}

	return adapter, nil
}

func TestDefaultRoleStorageInFileYAMLOutputAdapter_ListActions_Success(t *testing.T) {
	ctx := context.TODO()

	adapter, err := NewDefaultRoleStorageInFileYAMLOutputAdapterForTest()
	require.NoError(t, err)
	require.NotNil(t, adapter)

	listRolesInput := role.ListRolesInput{}
	listRolesOutput, listRolesErr := adapter.ListRoles(ctx, listRolesInput)
	require.NoError(t, listRolesErr)
	require.NotNil(t, listRolesOutput)

	expectedScopes := map[string]role.Scope{
		"test-admin": role.ScopeAdmin,
		"test-user":  role.ScopeApplication,
	}
	seen := make(map[string]bool, len(expectedScopes))

	for _, r := range listRolesOutput.Roles {
		expectedScope, ok := expectedScopes[r.ID]
		require.True(t, ok)
		require.Equal(t, expectedScope, r.Scope)
		seen[r.ID] = true
	}

	for id := range expectedScopes {
		require.True(t, seen[id])
	}
}

func TestProvideDefaultRoleStorageInFile_RejectsUnsupportedScope(t *testing.T) {
	fileSystem := fstest.MapFS{
		"roles.yaml": &fstest.MapFile{Data: []byte("roles:\n  - id: bad-role\n    scope: nonsense\n    permissions:\n      - allow-manual-actions\n")},
	}

	adapter, err := roleinfile.ProvideDefaultRoleStorageInFile(roleinfile.DefaultRoleStorageInFileOptions{
		FileSystem: fileSystem,
		BasePath:   "",
	})
	require.Error(t, err)
	require.Nil(t, adapter)
}

// TestProvideDefaultRoleStorageInFile_RejectsMissingScope covers the realistic misconfiguration: a
// role whose scope field is omitted entirely (empty string). Like an unsupported scope value, this
// must fail closed at load time rather than default to an assignable scope.
func TestProvideDefaultRoleStorageInFile_RejectsMissingScope(t *testing.T) {
	fileSystem := fstest.MapFS{
		"roles.yaml": &fstest.MapFile{Data: []byte("roles:\n  - id: missing-scope-role\n    permissions:\n      - allow-manual-actions\n")},
	}

	adapter, err := roleinfile.ProvideDefaultRoleStorageInFile(roleinfile.DefaultRoleStorageInFileOptions{
		FileSystem: fileSystem,
		BasePath:   "",
	})
	require.Error(t, err)
	require.Nil(t, adapter)
}
