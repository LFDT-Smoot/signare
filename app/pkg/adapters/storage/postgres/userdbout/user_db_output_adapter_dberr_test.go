package userdbout_test

import (
	"context"
	"database/sql/driver"
	stderrors "errors"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/adapters/storage/postgres/userdbout"
	persistencesql "github.com/lfdt-smoot/signare/app/pkg/commons/persistence/sql"
	"github.com/lfdt-smoot/signare/app/pkg/infra/storage/userdb"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/user"
	"github.com/lfdt-smoot/signare/app/test/fakedb"

	"github.com/stretchr/testify/require"
)

// TestEdit_RowsAffectedErrorIsReported is the DB-10 regression guard for userdbout.Edit: when
// result.Result.RowsAffected() fails, the adapter must surface that error rather than returning
// the unrelated (nil) variable, which previously masked the real failure.
func TestEdit_RowsAffectedErrorIsReported(t *testing.T) {
	rowsAffectedErr := stderrors.New("rows affected unavailable")
	conn, err := fakedb.NewConnection(fakedb.Behavior{
		QueryColumns:    []string{"exists_result"},
		QueryValues:     [][]driver.Value{{true}},
		RowsAffectedErr: rowsAffectedErr,
	})
	require.NoError(t, err)

	fw, err := persistencesql.NewPersistenceFw(persistencesql.FwOptions{Connection: conn})
	require.NoError(t, err)
	cfg, err := fakedb.MapperStatements("signare.user", map[string]string{
		"exists": "SELECT exists_result FROM cfg_user WHERE id=:id AND application_id=:application_id",
		"update": "UPDATE cfg_user SET id=:id WHERE application_id=:application_id",
	})
	require.NoError(t, err)
	require.NoError(t, fw.AddConfig(cfg))

	infra, err := userdb.ProvideUserRepositoryInfra(userdb.UserRepositoryInfraOptions{GenericStorage: fw})
	require.NoError(t, err)
	repository, err := userdbout.NewRepository(userdbout.RepositoryOptions{Infra: infra})
	require.NoError(t, err)

	editedUser := user.User{}
	editedUser.ID = "user-1"
	editedUser.ApplicationID = "app-1"
	editedUser.InternalResourceID = "internal-user-1"
	editedUser.Roles = []string{"role-1"}

	_, editErr := repository.Edit(context.Background(), editedUser)

	require.Error(t, editErr)
	require.Contains(t, editErr.Error(), rowsAffectedErr.Error())
}
