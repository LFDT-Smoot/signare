package admindbout_test

import (
	"context"
	"database/sql/driver"
	stderrors "errors"
	"testing"

	"github.com/hyperledger-labs/signare/app/pkg/adapters/storage/postgres/admindbout"
	persistencesql "github.com/hyperledger-labs/signare/app/pkg/commons/persistence/sql"
	"github.com/hyperledger-labs/signare/app/pkg/infra/storage/admindb"
	"github.com/hyperledger-labs/signare/app/pkg/usecases/admin"
	"github.com/hyperledger-labs/signare/app/test/fakedb"

	"github.com/stretchr/testify/require"
)

// TestEdit_RowsAffectedErrorIsReported is the DB-10 regression guard for admindbout.Edit, one of
// the additional adapters carrying the same wrong-variable bug: when result.Result.RowsAffected()
// fails, the adapter must surface that error rather than the unrelated (nil) variable.
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
	cfg, err := fakedb.MapperStatements("signare.admin", map[string]string{
		"exists": "SELECT exists_result FROM cfg_admin WHERE id=:id",
		"update": "UPDATE cfg_admin SET description='' WHERE id=:id",
	})
	require.NoError(t, err)
	require.NoError(t, fw.AddConfig(cfg))

	infra := admindb.ProvideAdminRepositoryInfra(admindb.AdminRepositoryInfraOptions{GenericStorage: fw})
	repository, err := admindbout.NewRepository(admindbout.RepositoryOptions{Infra: infra})
	require.NoError(t, err)

	editedAdmin := admin.Admin{}
	editedAdmin.ID = "admin-1"
	editedAdmin.InternalResourceID = "internal-admin-1"
	editedAdmin.Roles = []string{"role-1"}

	_, editErr := repository.Edit(context.Background(), editedAdmin)

	require.Error(t, editErr)
	require.Contains(t, editErr.Error(), rowsAffectedErr.Error())
}
