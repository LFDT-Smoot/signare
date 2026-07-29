package accountdbout_test

import (
	"context"
	"database/sql/driver"
	stderrors "errors"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/adapters/storage/postgres/accountdbout"
	persistencesql "github.com/lfdt-smoot/signare/app/pkg/commons/persistence/sql"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/infra/storage/accountdb"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/user"
	"github.com/lfdt-smoot/signare/app/test/fakedb"

	"github.com/stretchr/testify/require"
)

// TestRemove_RemoveErrorIsReported is the DB-10 regression guard for accountdbout.Remove: when
// the underlying delete fails, the adapter must surface that error rather than returning the
// unrelated (nil) variable, which previously made a failed delete look like a success.
func TestRemove_RemoveErrorIsReported(t *testing.T) {
	addr, err := address.NewFromHexString("0x1111111111111111111111111111111111111111")
	require.NoError(t, err)

	removeErr := stderrors.New("delete failed at db")
	conn, err := fakedb.NewConnection(fakedb.Behavior{
		QueryColumns: []string{"internal_resource_id", "address", "application_id", "user_id"},
		QueryValues:  [][]driver.Value{{"internal-account-1", addr.String(), "app-1", "user-1"}},
		ExecErr:      removeErr,
	})
	require.NoError(t, err)

	fw, err := persistencesql.NewPersistenceFw(persistencesql.FwOptions{Connection: conn})
	require.NoError(t, err)
	cfg, err := fakedb.MapperStatements("signare.account", map[string]string{
		"getById": "SELECT internal_resource_id, address, application_id, user_id FROM cfg_account WHERE address=:address AND application_id=:application_id AND user_id=:user_id",
		"delete":  "DELETE FROM cfg_account WHERE address=:address AND application_id=:application_id AND user_id=:user_id",
	})
	require.NoError(t, err)
	require.NoError(t, fw.AddConfig(cfg))

	infra, err := accountdb.ProvideAccountRepositoryInfra(accountdb.AccountRepositoryInfraOptions{GenericStorage: fw})
	require.NoError(t, err)
	repository, err := accountdbout.NewRepository(accountdbout.RepositoryOptions{Infra: infra})
	require.NoError(t, err)

	accountID := user.AccountID{
		Address:       addr,
		UserID:        "user-1",
		ApplicationID: "app-1",
	}

	_, removeErrResult := repository.Remove(context.Background(), accountID)

	require.Error(t, removeErrResult)
	require.Contains(t, removeErrResult.Error(), removeErr.Error())
}
