package sql_test

import (
	"context"
	"database/sql/driver"
	stderrors "errors"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/commons/persistence"
	persistencesql "github.com/lfdt-smoot/signare/app/pkg/commons/persistence/sql"
	"github.com/lfdt-smoot/signare/app/test/fakedb"

	"github.com/stretchr/testify/require"
)

type queryAllRow struct {
	Value string `storage:"value"`
}

type queryAllArgs struct {
	ID string `storage:"id"`
}

func newQueryAllFw(t *testing.T, behavior fakedb.Behavior) *persistencesql.Fw {
	t.Helper()
	conn, err := fakedb.NewConnection(behavior)
	require.NoError(t, err)
	fw, err := persistencesql.NewPersistenceFw(persistencesql.FwOptions{Connection: conn})
	require.NoError(t, err)
	cfg, err := fakedb.MapperStatements("test", map[string]string{
		"select": "SELECT value FROM t WHERE id=:id",
	})
	require.NoError(t, err)
	require.NoError(t, fw.AddConfig(cfg))
	return fw
}

// TestQueryAll_RowIterationErrorIsReported is the DB-7 regression guard: when the row iterator
// fails mid-stream, QueryAll must return an error rather than a truncated slice reported as success.
func TestQueryAll_RowIterationErrorIsReported(t *testing.T) {
	iterErr := stderrors.New("connection dropped mid-iteration")
	fw := newQueryAllFw(t, fakedb.Behavior{
		QueryColumns: []string{"value"},
		QueryIterErr: iterErr,
	})

	var dst []queryAllRow
	err := fw.QueryAll(context.Background(), "test.select", queryAllArgs{ID: "x"}, &dst)

	require.Error(t, err)
	require.True(t, persistence.IsDBResponseCouldNotBeProcessed(err))
}

// TestQueryAll_SuccessReturnsAllRows confirms the happy path still returns every scanned row.
func TestQueryAll_SuccessReturnsAllRows(t *testing.T) {
	fw := newQueryAllFw(t, fakedb.Behavior{
		QueryColumns: []string{"value"},
		QueryValues: [][]driver.Value{
			{"first"},
			{"second"},
		},
	})

	var dst []queryAllRow
	err := fw.QueryAll(context.Background(), "test.select", queryAllArgs{ID: "x"}, &dst)

	require.NoError(t, err)
	require.Len(t, dst, 2)
	require.Equal(t, "first", dst[0].Value)
	require.Equal(t, "second", dst[1].Value)
}
