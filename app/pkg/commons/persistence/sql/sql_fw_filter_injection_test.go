package sql_test

import (
	"context"
	"fmt"
	"testing"
	"testing/fstest"

	"github.com/lfdt-smoot/signare/app/pkg/commons/persistence"
	sqlfw "github.com/lfdt-smoot/signare/app/pkg/commons/persistence/sql"

	// Registers the sqlite dialect via its init function.
	_ "github.com/lfdt-smoot/signare/app/pkg/commons/persistence/sql/sqlite"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
)

// testMapper renders a filtered list through the same template path used by the
// production mappers: each filter contributes its ToSQLStmt fragment to the WHERE
// clause, and values are bound by sqlx from the args struct.
const testMapper = `<mapping id="test">
    <statement id="list">
        SELECT id, name FROM items
        WHERE 1=1
        {{ if .FilterGroup }}
            {{ range $filter := .FilterGroup.Filters }}
                AND {{ $filter.ToSQLStmt }}
            {{ end }}
        {{ end }}
    </statement>
    <statement id="listOrdered">
        SELECT id, name FROM items
        {{ if .Order }}
            ORDER BY {{ .Order.ToSQLStmt }}
        {{ end }}
    </statement>
</mapping>`

type itemArgs struct {
	Name        string `storage:"name"`
	FilterGroup *persistence.FilterGroup
	Order       *persistence.Order
}

type itemRow struct {
	ID   string `storage:"id"`
	Name string `storage:"name"`
}

// newTestFw stands up an in-memory sqlite-backed framework with an `items` table
// and the test mapper registered. Each test uses a uniquely named shared-cache
// in-memory database so tests stay isolated.
func newTestFw(t *testing.T, dbName string) (*sqlfw.Fw, *sqlx.DB) {
	t.Helper()
	conn, err := sqlfw.NewConnectionFw(sqlfw.ConnectionFwOptions{
		SQLite: &sqlfw.SQLiteInfo{ConnectionString: fmt.Sprintf("file:%s?mode=memory&cache=shared", dbName)},
	})
	require.NoError(t, err)

	db := conn.GetDB()
	// Closing the pool releases the shared-cache in-memory database so repeated runs
	// (e.g. go test -count=N) start from a clean schema rather than colliding.
	t.Cleanup(func() { _ = db.Close() })
	db.MustExec(`CREATE TABLE items (id TEXT, name TEXT, creation_date TEXT)`)

	fw, err := sqlfw.NewPersistenceFw(sqlfw.FwOptions{Connection: conn})
	require.NoError(t, err)

	cfg, err := persistence.NewStorageConfig(persistence.StorageConfigOptions{
		ReadDirAndFileFS: fstest.MapFS{
			"mappers/sqlite/test-mappers.xml": &fstest.MapFile{Data: []byte(testMapper)},
		},
		MappersPath: "mappers",
		Driver:      "sqlite",
	})
	require.NoError(t, err)
	require.NoError(t, fw.AddConfig(*cfg))

	return fw, db
}

// TestQueryAll_QuoteInFilterValueIsBoundAsData proves a value containing a single
// quote is bound as data, not interpreted as SQL: the row whose name is O'Brien is
// matched exactly through an EqualFilter. Had the value been interpolated, the
// embedded quote would have produced a syntax error or matched the wrong rows.
func TestQueryAll_QuoteInFilterValueIsBoundAsData(t *testing.T) {
	fw, db := newTestFw(t, "data_quote")
	db.MustExec(`INSERT INTO items (id, name) VALUES ('1', 'O''Brien'), ('2', 'Normal')`)

	group := &persistence.FilterGroup{Filters: []persistence.Filter{persistence.EqualFilter{By: "name"}}}
	args := itemArgs{Name: "O'Brien", FilterGroup: group}

	var out []itemRow
	err := fw.QueryAll(context.Background(), "test.list", args, &out)
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Equal(t, "O'Brien", out[0].Name)
}

// TestQueryAll_UnsafeFilterIdentifierIsRejected proves an attacker-controlled column
// identifier cannot inject SQL: the malicious By is rejected during template
// rendering, the query fails, and the table is left intact.
func TestQueryAll_UnsafeFilterIdentifierIsRejected(t *testing.T) {
	fw, db := newTestFw(t, "unsafe_identifier")
	db.MustExec(`INSERT INTO items (id, name) VALUES ('1', 'Normal')`)

	group := &persistence.FilterGroup{Filters: []persistence.Filter{persistence.EqualFilter{By: "name); DROP TABLE items;--"}}}
	args := itemArgs{Name: "Normal", FilterGroup: group}

	var out []itemRow
	err := fw.QueryAll(context.Background(), "test.list", args, &out)
	require.Error(t, err)

	var count int
	require.NoError(t, db.Get(&count, `SELECT COUNT(*) FROM items`))
	require.Equal(t, 1, count)
}

// TestQueryAll_OrderByRendersAndSorts exercises the full ORDER BY path through the
// production template: Order.ToSQLStmt renders a validated clause and rows come back
// sorted accordingly for both directions.
func TestQueryAll_OrderByRendersAndSorts(t *testing.T) {
	fw, db := newTestFw(t, "order_by")
	db.MustExec(`INSERT INTO items (id, name, creation_date) VALUES ('1', 'A', '2024-01-02'), ('2', 'B', '2024-01-01'), ('3', 'C', '2024-01-03')`)

	args := itemArgs{Order: &persistence.Order{By: persistence.CreationDate, Direction: persistence.Asc}}
	var out []itemRow
	require.NoError(t, fw.QueryAll(context.Background(), "test.listOrdered", args, &out))
	require.Equal(t, []string{"2", "1", "3"}, ids(out))

	args.Order.Direction = persistence.Desc
	out = nil
	require.NoError(t, fw.QueryAll(context.Background(), "test.listOrdered", args, &out))
	require.Equal(t, []string{"3", "1", "2"}, ids(out))
}

// TestQueryAll_UnsafeOrderByIsRejected proves the Order allow-list backstop fires
// through the framework: an order column outside the allow-list aborts the query.
func TestQueryAll_UnsafeOrderByIsRejected(t *testing.T) {
	fw, _ := newTestFw(t, "order_by_unsafe")

	args := itemArgs{Order: &persistence.Order{By: persistence.OrderByOption("name; DROP TABLE items;--"), Direction: persistence.Asc}}
	var out []itemRow
	require.Error(t, fw.QueryAll(context.Background(), "test.listOrdered", args, &out))
}

func ids(rows []itemRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.ID
	}
	return out
}
