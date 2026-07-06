package sql_test

import (
	"testing"

	persistencesql "github.com/hyperledger-labs/signare/app/pkg/commons/persistence/sql"
	"github.com/hyperledger-labs/signare/app/test/fakedb"

	"github.com/stretchr/testify/require"
)

// TestConnection_CloseClosesPool verifies the Connection lifecycle closes the underlying database
// connection pool so graceful shutdown releases server-side connections instead of leaking them
// until they time out.
func TestConnection_CloseClosesPool(t *testing.T) {
	conn, err := fakedb.NewConnection(fakedb.Behavior{})
	require.NoError(t, err)

	require.NoError(t, conn.GetDB().Ping(), "pool should be live before Close")

	require.NoError(t, conn.Close())

	require.Error(t, conn.GetDB().Ping(), "pool should be closed after Close")
}

// TestConnectionFw_CloseNilDBIsNoOp covers the production ConnectionFw.Close nil-guard directly: a
// zero-value connection has no pool and must report no error.
func TestConnectionFw_CloseNilDBIsNoOp(t *testing.T) {
	require.NoError(t, persistencesql.ConnectionFw{}.Close())
}
