package persistence_test

import (
	"testing"

	embedded "github.com/lfdt-smoot/signare/app"

	"github.com/stretchr/testify/require"
)

// TestDefaultChainIDColumnLengthParity is a regression guard for DB-12: the cfg_application chain-ID
// column must be VARCHAR(256) in both dialects. It stores entities.Int256.String() (decimal, up to 78
// digits), so a shorter declared length risks truncation under a length-enforcing dialect such as
// Postgres. SQLite carries the final column name (default_chain_id) in its single initial migration;
// Postgres declares chain_id in 000001 and renames it to default_chain_id in 000003 without changing
// the length, so the pre-rename declaration is the one to assert.
//
// NOTE: this is a per-column guard, not full cross-dialect DDL parity. Verifying that the complete
// schemas match requires applying the Postgres migration chain (rename + ALTERs) or booting both
// engines, which belongs with the Postgres integration suite (the CI/OPS-1 gap, see issue #70).
func TestDefaultChainIDColumnLengthParity(t *testing.T) {
	sqliteSchema, err := embedded.DatabaseMigrations.ReadFile("include/dbschemas/sqlite/000001_initial_schema.up.sql")
	require.NoError(t, err)
	postgresSchema, err := embedded.DatabaseMigrations.ReadFile("include/dbschemas/postgres/000001_initial_schema.up.sql")
	require.NoError(t, err)

	require.Regexp(t, `default_chain_id\s+VARCHAR\(256\)`, string(sqliteSchema),
		"sqlite cfg_application.default_chain_id must be VARCHAR(256)")
	require.Regexp(t, `[^_]chain_id\s+VARCHAR\(256\)`, string(postgresSchema),
		"postgres cfg_application.chain_id must be VARCHAR(256)")
}
