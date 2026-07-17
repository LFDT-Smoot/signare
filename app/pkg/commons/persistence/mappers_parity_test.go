package persistence_test

import (
	"encoding/xml"
	"path"
	"sort"
	"strings"
	"testing"

	embedded "github.com/lfdt-smoot/signare/app"
	"github.com/lfdt-smoot/signare/app/pkg/commons/persistence"

	"github.com/stretchr/testify/require"
)

const mappersBasePath = "include/config/mappers"

// statementIDsForDialect collects the sorted "mapping.statement" identifiers exposed by every mapper file
// of the given dialect, read from the embedded mappers filesystem.
func statementIDsForDialect(t *testing.T, dialect string) []string {
	t.Helper()

	dialectPath := path.Join(mappersBasePath, dialect)
	entries, err := embedded.DatabaseMappers.ReadDir(dialectPath)
	require.NoErrorf(t, err, "reading mapper directory for dialect %q", dialect)

	ids := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".xml") {
			continue
		}
		data, readErr := embedded.DatabaseMappers.ReadFile(path.Join(dialectPath, entry.Name()))
		require.NoErrorf(t, readErr, "reading mapper file %q", entry.Name())

		var mapper persistence.MapperConfig
		require.NoErrorf(t, xml.Unmarshal(data, &mapper), "parsing mapper file %q", entry.Name())

		for _, statement := range mapper.Statements {
			ids = append(ids, mapper.ID+"."+statement.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

// TestMapperStatementParity guards against dialect drift: the SQLite and Postgres mapper directories must
// expose exactly the same set of mapping.statement identifiers.
func TestMapperStatementParity(t *testing.T) {
	sqlite := statementIDsForDialect(t, "sqlite")
	postgres := statementIDsForDialect(t, "postgres")

	require.NotEmpty(t, sqlite, "expected sqlite mappers to be discovered")
	require.ElementsMatch(t, sqlite, postgres, "sqlite and postgres mappers must expose identical statement IDs")
}
