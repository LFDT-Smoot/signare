package persistence_test

import (
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/commons/persistence"

	"github.com/stretchr/testify/require"
)

func TestFilters_ToSQLStmt_ValidIdentifier(t *testing.T) {
	tests := []struct {
		name   string
		filter persistence.Filter
		want   string
	}{
		{"equal", persistence.EqualFilter{By: "application_id"}, "application_id=:application_id"},
		{"less", persistence.LessFilter{By: "creation_date"}, "creation_date<:creation_date"},
		{"lessOrEqual", persistence.LessOrEqualFilter{By: "creation_date"}, "creation_date<=:creation_date"},
		{"greater", persistence.GreaterFilter{By: "creation_date"}, "creation_date>:creation_date"},
		{"greaterOrEqual", persistence.GreaterOrEqualFilter{By: "creation_date"}, "creation_date>=:creation_date"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.filter.ToSQLStmt()
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFilters_ToSQLStmt_RejectsUnsafeIdentifier(t *testing.T) {
	unsafe := []string{
		"name'",
		"name; DROP TABLE users;--",
		"name OR 1=1",
		"a b",
		"name)",
		"1name",
		"",
	}
	for _, by := range unsafe {
		t.Run(by, func(t *testing.T) {
			filters := []persistence.Filter{
				persistence.EqualFilter{By: by},
				persistence.LessFilter{By: by},
				persistence.LessOrEqualFilter{By: by},
				persistence.GreaterFilter{By: by},
				persistence.GreaterOrEqualFilter{By: by},
			}
			for _, f := range filters {
				_, err := f.ToSQLStmt()
				require.Errorf(t, err, "expected %q to be rejected as an identifier", by)
			}
		})
	}
}

func TestOrder_ToSQLStmt(t *testing.T) {
	t.Run("valid asc", func(t *testing.T) {
		got, err := persistence.Order{By: persistence.CreationDate, Direction: persistence.Asc}.ToSQLStmt()
		require.NoError(t, err)
		require.Equal(t, "creation_date ASC", got)
	})
	t.Run("valid desc", func(t *testing.T) {
		got, err := persistence.Order{By: persistence.LastUpdate, Direction: persistence.Desc}.ToSQLStmt()
		require.NoError(t, err)
		require.Equal(t, "last_update DESC", got)
	})
	t.Run("rejects unknown column", func(t *testing.T) {
		_, err := persistence.Order{By: persistence.OrderByOption("name; DROP TABLE users"), Direction: persistence.Asc}.ToSQLStmt()
		require.Error(t, err)
	})
	t.Run("rejects unknown direction", func(t *testing.T) {
		_, err := persistence.Order{By: persistence.CreationDate, Direction: persistence.OrderDirection("asc; DROP TABLE users")}.ToSQLStmt()
		require.Error(t, err)
	})
}
