package persistence_test

import (
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/commons/persistence"

	"github.com/stretchr/testify/require"
)

func TestClampPageLimit(t *testing.T) {
	tests := []struct {
		name     string
		limit    int
		expected int
	}{
		{name: "zero falls back to the default", limit: 0, expected: persistence.DefaultPageLimit},
		{name: "negative falls back to the default", limit: -1, expected: persistence.DefaultPageLimit},
		{name: "value within range is preserved", limit: 50, expected: 50},
		{name: "value equal to max is preserved", limit: persistence.MaxPageLimit, expected: persistence.MaxPageLimit},
		{name: "value above max is capped to max", limit: persistence.MaxPageLimit + 1, expected: persistence.MaxPageLimit},
		{name: "very large value is capped to max", limit: 1_000_000, expected: persistence.MaxPageLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, persistence.ClampPageLimit(test.limit))
		})
	}
}
