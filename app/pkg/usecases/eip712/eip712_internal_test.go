package eip712

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// resolveFieldTypeWithLookups is resolveFieldType as it was before it dropped the map lookups, kept as
// the oracle for the claim that dropping them changes no result.
func resolveFieldTypeWithLookups(t Types, fieldType string) string {
	for {
		if t[fieldType] != nil {
			return fieldType
		}
		openBracket := strings.LastIndex(fieldType, "[")
		if !strings.HasSuffix(fieldType, "]") || openBracket < 0 {
			return fieldType
		}
		fieldType = fieldType[:openBracket]
	}
}

// Once checkTypeNames has passed, no declared name contains brackets, and the lookup-free resolution
// must return exactly what the lookup version returns. The corpus is every string up to seven
// characters over an alphabet holding the brackets, a digit and the first letters of the declared
// names, so it covers unbalanced, nested, empty and sized suffixes and names declared as prefixes.
func TestResolveFieldType_MatchesLookupResolution(t *testing.T) {
	typeSets := []Types{
		{"A": {}},
		{"A": {}, "AB": {}, "B2": {}},
		{"A": {}, "A2": {}, "B": {}, "2": {}},
	}
	for _, types := range typeSets {
		require.NoError(t, types.checkTypeNames())
	}

	const alphabet = "AB2[]"
	var corpus []string
	var extend func(prefix string)
	extend = func(prefix string) {
		corpus = append(corpus, prefix)
		if len(prefix) == 7 {
			return
		}
		for _, c := range alphabet {
			extend(prefix + string(c))
		}
	}
	extend("")
	require.Len(t, corpus, 97656)

	for _, types := range typeSets {
		for _, fieldType := range corpus {
			require.Equal(t, resolveFieldTypeWithLookups(types, fieldType), resolveFieldType(fieldType), "field type %q", fieldType)
		}
	}
}
