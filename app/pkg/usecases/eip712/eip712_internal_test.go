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
// must return exactly what the lookup version returns. The type maps are every subset of a set of
// bracket-free names, including the empty name and names that are prefixes of one another. The field
// types are every string up to seven characters over the brackets, a digit and the letters those names
// use, so they cover unbalanced, nested, empty and sized suffixes and names declared as prefixes.
func TestResolveFieldType_MatchesLookupResolution(t *testing.T) {
	names := []string{"", "A", "AB", "B2", "2"}
	var typeSets []Types
	for mask := 0; mask < 1<<len(names); mask++ {
		types := Types{}
		for i, name := range names {
			if mask&(1<<i) != 0 {
				types[name] = []Type{}
			}
		}
		require.NoError(t, types.checkTypeNames())
		typeSets = append(typeSets, types)
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
			if want, got := resolveFieldTypeWithLookups(types, fieldType), resolveFieldType(fieldType); want != got {
				t.Fatalf("field type %q with types %v: lookup resolution %q, lookup-free %q", fieldType, types, want, got)
			}
		}
	}
}
