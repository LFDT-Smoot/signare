package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestSplitList covers the unset-flag case specifically: strings.Split returns a single empty element
// for an empty string, and the default target passes no --operationIdInclusions, so an empty entry
// would reach the operation IDs and fail the one-to-one check against the actions.
func TestSplitList(t *testing.T) {
	tests := map[string]struct {
		value string
		want  []string
	}{
		"unset flag":            {value: "", want: nil},
		"single value":          {value: "a", want: []string{"a"}},
		"several values":        {value: "a,b,c", want: []string{"a", "b", "c"}},
		"empty trailing value":  {value: "a,", want: []string{"a", ""}},
		"value with whitespace": {value: "a, b", want: []string{"a", " b"}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := splitList(test.value)
			if !slices.Equal(got, test.want) {
				t.Fatalf("splitList(%q) = %#v, want %#v", test.value, got, test.want)
			}
		})
	}
}

func TestReadActions(t *testing.T) {
	tests := map[string]struct {
		contents string
		want     []string
		wantErr  bool
	}{
		"actions": {
			contents: "actions:\n  - one\n  - two\n",
			want:     []string{"one", "two"},
		},
		"empty actions key": {
			contents: "actions:\n",
			want:     nil,
		},
		"no actions key": {
			contents: "roles:\n  - id: a\n",
			want:     nil,
		},
		"actions is not a list": {
			contents: "actions: one\n",
			wantErr:  true,
		},
		"unterminated flow sequence": {
			contents: "actions: [one, two\n",
			wantErr:  true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "actions.yaml")
			if err := os.WriteFile(path, []byte(test.contents), 0o600); err != nil {
				t.Fatalf("writing the fixture: %v", err)
			}

			got, err := readActions(path)
			if test.wantErr {
				if err == nil {
					t.Fatalf("readActions(%q) = %#v, want an error", test.contents, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("readActions(%q) returned %v", test.contents, err)
			}
			if !slices.Equal(got.Actions, test.want) {
				t.Fatalf("readActions(%q) = %#v, want %#v", test.contents, got.Actions, test.want)
			}
		})
	}
}

func TestReadActionsMissingFile(t *testing.T) {
	if _, err := readActions(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("readActions on a missing file returned no error")
	}
}
