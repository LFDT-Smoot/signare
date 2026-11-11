package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/spf13/viper"
)

// TestSplitList pins that an unset list flag yields no entries. strings.Split would yield one empty
// entry instead, which only disappears today because an unset exclusions flag would produce the same
// empty entry and cancel it: an accident rather than a rule.
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

// TestAppendInclusions guards the rule that an exclusion wins over an inclusion. Inclusions arrive
// from two places, the flag and the actions file, and they used to be filtered on only one of those
// paths, so the same operationID survived or was dropped depending on which one was in use.
func TestAppendInclusions(t *testing.T) {
	tests := map[string]struct {
		ids        []string
		inclusions []string
		exclusions []string
		want       []string
	}{
		"no inclusions":            {ids: []string{"a"}, want: []string{"a"}},
		"inclusions appended":      {ids: []string{"a"}, inclusions: []string{"b", "c"}, want: []string{"a", "b", "c"}},
		"excluded inclusion":       {ids: []string{"a"}, inclusions: []string{"b", "c"}, exclusions: []string{"b"}, want: []string{"a", "c"}},
		"every inclusion excluded": {ids: []string{"a"}, inclusions: []string{"b"}, exclusions: []string{"b"}, want: []string{"a"}},
		"exclusion matching no inclusion": {
			ids: []string{"a"}, inclusions: []string{"b"}, exclusions: []string{"z"}, want: []string{"a", "b"},
		},
		"no operation IDs": {inclusions: []string{"b"}, want: []string{"b"}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			exclusions := make(map[string]string, len(test.exclusions))
			for _, exclusion := range test.exclusions {
				exclusions[exclusion] = ""
			}

			got := appendInclusions(test.ids, test.inclusions, exclusions)
			if !slices.Equal(got, test.want) {
				t.Fatalf("appendInclusions(%#v, %#v, %#v) = %#v, want %#v",
					test.ids, test.inclusions, test.exclusions, got, test.want)
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

// TestExecuteCmd_ExclusionWinsOverFileInclusion runs the command end to end on a fixture set, so the
// exclusion rule is checked on the path executeCmd takes and not only on the helper: a plain append
// of the inclusions would leave the excluded action as an unmapped operation ID and go red here.
func TestExecuteCmd_ExclusionWinsOverFileInclusion(t *testing.T) {
	dir := t.TempDir()
	write := func(name, contents string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		return path
	}
	spec := write("openapi.yaml", "openapi: 3.0.0\ninfo:\n  title: fixture\n  version: \"1\"\npaths:\n  /foo:\n    get:\n      operationId: foo.get\n      responses:\n        \"200\":\n          description: ok\n")
	generated := write("actions-generated.yaml", "actions:\n  - foo.get\n")
	manual := write("actions-manual.yaml", "actions:\n  - rpc.method.live\n  - rpc.method.retired\n")
	permissions := write("permissions.yaml", "permissions:\n  - id: p\n    actions:\n      - foo.get\n      - rpc.method.live\n")
	roles := write("roles.yaml", "roles:\n  - id: r\n    permissions:\n      - p\n")

	t.Cleanup(viper.Reset)
	viper.Set(openAPISpecFilesFlag, spec)
	viper.Set(actionsFilesFlag, generated+","+manual)
	viper.Set(operationIdInclusionsFileFlag, manual)
	viper.Set(permissionsFileFlag, permissions)
	viper.Set(rolesFileFlag, roles)

	// The retired action is declared and exempt but granted to no role, so the run must fail; this
	// pins that the fixtures exercise the checks at all.
	if err := executeCmd(nil, nil); err == nil {
		t.Fatal("expected the retired action to be reported as assigned to no role")
	}

	// Excluding it removes it from the actions and from the inclusions alike, so every check holds.
	viper.Set(operationIdExclusionsFlag, "rpc.method.retired")
	if err := executeCmd(nil, nil); err != nil {
		t.Fatalf("excluding the retired action should satisfy every check, got: %v", err)
	}
}
