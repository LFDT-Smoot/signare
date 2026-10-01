package hsmconnector

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"

	"github.com/stretchr/testify/require"
)

// TestValidatePinSource_AcceptsOnlySingleNames is the guard that keeps a slot from addressing a file
// outside the configured directory.
func TestValidatePinSource_AcceptsOnlySingleNames(t *testing.T) {
	t.Run("accepts a single name", func(t *testing.T) {
		for _, source := range []string{
			"pin",
			"slot-1-pin",
			"slot_1_pin",
			"slot.1.pin",
			".dockerconfigjson",
			"A1",
			strings.Repeat("a", maxPinSourceLength),
		} {
			require.NoError(t, ValidatePinSource(source), "%q is a single name and must be accepted", source)
		}
	})

	t.Run("rejects anything that is not a single name", func(t *testing.T) {
		for _, source := range []string{
			"",
			".",
			"..",
			"../pin",
			"..data",
			"..2026_09_14",
			"sub/pin",
			"/etc/passwd",
			`sub\pin`,
			`\\host\share`,
			"pin/",
			"a/../b",
			"has space",
			"semi;colon",
			"dollar$sign",
			"new\nline",
			"nul\x00byte",
			"héllo",
			strings.Repeat("a", maxPinSourceLength+1),
		} {
			err := ValidatePinSource(source)
			require.Error(t, err, "%q is not a single name and must be rejected", source)
			require.True(t, errors.IsInvalidArgument(err), "%q must be rejected as an invalid argument", source)
		}
	})
}

// TestValidatePinSource_MatchesFilepathOverAGeneratedCorpus cross-checks the validator against the
// standard library rather than against the cases above, which were written from the same model as the
// validator. Any accepted name must join to a path directly inside the directory, with no traversal.
func TestValidatePinSource_MatchesFilepathOverAGeneratedCorpus(t *testing.T) {
	const directory = "/etc/signare/pins"

	pieces := []string{"", ".", "..", "a", "-", "_", "/", `\`, "..a", "a..", " ", "\n", "é", "$"}
	corpus := make([]string, 0, len(pieces)*len(pieces)*len(pieces))
	for _, first := range pieces {
		for _, second := range pieces {
			for _, third := range pieces {
				corpus = append(corpus, first+second+third)
			}
		}
	}

	accepted := 0
	for _, source := range corpus {
		if ValidatePinSource(source) != nil {
			continue
		}
		accepted++
		joined := filepath.Join(directory, source)
		require.Equal(t, directory, filepath.Dir(joined), "accepted source %q must resolve directly inside the directory", source)
		require.Equal(t, source, filepath.Base(joined), "accepted source %q must survive Join unchanged", source)
		require.Equal(t, joined, filepath.Clean(joined), "accepted source %q must produce an already-clean path", source)
	}
	require.NotZero(t, accepted, "the corpus must exercise the accepting path as well")
}
