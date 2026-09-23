package pinsourceinfile_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/adapters/pinsource/infile/pinsourceinfile"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"

	"github.com/stretchr/testify/require"
)

func newResolver(t *testing.T, directory string) *pinsourceinfile.Resolver {
	t.Helper()
	resolver, err := pinsourceinfile.NewResolver(pinsourceinfile.ResolverOptions{Directory: directory})
	require.NoError(t, err)
	return resolver
}

func writeSource(t *testing.T, directory, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600))
}

func TestNewResolver(t *testing.T) {
	t.Run("an absent directory is allowed and reported on use", func(t *testing.T) {
		resolver, err := pinsourceinfile.NewResolver(pinsourceinfile.ResolverOptions{})
		require.NoError(t, err, "a deployment with no PKCS#11 slot must still start")

		pin, resolveErr := resolver.Resolve(context.Background(), "pin")
		require.Error(t, resolveErr)
		require.True(t, errors.IsPreconditionFailed(resolveErr))
		require.Contains(t, resolveErr.Error(), "pinSourceDirectory")
		require.Empty(t, pin)
	})

	t.Run("a configured directory that does not exist fails at startup", func(t *testing.T) {
		resolver, err := pinsourceinfile.NewResolver(pinsourceinfile.ResolverOptions{
			Directory: filepath.Join(t.TempDir(), "missing"),
		})
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, resolver)
	})
}

func TestResolver_Resolve(t *testing.T) {
	t.Run("reads the named secret", func(t *testing.T) {
		directory := t.TempDir()
		writeSource(t, directory, "slot-pin", "userpin")

		pin, err := newResolver(t, directory).Resolve(context.Background(), "slot-pin")
		require.NoError(t, err)
		require.Equal(t, "userpin", pin)
	})

	// `echo pin > file` is what an operator will do, and a trailing newline fails the login in a way
	// that looks exactly like a wrong secret.
	t.Run("strips exactly one trailing line ending", func(t *testing.T) {
		for name, content := range map[string]string{
			"unix":            "userpin\n",
			"windows":         "userpin\r\n",
			"none":            "userpin",
			"trailing space":  "userpin ",
			"leading space":   " userpin",
			"inner newline":   "user\npin\n",
			"two newlines":    "userpin\n\n",
			"carriage only":   "userpin\r",
			"tab is kept":     "userpin\t",
			"leading newline": "\nuserpin",
		} {
			expected := map[string]string{
				"unix":            "userpin",
				"windows":         "userpin",
				"none":            "userpin",
				"trailing space":  "userpin ",
				"leading space":   " userpin",
				"inner newline":   "user\npin",
				"two newlines":    "userpin\n",
				"carriage only":   "userpin",
				"tab is kept":     "userpin\t",
				"leading newline": "\nuserpin",
			}[name]

			directory := t.TempDir()
			writeSource(t, directory, "slot-pin", content)

			pin, err := newResolver(t, directory).Resolve(context.Background(), "slot-pin")
			require.NoError(t, err, name)
			require.Equal(t, expected, pin, name)
		}
	})

	// A Kubernetes secret projection mounts every key as a symlink into a timestamped directory, so
	// refusing to follow symlinks would break the deployment shape this exists for.
	t.Run("follows a Kubernetes-style symlink chain", func(t *testing.T) {
		directory := t.TempDir()
		versioned := filepath.Join(directory, "..2026_09_14")
		require.NoError(t, os.Mkdir(versioned, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(versioned, "slot-pin"), []byte("userpin\n"), 0o600))
		require.NoError(t, os.Symlink(versioned, filepath.Join(directory, "..data")))
		require.NoError(t, os.Symlink(filepath.Join("..data", "slot-pin"), filepath.Join(directory, "slot-pin")))

		pin, err := newResolver(t, directory).Resolve(context.Background(), "slot-pin")
		require.NoError(t, err)
		require.Equal(t, "userpin", pin)
	})

	t.Run("rejects a source that is not a single name", func(t *testing.T) {
		directory := t.TempDir()
		outside := filepath.Join(directory, "outside")
		require.NoError(t, os.Mkdir(outside, 0o700))
		writeSource(t, outside, "secret", "leaked")

		resolver := newResolver(t, directory)
		for _, source := range []string{"outside/secret", "../outside/secret", "..", ".", "/etc/passwd", ""} {
			pin, err := resolver.Resolve(context.Background(), source)
			require.Error(t, err, "%q must be rejected", source)
			require.True(t, errors.IsInvalidArgument(err), "%q must be rejected as an invalid argument", source)
			require.Empty(t, pin)
		}
	})

	t.Run("fails closed when the secret cannot be read", func(t *testing.T) {
		directory := t.TempDir()

		pin, err := newResolver(t, directory).Resolve(context.Background(), "no-such-source")
		require.Error(t, err)
		require.True(t, errors.IsPreconditionFailed(err))
		require.Empty(t, pin)
	})

	t.Run("rejects an empty secret", func(t *testing.T) {
		directory := t.TempDir()
		writeSource(t, directory, "slot-pin", "\n")

		pin, err := newResolver(t, directory).Resolve(context.Background(), "slot-pin")
		require.Error(t, err)
		require.True(t, errors.IsPreconditionFailed(err))
		require.Empty(t, pin)
	})

	t.Run("bounds the read", func(t *testing.T) {
		directory := t.TempDir()
		writeSource(t, directory, "at-limit", strings.Repeat("a", 1024))
		writeSource(t, directory, "over-limit", strings.Repeat("a", 1025))

		resolver := newResolver(t, directory)

		pin, err := resolver.Resolve(context.Background(), "at-limit")
		require.NoError(t, err)
		require.Len(t, pin, 1024)

		pin, err = resolver.Resolve(context.Background(), "over-limit")
		require.Error(t, err)
		require.True(t, errors.IsPreconditionFailed(err))
		require.Empty(t, pin)
	})

	// Rotation has to take effect without a restart, which rules out caching the resolved value.
	t.Run("re-reads the secret on every call", func(t *testing.T) {
		directory := t.TempDir()
		writeSource(t, directory, "slot-pin", "before")
		resolver := newResolver(t, directory)

		pin, err := resolver.Resolve(context.Background(), "slot-pin")
		require.NoError(t, err)
		require.Equal(t, "before", pin)

		writeSource(t, directory, "slot-pin", "after")

		pin, err = resolver.Resolve(context.Background(), "slot-pin")
		require.NoError(t, err)
		require.Equal(t, "after", pin)
	})

	// Only the human-readable message reaches an API caller, so that is where the directory must not
	// appear. The wrapped error keeps the path for the log.
	t.Run("does not report the directory to the caller", func(t *testing.T) {
		directory := t.TempDir()

		_, err := newResolver(t, directory).Resolve(context.Background(), "no-such-source")
		require.Error(t, err)

		useCaseErr, ok := errors.CastAsUseCaseError(err)
		require.True(t, ok)
		require.NotNil(t, useCaseErr.HumanReadableMessage())
		require.NotContains(t, *useCaseErr.HumanReadableMessage(), directory)
		require.Contains(t, *useCaseErr.HumanReadableMessage(), "no-such-source")
	})
}
