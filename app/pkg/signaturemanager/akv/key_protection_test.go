package akv

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/commons/logger"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
)

type fakeReader struct {
	description keyDescription
	err         error
	calls       int
}

func (f *fakeReader) describeKey(_ context.Context, _ string, _ string) (keyDescription, error) {
	f.calls++
	return f.description, f.err
}

func hsmKey() keyDescription {
	return keyDescription{keyType: "EC-HSM", curve: "P-256K", hsmPlatform: "2"}
}

func TestKeyProtectionProblems(t *testing.T) {
	cases := []struct {
		name        string
		description keyDescription
		problems    int
	}{
		{"HSM key on the current platform", hsmKey(), 0},
		{"HSM key, platform not reported", keyDescription{keyType: "EC-HSM", curve: "P-256K"}, 0},
		{"software key", keyDescription{keyType: "EC", curve: "P-256K", hsmPlatform: "0"}, 2},
		{"wrong curve", keyDescription{keyType: "EC-HSM", curve: "P-256", hsmPlatform: "2"}, 1},
		{"previous HSM platform", keyDescription{keyType: "EC-HSM", curve: "P-256K", hsmPlatform: "1"}, 1},
		{"nothing reported", keyDescription{}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Len(t, keyProtectionProblems(c.description), c.problems)
		})
	}
}

func TestKeyProtectionHardwareOnly(t *testing.T) {
	ctx := context.Background()
	tracer := logger.NewTracer(ctx)

	t.Run("HSM key is accepted and read once", func(t *testing.T) {
		reader := &fakeReader{description: hsmKey()}
		p := newKeyProtection(reader, true)
		require.NoError(t, p.check(ctx, tracer, "k", "v1"))
		require.NoError(t, p.check(ctx, tracer, "k", "v1"))
		require.Equal(t, 1, reader.calls, "a verified key version is not read again")
		require.NoError(t, p.check(ctx, tracer, "k", "v2"))
		require.Equal(t, 2, reader.calls, "a different version is read on its own")
	})

	t.Run("software key is refused with the policy error", func(t *testing.T) {
		reader := &fakeReader{description: keyDescription{keyType: "EC", curve: "P-256K", hsmPlatform: "0"}}
		p := newKeyProtection(reader, true)
		err := p.check(ctx, tracer, "k", "v1")
		require.Error(t, err)
		require.True(t, signaturemanager.IsPolicyRefusedError(err))
		require.Contains(t, err.Error(), "software-protected")
		require.Error(t, p.check(ctx, tracer, "k", "v1"))
		require.Equal(t, 1, reader.calls, "a refused key version is not read again")
	})

	t.Run("key on the previous HSM platform is refused", func(t *testing.T) {
		reader := &fakeReader{description: keyDescription{keyType: "EC-HSM", curve: "P-256K", hsmPlatform: "1"}}
		p := newKeyProtection(reader, true)
		err := p.check(ctx, tracer, "k", "v1")
		require.True(t, signaturemanager.IsPolicyRefusedError(err))
		require.Contains(t, err.Error(), "hsmPlatform")
	})

	t.Run("unreadable key is refused but not remembered", func(t *testing.T) {
		reader := &fakeReader{err: errors.New("403 Forbidden")}
		p := newKeyProtection(reader, true)
		err := p.check(ctx, tracer, "k", "v1")
		require.True(t, signaturemanager.IsPolicyRefusedError(err))
		require.Contains(t, err.Error(), "cannot verify")
		reader.err = nil
		reader.description = hsmKey()
		require.NoError(t, p.check(ctx, tracer, "k", "v1"), "the next attempt reads the key again")
		require.Equal(t, 2, reader.calls)
	})
}

func TestKeyProtectionLenient(t *testing.T) {
	ctx := context.Background()
	tracer := logger.NewTracer(ctx)

	t.Run("software key signs, and is read once", func(t *testing.T) {
		reader := &fakeReader{description: keyDescription{keyType: "EC", curve: "P-256K"}}
		p := newKeyProtection(reader, false)
		require.NoError(t, p.check(ctx, tracer, "k", "v1"))
		require.NoError(t, p.check(ctx, tracer, "k", "v1"))
		require.Equal(t, 1, reader.calls)
	})

	t.Run("unreadable key signs, and is read once", func(t *testing.T) {
		reader := &fakeReader{err: errors.New("403 Forbidden")}
		p := newKeyProtection(reader, false)
		require.NoError(t, p.check(ctx, tracer, "k", "v1"))
		require.NoError(t, p.check(ctx, tracer, "k", "v1"))
		require.Equal(t, 1, reader.calls)
	})
}
