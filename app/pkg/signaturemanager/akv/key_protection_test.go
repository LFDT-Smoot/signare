package akv

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/commons/logger"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
)

type fakeReader struct {
	mu          sync.Mutex
	description keyDescription
	err         error
	calls       int
}

func (f *fakeReader) describeKey(_ context.Context, _ string, _ string) (keyDescription, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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

	t.Run("unreadable key fails as unavailable, is remembered briefly, then read again", func(t *testing.T) {
		reader := &fakeReader{err: errors.New("403 Forbidden")}
		p := newKeyProtection(reader, true)
		clock := time.Unix(1_000_000, 0)
		p.now = func() time.Time { return clock }

		err := p.check(ctx, tracer, "k", "v1")
		require.True(t, signaturemanager.IsUnavailableError(err), "an unreadable key is an unavailable backend, not a policy refusal")
		require.False(t, signaturemanager.IsPolicyRefusedError(err))
		require.Contains(t, err.Error(), "cannot verify")

		clock = clock.Add(readErrorTTL - time.Millisecond)
		require.True(t, signaturemanager.IsUnavailableError(p.check(ctx, tracer, "k", "v1")))
		require.Equal(t, 1, reader.calls, "within the interval the failure is not retried against the vault")

		reader.err = nil
		reader.description = hsmKey()
		clock = clock.Add(time.Millisecond)
		require.NoError(t, p.check(ctx, tracer, "k", "v1"), "after the interval the key is read again")
		require.Equal(t, 2, reader.calls)
	})
}

// blockingReader holds every read until released, so concurrent checks overlap.
type blockingReader struct {
	release chan struct{}
	calls   atomic.Int32
}

func (b *blockingReader) describeKey(ctx context.Context, _ string, _ string) (keyDescription, error) {
	b.calls.Add(1)
	<-b.release
	return hsmKey(), ctx.Err()
}

func TestKeyProtectionConcurrentFirstChecksShareOneRead(t *testing.T) {
	reader := &blockingReader{release: make(chan struct{})}
	p := newKeyProtection(reader, true)
	tracer := logger.NewTracer(context.Background())

	// The first caller leads the read and its context is cancelled while the read is in flight: the
	// shared read must not inherit that cancellation and fail every other waiter.
	const callers = 20
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	start := func(ctx context.Context) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- p.check(ctx, tracer, "k", "v1")
		}()
	}
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	start(firstCtx)
	require.Eventually(t, func() bool { return reader.calls.Load() == 1 }, time.Second, time.Millisecond)
	for i := 1; i < callers; i++ {
		start(context.Background())
	}
	time.Sleep(20 * time.Millisecond)
	cancelFirst()
	close(reader.release)
	wg.Wait()
	close(errs)

	require.Equal(t, int32(1), reader.calls.Load(), "concurrent first checks of one key version share a single read")
	for err := range errs {
		require.NoError(t, err)
	}
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

// ctxReader records the context each read receives, and the context's state at the end of the read.
type ctxReader struct {
	ctx     context.Context
	errSeen error
	calls   atomic.Int32
	hold    chan struct{}
}

func (c *ctxReader) describeKey(ctx context.Context, _ string, _ string) (keyDescription, error) {
	c.ctx = ctx
	c.calls.Add(1)
	if c.hold != nil {
		<-c.hold
	}
	c.errSeen = ctx.Err()
	return hsmKey(), nil
}

func TestKeyProtectionReadIsBoundedAndDetached(t *testing.T) {
	reader := &ctxReader{hold: make(chan struct{})}
	p := newKeyProtection(reader, true)
	callerCtx, cancel := context.WithCancel(context.Background())
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- p.check(callerCtx, logger.NewTracer(callerCtx), "k", "v1") }()

	// Cancel the caller while its read is in flight, then let the read finish.
	require.Eventually(t, func() bool { return reader.calls.Load() == 1 }, time.Second, time.Millisecond)
	cancel()
	close(reader.hold)
	require.NoError(t, <-done)

	require.NoError(t, reader.errSeen, "cancelling the caller must not cancel the shared read")
	deadline, ok := reader.ctx.Deadline()
	require.True(t, ok, "the read must carry a deadline")
	require.LessOrEqual(t, deadline.Sub(start), keyReadTimeout+time.Second)
	require.Less(t, keyReadTimeout, 15*time.Second, "a read must not outlive the server's write timeout")
}

func TestKeyProtectionIDsDoNotCollide(t *testing.T) {
	reader := &ctxReader{}
	p := newKeyProtection(reader, true)
	ctx := context.Background()
	require.NoError(t, p.check(ctx, logger.NewTracer(ctx), "a/b", "c"))
	require.NoError(t, p.check(ctx, logger.NewTracer(ctx), "a", "b/c"))
	require.Equal(t, int32(2), reader.calls.Load(), "different name and version pairs are checked separately")
}
