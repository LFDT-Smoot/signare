package hsmconnector

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"

	"github.com/stretchr/testify/require"
)

// noopSignatureManager is a DigitalSignatureManager whose Open and Close succeed without touching a
// backend, so the factory's concurrency behaviour can be exercised without an HSM. It holds no
// mutable state, which is what makes it safe to share between the goroutines of the concurrency test.
//
// id is deliberate rather than dead weight: it makes the stub non-zero-sized. Go allows two distinct
// zero-size variables to share an address, so with an empty struct a Reset that replaced the map entry
// with a fresh instance would still satisfy the require.Same identity check below.
type noopSignatureManager struct{ id string }

func (*noopSignatureManager) Sign(_ context.Context, _ signaturemanager.SignInput) (*signaturemanager.SignOutput, error) {
	return &signaturemanager.SignOutput{}, nil
}

func (*noopSignatureManager) GenerateKey(_ context.Context, _ signaturemanager.GenerateKeyInput) (*signaturemanager.GenerateKeyOutput, error) {
	return &signaturemanager.GenerateKeyOutput{}, nil
}

func (*noopSignatureManager) DeriveAddressFromPrivateKey(_ context.Context, _ signaturemanager.DeriveAddressFromPrivateKeyInput) (*signaturemanager.DeriveAddressFromPrivateKeyOutput, error) {
	return &signaturemanager.DeriveAddressFromPrivateKeyOutput{}, nil
}

func (*noopSignatureManager) RemoveKey(_ context.Context, _ signaturemanager.RemoveKeyInput) (*signaturemanager.RemoveKeyOutput, error) {
	return &signaturemanager.RemoveKeyOutput{}, nil
}

func (*noopSignatureManager) ListKeys(_ context.Context, _ signaturemanager.ListKeysInput) (*signaturemanager.ListKeysOutput, error) {
	return &signaturemanager.ListKeysOutput{}, nil
}

func (*noopSignatureManager) Open(_ context.Context, _ signaturemanager.OpenInput) (*signaturemanager.OpenOutput, error) {
	return &signaturemanager.OpenOutput{}, nil
}

func (*noopSignatureManager) Close(_ context.Context, _ signaturemanager.CloseInput) (*signaturemanager.CloseOutput, error) {
	return &signaturemanager.CloseOutput{}, nil
}

func (*noopSignatureManager) IsAlive(_ context.Context, _ signaturemanager.IsAliveInput) (*signaturemanager.IsAliveOutput, error) {
	return &signaturemanager.IsAliveOutput{}, nil
}

// recordingSignatureManager counts Open and Close, and can be made to fail either of them, so the
// sequential tests can assert what Reset actually does rather than only what it returns.
//
// It is a separate type rather than counters on noopSignatureManager, and its counters are plain ints
// rather than atomics, both deliberately. The concurrency test shares one stub between two goroutines:
// plain counters there would be a data race, and atomic counters would be worse, because the atomic
// operations create a happens-before edge between the two goroutines that hides the map race the test
// exists to catch. Confirmed by re-adding the map write to Reset: with atomic counters on the shared
// stub the race detector stays silent, without them it reports the race. So this type must never be
// used from more than one goroutine.
type recordingSignatureManager struct {
	noopSignatureManager
	openErr    error
	closeErr   error
	openCalls  int
	closeCalls int
}

func (s *recordingSignatureManager) Open(_ context.Context, _ signaturemanager.OpenInput) (*signaturemanager.OpenOutput, error) {
	s.openCalls++
	if s.openErr != nil {
		return nil, s.openErr
	}
	return &signaturemanager.OpenOutput{}, nil
}

func (s *recordingSignatureManager) Close(_ context.Context, _ signaturemanager.CloseInput) (*signaturemanager.CloseOutput, error) {
	s.closeCalls++
	if s.closeErr != nil {
		return nil, s.closeErr
	}
	return &signaturemanager.CloseOutput{}, nil
}

// TestDigitalSignatureManagerFactory_ResetIsSafeAgainstConcurrentCreate is the regression guard for a
// data race that could kill the process.
//
// Create runs on every signing request; Reset runs when an administrator adds a SoftHSM slot. Both
// reach digitalSignatureManagerMap, which has no lock. While Reset wrote back into that map, the two
// could execute a concurrent map read and write, which the Go runtime reports as
// "fatal error: concurrent map read and map write". That is a runtime throw rather than a panic, so
// the recovery middleware cannot intercept it and the whole signer dies.
//
// Run this under the race detector (`make race_test`, or `go test -race ./pkg/usecases/hsmconnector/`):
// reverted, the detector reports the write in Reset against the read in Create deterministically.
// Without -race the same revert may still surface as the runtime's own fatal error, but only
// non-deterministically, so -race is what makes this a reliable guard.
func TestDigitalSignatureManagerFactory_ResetIsSafeAgainstConcurrentCreate(t *testing.T) {
	factory := &DefaultDigitalSignatureManagerFactory{
		digitalSignatureManagerMap: map[ModuleKind]signaturemanager.DigitalSignatureManager{
			SoftHSMModuleKind: &noopSignatureManager{id: "softhsm"},
		},
	}

	const iterations = 200
	ctx := context.Background()

	// Failures are collected rather than asserted in the spawned goroutines: require calls FailNow,
	// which testing only supports from the goroutine running the test.
	resetErrs := make([]error, 0, iterations)
	createErrs := make([]error, 0, iterations)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			// The admin path: adding a SoftHSM slot resets the module's snapshot.
			if err := factory.Reset(ctx, SoftHSMModuleKind); err != nil {
				resetErrs = append(resetErrs, err)
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			// The signing path: every request resolves its manager through Create.
			manager, err := factory.Create(ctx, CreateInput{ModuleKind: SoftHSMModuleKind})
			if err != nil {
				createErrs = append(createErrs, err)
				continue
			}
			if manager == nil {
				createErrs = append(createErrs, errors.New("Create returned a nil manager"))
			}
		}
	}()

	wg.Wait()

	require.Empty(t, resetErrs)
	require.Empty(t, createErrs)
}

// Reset must leave the same manager instance resolvable: it acts on the stored instance rather than
// replacing or dropping the map entry.
func TestDigitalSignatureManagerFactory_ResetKeepsTheManagerResolvable(t *testing.T) {
	ctx := context.Background()
	factory := &DefaultDigitalSignatureManagerFactory{
		digitalSignatureManagerMap: map[ModuleKind]signaturemanager.DigitalSignatureManager{
			SoftHSMModuleKind: &noopSignatureManager{id: "softhsm"},
		},
	}

	before, err := factory.Create(ctx, CreateInput{ModuleKind: SoftHSMModuleKind})
	require.NoError(t, err)
	require.NotNil(t, before)

	require.NoError(t, factory.Reset(ctx, SoftHSMModuleKind))

	after, err := factory.Create(ctx, CreateInput{ModuleKind: SoftHSMModuleKind})
	require.NoError(t, err)
	require.NotNil(t, after)
	require.Same(t, before, after, "Reset acts on the stored instance; it must not replace or drop it")
}

// Reset must still do its job. Without these call counts, deleting the racing map write could be
// "fixed" by deleting the body of Reset entirely and the rest of this file would stay green.
func TestDigitalSignatureManagerFactory_ResetClosesAndReopensTheManager(t *testing.T) {
	ctx := context.Background()
	manager := &recordingSignatureManager{}
	factory := &DefaultDigitalSignatureManagerFactory{
		digitalSignatureManagerMap: map[ModuleKind]signaturemanager.DigitalSignatureManager{
			SoftHSMModuleKind: manager,
		},
	}

	require.NoError(t, factory.Reset(ctx, SoftHSMModuleKind))

	require.Equal(t, 1, manager.closeCalls, "Reset must close the stored manager")
	require.Equal(t, 1, manager.openCalls, "Reset must reopen the stored manager")
}

func TestDigitalSignatureManagerFactory_ResetRejectsUnsupportedKind(t *testing.T) {
	factory := &DefaultDigitalSignatureManagerFactory{
		digitalSignatureManagerMap: map[ModuleKind]signaturemanager.DigitalSignatureManager{
			SoftHSMModuleKind: &noopSignatureManager{id: "softhsm"},
		},
	}

	require.Error(t, factory.Reset(context.Background(), AKVModuleKind))
}

// Reset reports a failure to close, and does not go on to reopen.
func TestDigitalSignatureManagerFactory_ResetPropagatesCloseFailure(t *testing.T) {
	manager := &recordingSignatureManager{closeErr: errors.New("close failed")}
	factory := &DefaultDigitalSignatureManagerFactory{
		digitalSignatureManagerMap: map[ModuleKind]signaturemanager.DigitalSignatureManager{
			SoftHSMModuleKind: manager,
		},
	}

	require.Error(t, factory.Reset(context.Background(), SoftHSMModuleKind))
	require.Equal(t, 0, manager.openCalls, "Reset must not reopen after Close failed")
}

// Reset reports a failure to reopen rather than returning nil.
func TestDigitalSignatureManagerFactory_ResetPropagatesOpenFailure(t *testing.T) {
	manager := &recordingSignatureManager{openErr: errors.New("open failed")}
	factory := &DefaultDigitalSignatureManagerFactory{
		digitalSignatureManagerMap: map[ModuleKind]signaturemanager.DigitalSignatureManager{
			SoftHSMModuleKind: manager,
		},
	}

	require.Error(t, factory.Reset(context.Background(), SoftHSMModuleKind))
	require.Equal(t, 1, manager.closeCalls)
}
