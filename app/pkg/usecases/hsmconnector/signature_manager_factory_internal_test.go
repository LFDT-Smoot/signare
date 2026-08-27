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
// backend, so the factory's concurrency behaviour can be exercised without an HSM.
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

// Reset must still do its job: the manager is closed and reopened, and remains resolvable afterwards.
// Without this, deleting the map write could be "fixed" by deleting Reset's body entirely.
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

func TestDigitalSignatureManagerFactory_ResetRejectsUnsupportedKind(t *testing.T) {
	factory := &DefaultDigitalSignatureManagerFactory{
		digitalSignatureManagerMap: map[ModuleKind]signaturemanager.DigitalSignatureManager{
			SoftHSMModuleKind: &noopSignatureManager{id: "softhsm"},
		},
	}

	require.Error(t, factory.Reset(context.Background(), AKVModuleKind))
}
