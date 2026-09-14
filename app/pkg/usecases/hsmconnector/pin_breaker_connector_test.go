package hsmconnector_test

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/adapters/pinsource/infile/pinsourceinfile"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"

	"github.com/stretchr/testify/require"
)

// refusingSignatureManager is a fake DigitalSignatureManager that refuses every PIN and counts the
// attempts, so the breaker can be observed through the connector rather than in isolation.
type refusingSignatureManager struct {
	malformedSignatureManager
	attempts atomic.Int32
}

func (m *refusingSignatureManager) Sign(_ context.Context, _ signaturemanager.SignInput) (*signaturemanager.SignOutput, error) {
	m.attempts.Add(1)
	return nil, signaturemanager.NewPinIncorrectError()
}

func (m *refusingSignatureManager) ListKeys(_ context.Context, _ signaturemanager.ListKeysInput) (*signaturemanager.ListKeysOutput, error) {
	m.attempts.Add(1)
	return nil, signaturemanager.NewPinIncorrectError()
}

func (m *refusingSignatureManager) IsAlive(_ context.Context, _ signaturemanager.IsAliveInput) (*signaturemanager.IsAliveOutput, error) {
	m.attempts.Add(1)
	return nil, signaturemanager.NewPinIncorrectError()
}

type refusingFactory struct {
	manager *refusingSignatureManager
}

func (f *refusingFactory) Create(_ context.Context, _ hsmconnector.CreateInput) (signaturemanager.DigitalSignatureManager, error) {
	return f.manager, nil
}

func (f *refusingFactory) Close(_ context.Context, _ hsmconnector.CloseInput) (*hsmconnector.CloseOutput, error) {
	return &hsmconnector.CloseOutput{}, nil
}

func (f *refusingFactory) Reset(_ context.Context, _ hsmconnector.ModuleKind) error {
	return nil
}

// TestConnectorStopsRetryingARefusedPin covers the failure mode this change introduces: login happens
// per operation, so without a breaker one wrong secret becomes a failed login on every request and an
// HSM locks the user PIN after a few of those.
func TestConnectorStopsRetryingARefusedPin(t *testing.T) {
	const slot = "0"

	newConnector := func(t *testing.T, directory string) (hsmconnector.HSMConnector, *refusingSignatureManager) {
		t.Helper()
		manager := &refusingSignatureManager{}
		resolver, err := pinsourceinfile.NewResolver(pinsourceinfile.ResolverOptions{Directory: directory})
		require.NoError(t, err)
		connector, err := hsmconnector.ProvideDefaultHSMConnector(hsmconnector.DefaultUseCaseOptions{
			DigitalSignatureManagerFactory: &refusingFactory{manager: manager},
			PinResolver:                    resolver,
		})
		require.NoError(t, err)
		return connector, manager
	}

	listInput := func() hsmconnector.ListAddressesInput {
		return hsmconnector.ListAddressesInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slot,
				PinSource:  "slot-pin",
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
		}
	}

	t.Run("a refused PIN is reported as a precondition failure, not an internal error", func(t *testing.T) {
		directory := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(directory, "slot-pin"), []byte("wrong"), 0o600))
		connector, _ := newConnector(t, directory)

		_, err := connector.ListAddresses(context.Background(), listInput())
		require.Error(t, err)
		require.True(t, errors.IsPreconditionFailed(err), "a wrong PIN is a state the caller can act on")
	})

	t.Run("the second attempt with the same secret never reaches the HSM", func(t *testing.T) {
		directory := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(directory, "slot-pin"), []byte("wrong"), 0o600))
		connector, manager := newConnector(t, directory)

		_, err := connector.ListAddresses(context.Background(), listInput())
		require.Error(t, err)
		require.Equal(t, int32(1), manager.attempts.Load())

		for i := 0; i < 5; i++ {
			_, err = connector.ListAddresses(context.Background(), listInput())
			require.Error(t, err)
			require.True(t, errors.IsPreconditionFailed(err))
		}
		require.Equal(t, int32(1), manager.attempts.Load(), "the token must not be hammered with a PIN it already refused")
	})

	t.Run("the breaker is scoped to the slot", func(t *testing.T) {
		directory := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(directory, "slot-pin"), []byte("wrong"), 0o600))
		connector, manager := newConnector(t, directory)

		_, err := connector.ListAddresses(context.Background(), listInput())
		require.Error(t, err)

		other := listInput()
		other.Slot = "1"
		_, err = connector.ListAddresses(context.Background(), other)
		require.Error(t, err)
		require.Equal(t, int32(2), manager.attempts.Load(), "another slot must still be attempted")
	})

	t.Run("changing the secret lets the slot be attempted again", func(t *testing.T) {
		directory := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(directory, "slot-pin"), []byte("wrong"), 0o600))
		connector, manager := newConnector(t, directory)

		_, err := connector.ListAddresses(context.Background(), listInput())
		require.Error(t, err)
		require.Equal(t, int32(1), manager.attempts.Load())

		_, err = connector.ListAddresses(context.Background(), listInput())
		require.Error(t, err)
		require.Equal(t, int32(1), manager.attempts.Load(), "still the same secret")

		require.NoError(t, os.WriteFile(filepath.Join(directory, "slot-pin"), []byte("corrected"), 0o600))

		_, err = connector.ListAddresses(context.Background(), listInput())
		require.Error(t, err, "this fake refuses every PIN, so the retry still fails")
		require.Equal(t, int32(2), manager.attempts.Load(), "a corrected secret must be tried")
	})

	// IsAlive is what admin.slots.verifyPinSource runs, so it has to reach the HSM even while the
	// breaker is open: it is the operation an administrator uses to clear it.
	t.Run("verifying bypasses an open breaker", func(t *testing.T) {
		directory := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(directory, "slot-pin"), []byte("wrong"), 0o600))
		connector, manager := newConnector(t, directory)

		_, err := connector.ListAddresses(context.Background(), listInput())
		require.Error(t, err)
		require.Equal(t, int32(1), manager.attempts.Load())

		_, err = connector.IsAlive(context.Background(), hsmconnector.IsAliveInput{
			Slot:       slot,
			PinSource:  "slot-pin",
			ModuleKind: hsmconnector.SoftHSMModuleKind,
		})
		require.Error(t, err)
		require.True(t, errors.IsPreconditionFailed(err))
		require.Equal(t, int32(2), manager.attempts.Load(), "verify must reach the HSM even with the breaker open")
	})

	t.Run("a slot with neither a source nor a stored pin is refused without a login", func(t *testing.T) {
		connector, manager := newConnector(t, t.TempDir())

		input := listInput()
		input.PinSource = ""
		_, err := connector.ListAddresses(context.Background(), input)
		require.Error(t, err)
		require.True(t, errors.IsPreconditionFailed(err))
		require.Zero(t, manager.attempts.Load(), "no PIN means nothing to try")
	})

	t.Run("a slot still carrying a stored pin keeps working", func(t *testing.T) {
		connector, manager := newConnector(t, t.TempDir())

		input := listInput()
		input.PinSource = ""
		input.LegacyPin = "legacy"
		_, err := connector.ListAddresses(context.Background(), input)
		require.Error(t, err, "this fake refuses every PIN")
		require.Equal(t, int32(1), manager.attempts.Load(), "the stored PIN must still be used")
	})

	t.Run("a module kind that does not log in is never blocked", func(t *testing.T) {
		connector, manager := newConnector(t, t.TempDir())

		for i := 0; i < 3; i++ {
			_, err := connector.ListAddresses(context.Background(), hsmconnector.ListAddressesInput{
				SlotConnectionData: hsmconnector.SlotConnectionData{
					ModuleKind: hsmconnector.AKVModuleKind,
				},
			})
			require.Error(t, err, "this fake refuses every call")
		}
		require.Equal(t, int32(3), manager.attempts.Load(), "AKV has no PIN, so there is nothing to break")
	})

	t.Run("the resolved PIN does not appear in the error", func(t *testing.T) {
		directory := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(directory, "slot-pin"), []byte("s3cr3t-pin"), 0o600))
		connector, _ := newConnector(t, directory)

		_, err := connector.ListAddresses(context.Background(), listInput())
		require.Error(t, err)
		require.NotContains(t, err.Error(), "s3cr3t-pin")

		_, err = connector.ListAddresses(context.Background(), listInput())
		require.Error(t, err)
		require.NotContains(t, err.Error(), "s3cr3t-pin", "the breaker must not report the value it holds")
	})

}
