package hsmslot_test

import (
	"context"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager/localkeyvault"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/application"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmmodule"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmslot"

	curves "github.com/btcsuite/btcd/btcec/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// createLKVSlot creates an application with a slot on a fresh Local Key Vault module.
func createLKVSlot(t *testing.T) *hsmslot.HSMSlot {
	t.Helper()
	applicationID := uuid.NewString()
	_, err := app.ApplicationUseCase.CreateApplication(ctx, application.CreateApplicationInput{
		ID:      &applicationID,
		ChainID: *chainID,
	})
	require.NoError(t, err)

	moduleID := uuid.NewString()
	_, err = app.HSMModuleUseCase.CreateHSMModule(ctx, hsmmodule.CreateHSMModuleInput{
		ID:            &moduleID,
		Description:   &resourceDescription,
		Configuration: hsmmodule.HSMModuleConfiguration{LKVConfiguration: &hsmmodule.LKVConfiguration{}},
		ModuleKind:    hsmmodule.LKVModuleKind,
	})
	require.NoError(t, err)

	slot, err := app.HSMSlotUseCase.CreateHSMSlot(ctx, hsmslot.CreateHSMSlotInput{
		ApplicationID: applicationID,
		HSMModuleID:   moduleID,
		Slot:          "lkv-" + uuid.NewString()[:8],
	})
	require.NoError(t, err)
	return &slot.HSMSlot
}

// addressOfStoredKey derives the address of a key store entry independently of the code under test.
func addressOfStoredKey(t *testing.T, storedKey string) string {
	t.Helper()
	keyBytes, err := entities.NewHexBytesFromString(storedKey)
	require.NoError(t, err)
	require.Len(t, keyBytes, 32)
	x, y := curves.S256().ScalarBaseMult(keyBytes)
	hash, err := entities.HashKeccak256(append(x.FillBytes(make([]byte, 32)), y.FillBytes(make([]byte, 32))...))
	require.NoError(t, err)
	addr, err := address.NewFromRawBytes(hash.Bytes()[12:])
	require.NoError(t, err)
	return addr.String()
}

func TestDefaultUseCase_GenerateLocalKey(t *testing.T) {
	t.Run("failure: invalid input arguments", func(t *testing.T) {
		out, err := app.HSMSlotUseCase.GenerateLocalKey(ctx, hsmslot.GenerateLocalKeyInput{})
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, out)
	})

	t.Run("failure: slot not found", func(t *testing.T) {
		out, err := app.HSMSlotUseCase.GenerateLocalKey(ctx, hsmslot.GenerateLocalKeyInput{
			StandardID: entities.StandardID{ID: uuid.NewString()},
		})
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Nil(t, out)
	})

	t.Run("failure: slot is not on a Local Key Vault", func(t *testing.T) {
		applicationID := uuid.NewString()
		_, err := app.ApplicationUseCase.CreateApplication(ctx, application.CreateApplicationInput{
			ID:      &applicationID,
			ChainID: *chainID,
		})
		require.NoError(t, err)
		module := createOrGetModule(t, "0c1f7a52-5c3e-4f7e-9d0b-6a2b9f1e4d38")
		slot := createOrGetSlot(t, applicationID, slotIDTwo, module.ID)

		out, err := app.HSMSlotUseCase.GenerateLocalKey(ctx, hsmslot.GenerateLocalKeyInput{StandardID: slot.StandardID})
		require.Error(t, err)
		require.True(t, errors.IsPreconditionFailed(err))
		require.Nil(t, out)

		stored, err := app.HSMSlotUseCase.GetHSMSlot(ctx, hsmslot.GetHSMSlotInput{StandardID: slot.StandardID})
		require.NoError(t, err)
		require.Nil(t, stored.Config.LocalKeyVault, "a refused generation must not write a key store")
	})

	t.Run("success: each key is stored under its own address", func(t *testing.T) {
		slot := createLKVSlot(t)

		first, err := app.HSMSlotUseCase.GenerateLocalKey(ctx, hsmslot.GenerateLocalKeyInput{StandardID: slot.StandardID})
		require.NoError(t, err)
		second, err := app.HSMSlotUseCase.GenerateLocalKey(ctx, hsmslot.GenerateLocalKeyInput{StandardID: slot.StandardID})
		require.NoError(t, err)
		require.NotEqual(t, first.Address, second.Address)

		stored, err := app.HSMSlotUseCase.GetHSMSlot(ctx, hsmslot.GetHSMSlotInput{StandardID: slot.StandardID})
		require.NoError(t, err)
		require.NotNil(t, stored.Config.LocalKeyVault)
		require.Len(t, stored.Config.LocalKeyVault.KeyStore, 2)
		for _, generated := range []address.Address{first.Address, second.Address} {
			storedKey, ok := stored.Config.LocalKeyVault.KeyStore[generated]
			require.True(t, ok, "generated address %s missing from the key store", generated)
			require.Equal(t, generated.String(), addressOfStoredKey(t, storedKey))
		}

		listed, err := app.HSMSlotUseCase.ListLocalKeys(ctx, hsmslot.ListLocalKeysInput{StandardID: slot.StandardID})
		require.NoError(t, err)
		require.ElementsMatch(t, []address.Address{first.Address, second.Address}, listed.Addresses)

		require.NoError(t, app.HSMSlotUseCase.RemoveLocalKey(ctx, hsmslot.RemoveLocalKeyInput{StandardID: slot.StandardID, Address: first.Address}))
		listed, err = app.HSMSlotUseCase.ListLocalKeys(ctx, hsmslot.ListLocalKeysInput{StandardID: slot.StandardID})
		require.NoError(t, err)
		require.Equal(t, []address.Address{second.Address}, listed.Addresses)
	})
}

// versionedSlotStorage holds one slot and enforces the resource version guard the SQL `updateConfig`
// statement applies. conflicts makes that many writes lose to a concurrent writer, which adds a key of
// its own and bumps the version; deleteOnWrite makes the slot disappear at the first write.
type versionedSlotStorage struct {
	hsmslot.HSMSlotStorage
	slot          hsmslot.HSMSlot
	conflicts     int
	deleteOnWrite bool
	failWrite     bool
	deleted       bool
	writes        int
	otherKeys     []address.Address
}

func cloneSlot(slot hsmslot.HSMSlot) hsmslot.HSMSlot {
	if slot.Config.LocalKeyVault != nil {
		store := make(map[address.Address]string, len(slot.Config.LocalKeyVault.KeyStore))
		for addr, key := range slot.Config.LocalKeyVault.KeyStore {
			store[addr] = key
		}
		slot.Config.LocalKeyVault = &hsmslot.LocalKeyVaultConfig{KeyStore: store}
	}
	return slot
}

func (s *versionedSlotStorage) Get(_ context.Context, _ entities.StandardID) (*hsmslot.HSMSlot, error) {
	if s.deleted {
		return nil, errors.NotFound().WithMessage("slot deleted")
	}
	slot := cloneSlot(s.slot)
	return &slot, nil
}

func (s *versionedSlotStorage) EditConfig(_ context.Context, data hsmslot.HSMSlot) (*hsmslot.HSMSlot, error) {
	s.writes++
	if s.failWrite {
		return nil, errors.Internal().WithMessage("database unavailable")
	}
	if s.deleteOnWrite {
		s.deleted = true
		return nil, errors.NotFound().WithMessage("resource 'hsm_slot' does not match the one stored")
	}
	if s.conflicts > 0 {
		s.conflicts--
		_, other, err := localkeyvault.NewKey()
		if err != nil {
			return nil, err
		}
		if s.slot.Config.LocalKeyVault == nil {
			s.slot.Config.LocalKeyVault = &hsmslot.LocalKeyVaultConfig{KeyStore: map[address.Address]string{}}
		}
		s.slot.Config.LocalKeyVault.KeyStore[*other] = "written-by-another-request"
		s.slot.ResourceVersion = uuid.NewString()
		s.otherKeys = append(s.otherKeys, *other)
	}
	if data.ResourceVersion != s.slot.ResourceVersion {
		return nil, errors.NotFound().WithMessage("resource 'hsm_slot' does not match the one stored")
	}
	s.slot = cloneSlot(data)
	s.slot.ResourceVersion = uuid.NewString()
	slot := cloneSlot(s.slot)
	return &slot, nil
}

// useCaseOver builds a slot use case over storage, with the real module use case, and a slot on a
// fresh Local Key Vault module.
func useCaseOver(t *testing.T, storage *versionedSlotStorage) *hsmslot.DefaultUseCase {
	t.Helper()
	moduleID := uuid.NewString()
	_, err := app.HSMModuleUseCase.CreateHSMModule(ctx, hsmmodule.CreateHSMModuleInput{
		ID:            &moduleID,
		Description:   &resourceDescription,
		Configuration: hsmmodule.HSMModuleConfiguration{LKVConfiguration: &hsmmodule.LKVConfiguration{}},
		ModuleKind:    hsmmodule.LKVModuleKind,
	})
	require.NoError(t, err)

	storage.slot.ID = "lkv-slot"
	storage.slot.HSMModuleID = moduleID
	storage.slot.ResourceVersion = uuid.NewString()

	useCase, err := hsmslot.ProvideDefaultUseCase(hsmslot.DefaultUseCaseOptions{
		HSMSlotStorage:              storage,
		ApplicationUseCase:          app.ApplicationUseCase,
		HSMModuleUseCase:            app.HSMModuleUseCase,
		HSMConnector:                app.HSMConnector,
		ReferentialIntegrityUseCase: app.ReferentialIntegrityUseCase,
	})
	require.NoError(t, err)
	return useCase
}

func TestDefaultUseCase_GenerateLocalKey_ConcurrentWriter(t *testing.T) {
	input := hsmslot.GenerateLocalKeyInput{StandardID: entities.StandardID{ID: "lkv-slot"}}

	t.Run("a lost write is retried on top of the other writer's key", func(t *testing.T) {
		storage := &versionedSlotStorage{conflicts: 1}
		out, err := useCaseOver(t, storage).GenerateLocalKey(ctx, input)
		require.NoError(t, err)
		require.Equal(t, 2, storage.writes)

		store := storage.slot.Config.LocalKeyVault.KeyStore
		require.Len(t, store, 2)
		require.Contains(t, store, out.Address)
		require.Contains(t, store, storage.otherKeys[0], "the retry must not overwrite the other writer's key")
	})

	t.Run("a write that keeps losing is reported as a precondition failure", func(t *testing.T) {
		storage := &versionedSlotStorage{conflicts: hsmslot.LocalKeyWriteAttempts}
		out, err := useCaseOver(t, storage).GenerateLocalKey(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsPreconditionFailed(err), "a slot that exists must not be reported as not found")
		require.Nil(t, out)
		require.Equal(t, hsmslot.LocalKeyWriteAttempts, storage.writes)
		require.ElementsMatch(t, storage.otherKeys, keysOf(storage.slot.Config.LocalKeyVault.KeyStore), "no generated key may be stored")
	})

	t.Run("a storage failure is reported as internal, without a retry", func(t *testing.T) {
		storage := &versionedSlotStorage{failWrite: true}
		out, err := useCaseOver(t, storage).GenerateLocalKey(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInternal(err))
		require.Nil(t, out)
		require.Equal(t, 1, storage.writes)
	})

	t.Run("a slot deleted before the write is reported as not found", func(t *testing.T) {
		storage := &versionedSlotStorage{deleteOnWrite: true}
		out, err := useCaseOver(t, storage).GenerateLocalKey(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Nil(t, out)
		require.Equal(t, 1, storage.writes)
	})
}

func keysOf(store map[address.Address]string) []address.Address {
	keys := make([]address.Address, 0, len(store))
	for addr := range store {
		keys = append(keys, addr)
	}
	return keys
}

func TestDefaultUseCase_RemoveLocalKey_ConcurrentWriter(t *testing.T) {
	_, target, err := localkeyvault.NewKey()
	require.NoError(t, err)
	input := hsmslot.RemoveLocalKeyInput{StandardID: entities.StandardID{ID: "lkv-slot"}, Address: *target}
	storageHolding := func(conflicts int) *versionedSlotStorage {
		storage := &versionedSlotStorage{conflicts: conflicts}
		storage.slot.Config.LocalKeyVault = &hsmslot.LocalKeyVaultConfig{KeyStore: map[address.Address]string{*target: "stored"}}
		return storage
	}

	t.Run("a lost write is retried on top of the other writer's key", func(t *testing.T) {
		storage := storageHolding(1)
		require.NoError(t, useCaseOver(t, storage).RemoveLocalKey(ctx, input))
		require.Equal(t, 2, storage.writes)
		require.ElementsMatch(t, storage.otherKeys, keysOf(storage.slot.Config.LocalKeyVault.KeyStore),
			"the key is removed and the other writer's key kept")
	})

	t.Run("a write that keeps losing is reported as a precondition failure", func(t *testing.T) {
		storage := storageHolding(hsmslot.LocalKeyWriteAttempts)
		err := useCaseOver(t, storage).RemoveLocalKey(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsPreconditionFailed(err), "a slot and address that exist must not be reported as not found")
		require.Contains(t, storage.slot.Config.LocalKeyVault.KeyStore, *target, "nothing may be removed")
	})

	t.Run("a slot that does not exist is reported as not found", func(t *testing.T) {
		err := app.HSMSlotUseCase.RemoveLocalKey(ctx, hsmslot.RemoveLocalKeyInput{StandardID: entities.StandardID{ID: uuid.NewString()}, Address: *target})
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
	})

	t.Run("an address the slot does not hold is reported as not found", func(t *testing.T) {
		storage := storageHolding(0)
		_, other, err := localkeyvault.NewKey()
		require.NoError(t, err)
		err = useCaseOver(t, storage).RemoveLocalKey(ctx, hsmslot.RemoveLocalKeyInput{StandardID: input.StandardID, Address: *other})
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Zero(t, storage.writes)
	})
}
