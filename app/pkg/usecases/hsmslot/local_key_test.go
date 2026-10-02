package hsmslot_test

import (
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
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
