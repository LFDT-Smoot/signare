package hsmslot_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/adapters/storage/postgres/hsmslotdbout"
	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/application"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmmodule"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmslot"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/referentialintegrity"
)

// lkvModules answers every module lookup with a Local Key Vault module.
type lkvModules struct {
	hsmmodule.HSMModuleUseCase
}

func (lkvModules) GetHSMModule(_ context.Context, input hsmmodule.GetHSMModuleInput) (*hsmmodule.GetHSMModuleOutput, error) {
	module := hsmmodule.HSMModule{Kind: hsmmodule.LKVModuleKind}
	module.ID = input.ID
	return &hsmmodule.GetHSMModuleOutput{HSMModule: module}, nil
}

// TestHardwareOnlyRefusesLocalKeyVaultSlots: the refusal comes right after the module lookup, before
// the slot is stored.
func TestHardwareOnlyRefusesLocalKeyVaultSlots(t *testing.T) {
	useCase, err := hsmslot.ProvideDefaultUseCase(hsmslot.DefaultUseCaseOptions{
		HSMSlotStorage:              &hsmslotdbout.Repository{},
		ApplicationUseCase:          &application.DefaultUseCase{},
		HSMModuleUseCase:            lkvModules{},
		HSMConnector:                &hsmconnector.DefaultUseCase{},
		ReferentialIntegrityUseCase: &referentialintegrity.DefaultUseCase{},
		HardwareOnly:                true,
	})
	require.NoError(t, err)

	_, createErr := useCase.CreateHSMSlot(context.Background(), hsmslot.CreateHSMSlotInput{
		ApplicationID: "app",
		HSMModuleID:   "lkv",
		Slot:          "0",
	})
	require.Error(t, createErr)
	require.True(t, errors.IsPreconditionFailed(createErr))
	require.Contains(t, createErr.Error(), "HSM-held keys only")
}

// TestHardwareOnlyRefusesLocalKeys: the refusal comes before any lookup, so the zero-value
// dependencies are never touched.
func TestHardwareOnlyRefusesLocalKeys(t *testing.T) {
	useCase, err := hsmslot.ProvideDefaultUseCase(hsmslot.DefaultUseCaseOptions{
		HSMSlotStorage:              &hsmslotdbout.Repository{},
		ApplicationUseCase:          &application.DefaultUseCase{},
		HSMModuleUseCase:            &hsmmodule.DefaultUseCase{},
		HSMConnector:                &hsmconnector.DefaultUseCase{},
		ReferentialIntegrityUseCase: &referentialintegrity.DefaultUseCase{},
		HardwareOnly:                true,
	})
	require.NoError(t, err)

	_, generateErr := useCase.GenerateLocalKey(context.Background(), hsmslot.GenerateLocalKeyInput{
		StandardID: entities.StandardID{ID: "slot"},
	})
	require.Error(t, generateErr)
	require.True(t, errors.IsPreconditionFailed(generateErr))
	require.Contains(t, generateErr.Error(), "HSM-held keys only")
}
