package hsmmodule_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmmodule"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/referentialintegrity"
)

// recordingStorage stands in for the database: the policy must refuse before storage is reached, and
// a permitted module must reach it.
type recordingStorage struct {
	hsmmodule.HSMModuleStorage
	added []hsmmodule.HSMModule
}

func (s *recordingStorage) Add(_ context.Context, data hsmmodule.HSMModule) (*hsmmodule.HSMModule, error) {
	s.added = append(s.added, data)
	return &data, nil
}

func TestHardwareOnlyRefusesLocalKeyVaultModules(t *testing.T) {
	ctx := context.Background()
	storage := &recordingStorage{}
	useCase, err := hsmmodule.ProvideDefaultHSMModuleUseCase(hsmmodule.DefaultUseCaseOptions{
		HSMModuleStorage:            storage,
		ReferentialIntegrityUseCase: &referentialintegrity.DefaultUseCase{},
		HardwareOnly:                true,
	})
	require.NoError(t, err)

	t.Run("create is refused as a precondition failure", func(t *testing.T) {
		id := "lkv"
		_, createErr := useCase.CreateHSMModule(ctx, hsmmodule.CreateHSMModuleInput{
			ID:            &id,
			Configuration: hsmmodule.HSMModuleConfiguration{LKVConfiguration: &hsmmodule.LKVConfiguration{}},
			ModuleKind:    hsmmodule.LKVModuleKind,
		})
		require.Error(t, createErr)
		require.True(t, errors.IsPreconditionFailed(createErr))
		require.Contains(t, createErr.Error(), "HSM-held keys only")
		require.Empty(t, storage.added, "nothing reaches storage")
	})

	t.Run("a SoftHSM module is still created", func(t *testing.T) {
		id := "softhsm"
		out, createErr := useCase.CreateHSMModule(ctx, hsmmodule.CreateHSMModuleInput{
			ID:            &id,
			Configuration: hsmmodule.HSMModuleConfiguration{SoftHSMConfiguration: &hsmmodule.SoftHSMConfiguration{}},
			ModuleKind:    hsmmodule.SoftHSMModuleKind,
		})
		require.NoError(t, createErr)
		require.Equal(t, entities.StandardID{ID: id}, out.StandardID)
		require.Len(t, storage.added, 1)
	})
}

func TestPolicyOffAllowsLocalKeyVaultModules(t *testing.T) {
	storage := &recordingStorage{}
	useCase, err := hsmmodule.ProvideDefaultHSMModuleUseCase(hsmmodule.DefaultUseCaseOptions{
		HSMModuleStorage:            storage,
		ReferentialIntegrityUseCase: &referentialintegrity.DefaultUseCase{},
	})
	require.NoError(t, err)
	id := "lkv"
	_, createErr := useCase.CreateHSMModule(context.Background(), hsmmodule.CreateHSMModuleInput{
		ID:            &id,
		Configuration: hsmmodule.HSMModuleConfiguration{LKVConfiguration: &hsmmodule.LKVConfiguration{}},
		ModuleKind:    hsmmodule.LKVModuleKind,
	})
	require.NoError(t, createErr)
	require.Len(t, storage.added, 1)
}
