package graph_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/commons/logger"
	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/graph"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmmodule"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmslot"
	"github.com/lfdt-smoot/signare/app/test/dbtesthelper"
)

// TestHardwareOnlyReachesEveryGuard builds the generated graph with hardwareOnly set and sends one
// software-key operation through each component the setting is wired into. Each must refuse it, so
// dropping the setting from any of the generated provider calls fails here.
func TestHardwareOnlyReachesEveryGuard(t *testing.T) {
	app, err := dbtesthelper.InitializeAppWithHSMModules(&graph.HSMModules{HardwareOnly: true})
	require.NoError(t, err)
	ctx := context.Background()

	t.Run("module use case", func(t *testing.T) {
		id := "lkv"
		_, createErr := app.HSMModuleUseCase.CreateHSMModule(ctx, hsmmodule.CreateHSMModuleInput{
			ID:            &id,
			Configuration: hsmmodule.HSMModuleConfiguration{LKVConfiguration: &hsmmodule.LKVConfiguration{}},
			ModuleKind:    hsmmodule.LKVModuleKind,
		})
		require.True(t, errors.IsPreconditionFailed(createErr), "got %v", createErr)
	})

	t.Run("slot use case", func(t *testing.T) {
		_, generateErr := app.HSMSlotUseCase.GenerateLocalKey(ctx, hsmslot.GenerateLocalKeyInput{
			StandardID: entities.StandardID{ID: "slot"},
		})
		require.True(t, errors.IsPreconditionFailed(generateErr), "got %v", generateErr)
	})

	t.Run("signature manager factory", func(t *testing.T) {
		manager, createErr := app.DigitalSignatureManagerFactory.Create(ctx, hsmconnector.CreateInput{ModuleKind: hsmconnector.LKVModuleKind})
		require.NoError(t, createErr)
		_, signErr := manager.Sign(ctx, signaturemanager.SignInput{
			Tracer: logger.NewTracer(ctx),
			From:   address.MustNewFromHexString("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"),
			Data:   make([]byte, 32),
		})
		require.True(t, signaturemanager.IsPolicyRefusedError(signErr), "got %v", signErr)
	})
}
