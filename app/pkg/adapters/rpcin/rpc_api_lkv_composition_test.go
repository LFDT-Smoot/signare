package rpcin_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/adapters/rpcin"
	"github.com/lfdt-smoot/signare/app/pkg/commons/validators"
	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/graph"
	"github.com/lfdt-smoot/signare/app/pkg/infra/requestcontext"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/application"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmmodule"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmslot"
	"github.com/lfdt-smoot/signare/app/test/dbtesthelper"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

var app graph.GraphShared

// TestMain builds the application graph once: PKCS#11 can be initialised only once per process.
func TestMain(m *testing.M) {
	a, err := dbtesthelper.InitializeApp()
	if err != nil {
		panic(err)
	}
	app = *a
	validators.SetValidators()
	os.Exit(m.Run())
}

// TestLocalKeyVault_GenerateListSign_ThroughTheRealComposition runs a Local Key Vault account through
// the handler, the adapter and the wired use cases over SQLite: generated, listed, then used to sign.
// The adapter and use case tests each stop at a fake, so this is what guards the wiring between them.
func TestLocalKeyVault_GenerateListSign_ThroughTheRealComposition(t *testing.T) {
	ctx := context.Background()

	applicationID := uuid.NewString()
	_, err := app.ApplicationUseCase.CreateApplication(ctx, application.CreateApplicationInput{ID: &applicationID, ChainID: *entities.NewInt256FromInt(44844)})
	require.NoError(t, err)
	moduleID := uuid.NewString()
	description := "local key vault"
	_, err = app.HSMModuleUseCase.CreateHSMModule(ctx, hsmmodule.CreateHSMModuleInput{
		ID:            &moduleID,
		Description:   &description,
		Configuration: hsmmodule.HSMModuleConfiguration{LKVConfiguration: &hsmmodule.LKVConfiguration{}},
		ModuleKind:    hsmmodule.LKVModuleKind,
	})
	require.NoError(t, err)
	_, err = app.HSMSlotUseCase.CreateHSMSlot(ctx, hsmslot.CreateHSMSlotInput{ApplicationID: applicationID, HSMModuleID: moduleID, Slot: "lkv-0"})
	require.NoError(t, err)

	adapter, err := rpcin.NewDefaultAPIAdapter(rpcin.DefaultAPIAdapterOptions{
		AccountUseCase:        app.AccountUseCase,
		SlotUseCase:           app.HSMSlotUseCase,
		HSMConnectionResolver: app.HSMConnectionResolver,
		HSMConnector:          app.HSMConnector,
	})
	require.NoError(t, err)
	handler, err := rpcinfra.NewDefaultJSONRPCAPIHandler(rpcinfra.DefaultJSONRPCAPIHandlerOptions{Adapter: adapter})
	require.NoError(t, err)
	appCtx := context.WithValue(ctx, requestcontext.ApplicationContextKey, applicationID)

	generated, rpcErr := handler.HandleGenerateAccount(appCtx, rpcinfra.RPCRequest{ID: 1})
	require.Nil(t, rpcErr)
	addr := *generated.(*rpcinfra.RPCResponse).Result.(*string)
	require.Regexp(t, `^0x[0-9a-fA-F]{40}$`, addr)

	listed, rpcErr := handler.HandleListAccounts(appCtx, rpcinfra.RPCRequest{ID: 2})
	require.Nil(t, rpcErr)
	require.Equal(t, []string{addr}, listed.(*rpcinfra.RPCResponse).Result)

	params, err := json.Marshal(map[string]string{
		"from": addr, "to": "0xA4F666f1860D2aCbe49b342C87867754a21dE850",
		"gas": "0x5208", "gasPrice": "0x0", "value": "0x1", "nonce": "0x0",
	})
	require.NoError(t, err)
	signed, rpcErr := handler.HandleSignTX(appCtx, rpcinfra.RPCRequest{ID: 3, Params: params})
	require.Nil(t, rpcErr, "the generated key must sign as its address")
	require.Regexp(t, `^0x[0-9a-f]+$`, *signed.(*rpcinfra.RPCResponse).Result.(*string))
}
