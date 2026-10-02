package rpcin

import (
	"context"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra/rpcerrors"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnection"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmslot"

	"github.com/stretchr/testify/require"
)

// fakeSlotUseCase implements only the Local Key Vault methods; anything else panics through the
// embedded nil interface.
type fakeSlotUseCase struct {
	hsmslot.HSMSlotUseCase
	generated    address.Address
	generateErr  error
	gotGenerate  *hsmslot.GenerateLocalKeyInput
	listErr      error
	listedOutput *hsmslot.ListLocalKeysOutput
}

func (f *fakeSlotUseCase) GenerateLocalKey(_ context.Context, input hsmslot.GenerateLocalKeyInput) (*hsmslot.GenerateLocalKeyOutput, error) {
	f.gotGenerate = &input
	if f.generateErr != nil {
		return nil, f.generateErr
	}
	return &hsmslot.GenerateLocalKeyOutput{Address: f.generated}, nil
}

func (f *fakeSlotUseCase) ListLocalKeys(_ context.Context, _ hsmslot.ListLocalKeysInput) (*hsmslot.ListLocalKeysOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listedOutput, nil
}

// fakeGenerateConnector implements only GenerateAddress.
type fakeGenerateConnector struct {
	hsmconnector.HSMConnector
	generated address.Address
	called    bool
}

func (f *fakeGenerateConnector) GenerateAddress(_ context.Context, _ hsmconnector.GenerateAddressInput) (*hsmconnector.GenerateAddressOutput, error) {
	f.called = true
	return &hsmconnector.GenerateAddressOutput{Address: f.generated}, nil
}

func connectionOfKind(kind hsmconnector.ModuleKind) fakeConnectionResolver {
	return fakeConnectionResolver{connection: &hsmconnection.HSMConnection{
		ModuleKind: kind,
	}}
}

func mustAddress(t *testing.T, hex string) address.Address {
	t.Helper()
	addr, err := address.NewFromHexString(hex)
	require.NoError(t, err)
	return addr
}

func TestAdaptGenerateAccount_LocalKeyVaultGeneratesInTheSlot(t *testing.T) {
	generated := mustAddress(t, "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23")
	resolver := connectionOfKind(hsmconnector.LKVModuleKind)
	resolver.connection.Slot.ID = "lkv-slot"
	slots := &fakeSlotUseCase{generated: generated}
	connector := &fakeGenerateConnector{}
	adapter := &DefaultAPIAdapter{hsmConnectionResolver: resolver, slotUseCase: slots, hsmConnector: connector}

	out, rpcErr := adapter.AdaptGenerateAccount(context.Background(), rpcinfra.GenerateAccountRequestParams{ApplicationID: "app1"})
	require.Nil(t, rpcErr)
	require.Equal(t, generated.String(), *out)
	require.NotNil(t, slots.gotGenerate)
	require.Equal(t, "lkv-slot", slots.gotGenerate.ID)
	require.False(t, connector.called, "a Local Key Vault key must not be generated through the connector")
}

func TestAdaptGenerateAccount_OtherKindsGenerateInTheModule(t *testing.T) {
	generated := mustAddress(t, "0x87Bee29C1942d15E9CAE97839A9FD0e9ff723fDE")
	slots := &fakeSlotUseCase{}
	connector := &fakeGenerateConnector{generated: generated}
	adapter := &DefaultAPIAdapter{hsmConnectionResolver: connectionOfKind(hsmconnector.SoftHSMModuleKind), slotUseCase: slots, hsmConnector: connector}

	out, rpcErr := adapter.AdaptGenerateAccount(context.Background(), rpcinfra.GenerateAccountRequestParams{ApplicationID: "app1"})
	require.Nil(t, rpcErr)
	require.Equal(t, generated.String(), *out)
	require.True(t, connector.called)
	require.Nil(t, slots.gotGenerate, "a module key must not be written to the slot configuration")
}

func TestAdaptGenerateAccount_LocalKeyVaultErrorKeepsItsClass(t *testing.T) {
	slots := &fakeSlotUseCase{generateErr: errors.PreconditionFailed().WithMessage("not a local key vault")}
	adapter := &DefaultAPIAdapter{hsmConnectionResolver: connectionOfKind(hsmconnector.LKVModuleKind), slotUseCase: slots, hsmConnector: &fakeGenerateConnector{}}

	out, rpcErr := adapter.AdaptGenerateAccount(context.Background(), rpcinfra.GenerateAccountRequestParams{ApplicationID: "app1"})
	require.Nil(t, out)
	require.NotNil(t, rpcErr)
	require.Equal(t, rpcerrors.PreconditionFailedErrorCode, rpcErr.Code)
}

// TestAdaptListAccounts_LocalKeyVaultErrorKeepsItsClass guards the error the adapter maps: it must be
// the one ListLocalKeys returned, not the resolver's nil error, which flattened every failure to an
// internal error and dropped its cause from the log.
func TestAdaptListAccounts_LocalKeyVaultErrorKeepsItsClass(t *testing.T) {
	listErr := errors.NotFound().WithMessage("slot not found")
	slots := &fakeSlotUseCase{listErr: listErr}
	adapter := &DefaultAPIAdapter{hsmConnectionResolver: connectionOfKind(hsmconnector.LKVModuleKind), slotUseCase: slots}

	out, rpcErr := adapter.AdaptListAccounts(context.Background(), rpcinfra.ListAccountsRequestParams{ApplicationID: "app1"})
	require.Nil(t, out)
	require.NotNil(t, rpcErr)
	require.Equal(t, rpcerrors.NotFoundErrorCode, rpcErr.Code)
	require.ErrorIs(t, rpcErr.WrappedErr, listErr)
}
