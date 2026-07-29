package hsmconnector_test

import (
	"context"
	"math/big"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/eip712"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/test/signaturemanagertesthelper"

	"github.com/stretchr/testify/require"
)

// malformedSignatureManager is a fake DigitalSignatureManager whose Sign returns a configurable raw
// signature, used to exercise the connector's backend-signature validation without a real backend.
type malformedSignatureManager struct {
	signature []byte
}

func (m *malformedSignatureManager) Sign(_ context.Context, _ signaturemanager.SignInput) (*signaturemanager.SignOutput, error) {
	return &signaturemanager.SignOutput{Signature: m.signature}, nil
}

func (m *malformedSignatureManager) GenerateKey(_ context.Context, _ signaturemanager.GenerateKeyInput) (*signaturemanager.GenerateKeyOutput, error) {
	return &signaturemanager.GenerateKeyOutput{}, nil
}

func (m *malformedSignatureManager) DeriveAddressFromPrivateKey(_ context.Context, _ signaturemanager.DeriveAddressFromPrivateKeyInput) (*signaturemanager.DeriveAddressFromPrivateKeyOutput, error) {
	return &signaturemanager.DeriveAddressFromPrivateKeyOutput{}, nil
}

func (m *malformedSignatureManager) RemoveKey(_ context.Context, _ signaturemanager.RemoveKeyInput) (*signaturemanager.RemoveKeyOutput, error) {
	return &signaturemanager.RemoveKeyOutput{}, nil
}

func (m *malformedSignatureManager) ListKeys(_ context.Context, _ signaturemanager.ListKeysInput) (*signaturemanager.ListKeysOutput, error) {
	return &signaturemanager.ListKeysOutput{}, nil
}

func (m *malformedSignatureManager) Close(_ context.Context, _ signaturemanager.CloseInput) (*signaturemanager.CloseOutput, error) {
	return &signaturemanager.CloseOutput{}, nil
}

func (m *malformedSignatureManager) Open(_ context.Context, _ signaturemanager.OpenInput) (*signaturemanager.OpenOutput, error) {
	return &signaturemanager.OpenOutput{}, nil
}

func (m *malformedSignatureManager) IsAlive(_ context.Context, _ signaturemanager.IsAliveInput) (*signaturemanager.IsAliveOutput, error) {
	return &signaturemanager.IsAliveOutput{IsAlive: true}, nil
}

// malformedSignatureFactory is a fake DigitalSignatureManagerFactory returning a malformedSignatureManager.
type malformedSignatureFactory struct {
	manager *malformedSignatureManager
}

func (f *malformedSignatureFactory) Create(_ context.Context, _ hsmconnector.CreateInput) (signaturemanager.DigitalSignatureManager, error) {
	return f.manager, nil
}

func (f *malformedSignatureFactory) Close(_ context.Context, _ hsmconnector.CloseInput) (*hsmconnector.CloseOutput, error) {
	return &hsmconnector.CloseOutput{}, nil
}

func (f *malformedSignatureFactory) Reset(_ context.Context, _ hsmconnector.ModuleKind) error {
	return nil
}

// connectorWithBackendSignature builds an HSMConnector backed by a fake signature manager that
// returns the given raw signature, for exercising the connector's backend-signature validation.
func connectorWithBackendSignature(t *testing.T, sig []byte) hsmconnector.HSMConnector {
	t.Helper()
	factory := &malformedSignatureFactory{manager: &malformedSignatureManager{signature: sig}}
	connector, err := hsmconnector.ProvideDefaultHSMConnector(hsmconnector.DefaultUseCaseOptions{
		DigitalSignatureManagerFactory: factory,
	})
	require.NoError(t, err)
	return connector
}

// malformedBackendSignatures are the malformed raw signatures shared by the connector validation
// tests: a wrong-length signature and a 64-byte r||s with s == 0 (r == 1).
func malformedBackendSignatures() map[string][]byte {
	sZero := make([]byte, 64)
	sZero[31] = 0x01 // r = 1, s = 0
	return map[string][]byte{
		"wrong length (63 bytes)": make([]byte, 63),
		"s == 0":                  sZero,
	}
}

func TestDefaultUseCase_SignTx_MalformedBackendSignature(t *testing.T) {
	toAddress := address.MustNewFromHexString("0xA4F666f1860D2aCbe49b342C87867754a21dE850")

	legacyTxInput := func() hsmconnector.SignTxInput {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		return hsmconnector.SignTxInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			ChainID: *chainIDHex,
			From:    address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:      &toAddress,
			Data:    *data,
			Nonce:   entities.HexUInt64{UInt64: 1},
		}
	}

	for name, sig := range malformedBackendSignatures() {
		t.Run(name, func(t *testing.T) {
			signTxOutput, err := connectorWithBackendSignature(t, sig).SignTx(ctx, legacyTxInput())
			require.Error(t, err)
			require.Nil(t, signTxOutput)
			require.True(t, errors.IsBadGateway(err))
			require.Contains(t, err.Error(), "malformed signature")
			require.NotContains(t, err.Error(), "unable to find EC recovery value")
		})
	}
}

// TestDefaultUseCase_SignTypedData exercises the public typed-data signing path end to end against
// the real backend. It is a regression guard for the unregistered "typedData" validator that
// previously made govalidator reject every SignTypedData request.
func TestDefaultUseCase_SignTypedData(t *testing.T) {
	signTypedDataInput := hsmconnector.SignTypedDataInput{
		SlotConnectionData: hsmconnector.SlotConnectionData{
			Slot:       slotID,
			Pin:        slotPin,
			ModuleKind: hsmconnector.SoftHSMModuleKind,
		},
		ChainID:   entities.HexInt256{Int256: entities.Int256{Int: *big.NewInt(1)}},
		Address:   address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
		TypedData: etherMailTypedData(),
	}

	signTypedDataOutput, err := app.HSMConnector.SignTypedData(ctx, signTypedDataInput)
	require.NoError(t, err)
	require.NotNil(t, signTypedDataOutput)
	require.NotEmpty(t, signTypedDataOutput.SignedData)
	require.NotEmpty(t, signTypedDataOutput.TypedHash)
}

// TestDefaultUseCase_SignTypedData_InvalidTypedData guards that a degenerate (empty) TypedData is
// rejected as invalid input rather than signed. Skipping govalidator on the field must not mean
// skipping validation altogether.
func TestDefaultUseCase_SignTypedData_InvalidTypedData(t *testing.T) {
	signTypedDataOutput, err := app.HSMConnector.SignTypedData(ctx, hsmconnector.SignTypedDataInput{
		SlotConnectionData: hsmconnector.SlotConnectionData{
			Slot:       slotID,
			Pin:        slotPin,
			ModuleKind: hsmconnector.SoftHSMModuleKind,
		},
		ChainID:   entities.HexInt256{Int256: entities.Int256{Int: *big.NewInt(1)}},
		Address:   address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
		TypedData: eip712.TypedData{}, // empty/degenerate: must be rejected, not signed
	})
	require.Error(t, err)
	require.Nil(t, signTypedDataOutput)
	require.True(t, errors.IsInvalidArgument(err))
}

func TestDefaultUseCase_SignTypedData_MalformedBackendSignature(t *testing.T) {
	signTypedDataInput := func() hsmconnector.SignTypedDataInput {
		return hsmconnector.SignTypedDataInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			ChainID:   entities.HexInt256{Int256: entities.Int256{Int: *big.NewInt(1)}},
			Address:   address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			TypedData: etherMailTypedData(),
		}
	}

	for name, sig := range malformedBackendSignatures() {
		t.Run(name, func(t *testing.T) {
			signTypedDataOutput, err := connectorWithBackendSignature(t, sig).SignTypedData(ctx, signTypedDataInput())
			require.Error(t, err)
			require.Nil(t, signTypedDataOutput)
			require.True(t, errors.IsBadGateway(err))
			require.Contains(t, err.Error(), "malformed signature")
			require.NotContains(t, err.Error(), "unable to find EC recovery value")
		})
	}
}

// etherMailTypedData returns the canonical EIP-712 "Ether Mail" example used by the typed-data tests.
func etherMailTypedData() eip712.TypedData {
	return eip712.TypedData{
		Types: eip712.Types{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"Person": {
				{Name: "name", Type: "string"},
				{Name: "wallet", Type: "address"},
			},
			"Mail": {
				{Name: "from", Type: "Person"},
				{Name: "to", Type: "Person"},
				{Name: "contents", Type: "string"},
			},
		},
		PrimaryType: "Mail",
		Domain: eip712.EIP712Domain{
			Name:              "Ether Mail",
			Version:           "1",
			ChainId:           big.NewInt(1),
			VerifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
		},
		Message: eip712.EIP712Message{
			"from":     map[string]interface{}{"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
			"to":       map[string]interface{}{"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
			"contents": "Hello, Bob!",
		},
	}
}
