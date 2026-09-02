package hsmconnector_test

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/eip191"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/eip712"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/test/signaturemanagertesthelper"

	btcececdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
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

// TestDefaultUseCase_SignTypedData_EncoderErrorIsInvalidArgument covers the branch that classifies a
// HashTypedData failure. TestDefaultUseCase_SignTypedData_InvalidTypedData does not reach it: an empty
// TypedData is caught by the Validate call above, so encoding never starts. These payloads pass Validate
// and fail inside the encoder, which is the only way into that branch.
//
// Every failure there is caused by the caller's own types or message, so the classification has to be
// InvalidArgument. Returning the encoder error unwrapped would fall through adaptError to -32603
// Internal error and report attacker-controlled input as a signer fault.
func TestDefaultUseCase_SignTypedData_EncoderErrorIsInvalidArgument(t *testing.T) {
	// deepArrayType nests array notation past the encoder's depth cap, with a message to match.
	deepArrayType := func(depth int) (string, interface{}) {
		fieldType := "string"
		var value interface{} = "leaf"
		for i := 0; i < depth; i++ {
			fieldType += "[]"
			value = []interface{}{value}
		}
		return fieldType, value
	}

	testCases := map[string]func() eip712.TypedData{
		"value of the wrong shape for its declared type": func() eip712.TypedData {
			typedData := etherMailTypedData()
			// Mail.contents is declared as string, so a number fails the encoder's type assertion.
			typedData.Message["contents"] = 42
			return typedData
		},
		"unsupported field type": func() eip712.TypedData {
			typedData := etherMailTypedData()
			typedData.Types["Mail"] = append(typedData.Types["Mail"], eip712.Type{Name: "extra", Type: "tuple"})
			typedData.Message["extra"] = "anything"
			return typedData
		},
		"nesting beyond the depth cap": func() eip712.TypedData {
			typedData := etherMailTypedData()
			fieldType, value := deepArrayType(40)
			typedData.Types["Mail"] = append(typedData.Types["Mail"], eip712.Type{Name: "deep", Type: fieldType})
			typedData.Message["deep"] = value
			return typedData
		},
	}

	for name, buildTypedData := range testCases {
		t.Run(name, func(t *testing.T) {
			typedData := buildTypedData()
			require.NoError(t, typedData.Validate(), "the payload must pass Validate, otherwise the encoder branch is not reached")

			signTypedDataOutput, err := app.HSMConnector.SignTypedData(ctx, hsmconnector.SignTypedDataInput{
				SlotConnectionData: hsmconnector.SlotConnectionData{
					Slot:       slotID,
					Pin:        slotPin,
					ModuleKind: hsmconnector.SoftHSMModuleKind,
				},
				ChainID:   entities.HexInt256{Int256: entities.Int256{Int: *big.NewInt(1)}},
				Address:   address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
				TypedData: typedData,
			})

			require.Error(t, err)
			require.Nil(t, signTypedDataOutput)
			require.True(t, errors.IsInvalidArgument(err), "encoder failures are caused by the caller's input, got %v", err)
		})
	}
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

// TestDefaultUseCase_PersonalSign_RecoversSigner is the acceptance criterion from the issue: a
// personal_sign signature over an arbitrary message must EC-recover to the signing account, which is
// exactly what a SIWE verifier does. Signing and then recovering is the only check that proves the
// digest, the recovery byte and the serialisation all agree; asserting the output is non-empty would
// pass with a wrong prefix.
func TestDefaultUseCase_PersonalSign_RecoversSigner(t *testing.T) {
	expected := address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress)
	message := []byte("example.com wants you to sign in with your Ethereum account")

	out, err := app.HSMConnector.PersonalSign(ctx, hsmconnector.PersonalSignInput{
		SlotConnectionData: hsmconnector.SlotConnectionData{
			Slot:       slotID,
			Pin:        slotPin,
			ModuleKind: hsmconnector.SoftHSMModuleKind,
		},
		Address: expected,
		Message: message,
	})
	require.NoError(t, err)
	require.NotNil(t, out)

	digest, digestErr := eip191.HashPersonalMessage(message)
	require.NoError(t, digestErr)
	require.Equal(t, hex.EncodeToString(digest), out.Digest, "the reported digest must be the one that was signed")

	signature, decodeErr := hex.DecodeString(strings.TrimPrefix(out.SignedData, "0x"))
	require.NoError(t, decodeErr)
	require.Len(t, signature, 65, "SIWE verifiers expect a 65-byte r||s||v signature")

	v := signature[64]
	require.Contains(t, []byte{27, 28}, v, "EIP-191 signatures carry a plain 27/28 recovery byte, not the EIP-155 form")

	// btcec's RecoverCompact takes v||r||s, while the wire format is r||s||v.
	compact := make([]byte, 65)
	compact[0] = v
	copy(compact[1:], signature[:64])

	publicKey, _, recoverErr := btcececdsa.RecoverCompact(compact, digest)
	require.NoError(t, recoverErr)
	recovered, deriveErr := signaturemanager.DeriveAddressFromPublicKey(publicKey.SerializeUncompressed())
	require.NoError(t, deriveErr)
	require.Equal(t, expected.String(), recovered.String())
}

// A signature over a different message must not recover to the signer, which pins that the message
// bytes actually reach the digest rather than being ignored.
func TestDefaultUseCase_PersonalSign_MessageIsBoundToTheSignature(t *testing.T) {
	signer := address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress)
	input := func(message []byte) hsmconnector.PersonalSignInput {
		return hsmconnector.PersonalSignInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			Address: signer,
			Message: message,
		}
	}

	first, err := app.HSMConnector.PersonalSign(ctx, input([]byte("message one")))
	require.NoError(t, err)
	second, err := app.HSMConnector.PersonalSign(ctx, input([]byte("message two")))
	require.NoError(t, err)

	require.NotEqual(t, first.Digest, second.Digest)
	require.NotEqual(t, first.SignedData, second.SignedData)
}

func TestDefaultUseCase_PersonalSign_RejectsEmptyMessage(t *testing.T) {
	out, err := app.HSMConnector.PersonalSign(ctx, hsmconnector.PersonalSignInput{
		SlotConnectionData: hsmconnector.SlotConnectionData{
			Slot:       slotID,
			Pin:        slotPin,
			ModuleKind: hsmconnector.SoftHSMModuleKind,
		},
		Address: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
		Message: []byte{},
	})
	require.Error(t, err)
	require.Nil(t, out)
	require.True(t, errors.IsInvalidArgument(err))
}

func TestDefaultUseCase_PersonalSign_RejectsEmptyAddress(t *testing.T) {
	out, err := app.HSMConnector.PersonalSign(ctx, hsmconnector.PersonalSignInput{
		SlotConnectionData: hsmconnector.SlotConnectionData{
			Slot:       slotID,
			Pin:        slotPin,
			ModuleKind: hsmconnector.SoftHSMModuleKind,
		},
		Message: []byte("hello"),
	})
	require.Error(t, err)
	require.Nil(t, out)
	require.True(t, errors.IsInvalidArgument(err))
}
