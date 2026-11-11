package hsmconnector_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/test/signaturemanagertesthelper"
)

// refusingManager fails key generation the way the PKCS#11 adapter does when a token ignores the
// protection attributes.
type refusingManager struct {
	signaturemanager.DigitalSignatureManager
	err error
}

func (m refusingManager) GenerateKey(_ context.Context, _ signaturemanager.GenerateKeyInput) (*signaturemanager.GenerateKeyOutput, error) {
	return nil, m.err
}

type fixedFactory struct {
	hsmconnector.DigitalSignatureManagerFactory
	manager signaturemanager.DigitalSignatureManager
}

func (f fixedFactory) Create(_ context.Context, _ hsmconnector.CreateInput) (signaturemanager.DigitalSignatureManager, error) {
	return f.manager, nil
}

// TestGenerateAddressReportsAKeyPolicyRefusalAsAPreconditionFailure follows eth_generateAccount's use
// case to the error class its caller sees, which JSON-RPC maps to -32097.
func TestGenerateAddressReportsAKeyPolicyRefusalAsAPreconditionFailure(t *testing.T) {
	pinResolver, err := signaturemanagertesthelper.NewPinResolver()
	require.NoError(t, err)
	refusal := signaturemanager.NewPolicyRefusedError().WithMessage("the token generated the private key with CKA_SENSITIVE false")
	connector, err := hsmconnector.ProvideDefaultHSMConnector(hsmconnector.DefaultUseCaseOptions{
		DigitalSignatureManagerFactory: fixedFactory{manager: refusingManager{err: refusal}},
		PinResolver:                    pinResolver,
	})
	require.NoError(t, err)

	_, genErr := connector.GenerateAddress(context.Background(), hsmconnector.GenerateAddressInput{
		SlotConnectionData: hsmconnector.SlotConnectionData{Slot: "1", ModuleKind: hsmconnector.AKVModuleKind},
	})
	require.Error(t, genErr)
	require.True(t, errors.IsPreconditionFailed(genErr), genErr.Error())
	require.Contains(t, genErr.Error(), "CKA_SENSITIVE false")
}
