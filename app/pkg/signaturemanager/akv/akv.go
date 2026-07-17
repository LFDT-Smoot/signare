package akv

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
)

const (
	standard = "AKV"
)

// AKVSignatureManager implements the DigitalSignatureManager interface.
type AKVSignatureManager struct {
	akvClient *azkeys.Client
}

// AVSignatureManagerOptions defines options to create a new instance of AKVSignatureManager.
type AVSignatureManagerOptions struct {
	AKVVaultURL string
}

var _ signaturemanager.DigitalSignatureManager = (*AKVSignatureManager)(nil)

// ProvideAKVSignatureManager creates a new instance of AKVSignatureManager using the provided options, returning an error if it fails.
func ProvideAKVSignatureManager(options AVSignatureManagerOptions) (*AKVSignatureManager, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	azKeysClient, err := azkeys.NewClient(options.AKVVaultURL, cred, nil)
	if err != nil {
		return nil, err
	}
	return &AKVSignatureManager{
		akvClient: azKeysClient,
	}, nil
}

func (s *AKVSignatureManager) GenerateKey(_ context.Context, _ signaturemanager.GenerateKeyInput) (*signaturemanager.GenerateKeyOutput, error) {
	return nil, signaturemanager.NewNotImplementedError()
}

func (s *AKVSignatureManager) DeriveAddressFromPrivateKey(_ context.Context, _ signaturemanager.DeriveAddressFromPrivateKeyInput) (*signaturemanager.DeriveAddressFromPrivateKeyOutput, error) {
	return nil, signaturemanager.NewNotImplementedError()
}

func (s *AKVSignatureManager) RemoveKey(_ context.Context, _ signaturemanager.RemoveKeyInput) (*signaturemanager.RemoveKeyOutput, error) {
	return nil, signaturemanager.NewNotImplementedError()
}

func (s *AKVSignatureManager) ListKeys(_ context.Context, _ signaturemanager.ListKeysInput) (*signaturemanager.ListKeysOutput, error) {
	return nil, signaturemanager.NewNotImplementedError()
}

func (s *AKVSignatureManager) Sign(ctx context.Context, input signaturemanager.SignInput) (*signaturemanager.SignOutput, error) {
	tracer := input.Tracer
	from := input.From.String()
	tracer.AddProperty("address", from)
	tracer.AddProperty("standard", standard)
	tracer.Debug("signing transaction")

	var name string
	var version string
	for _, inputConfig := range input.Config.AKV {
		if inputConfig.KeyPublicAddress == from {
			name = inputConfig.KeyName
			version = inputConfig.KeyVersion
		}
	}
	if len(name) == 0 || len(version) == 0 {
		return nil, signaturemanager.NewInternalError().WithMessage("cannot obtain key to sign")
	}

	tracer.AddProperty("name", name)
	tracer.AddProperty("version", version)

	es256 := azkeys.SignatureAlgorithmES256K
	parameters := azkeys.SignParameters{
		Algorithm: &es256,
		Value:     input.Data[:],
	}
	sig, err := s.akvClient.Sign(ctx, name, version, parameters, &azkeys.SignOptions{})
	if err != nil {
		return nil, signaturemanager.NewInternalError().WithMessage(fmt.Sprintf("error signing data: %v", err))
	}
	return &signaturemanager.SignOutput{
		Signature: sig.Result,
	}, nil
}

func (s *AKVSignatureManager) Close(_ context.Context, _ signaturemanager.CloseInput) (*signaturemanager.CloseOutput, error) {
	return &signaturemanager.CloseOutput{}, nil
}

func (s *AKVSignatureManager) Open(_ context.Context, _ signaturemanager.OpenInput) (*signaturemanager.OpenOutput, error) {
	return &signaturemanager.OpenOutput{}, nil
}

func (s *AKVSignatureManager) IsAlive(_ context.Context, _ signaturemanager.IsAliveInput) (*signaturemanager.IsAliveOutput, error) {
	return &signaturemanager.IsAliveOutput{
		IsAlive: true,
	}, nil
}
