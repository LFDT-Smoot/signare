package hsmconnector

import (
	"context"
	"os"

	signererrors "github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager/akv"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager/localkeyvault"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager/pkcs11hsm"

	"github.com/miekg/pkcs11"
)

// DigitalSignatureManagerFactory defines the factory to create DigitalSignatureManager connections.
type DigitalSignatureManagerFactory interface {
	// Create returns the connection to a DigitalSignatureManager.
	Create(ctx context.Context, input CreateInput) (signaturemanager.DigitalSignatureManager, error)
	// Close closes open resources to the digital signature manager.
	Close(ctx context.Context, input CloseInput) (*CloseOutput, error)
	// Reset the snapshot of a given module kind to include slots created after the initialization.
	Reset(_ context.Context, kind ModuleKind) error
}

func (u *DefaultDigitalSignatureManagerFactory) Reset(ctx context.Context, kind ModuleKind) error {
	digitalSignatureManager, ok := u.digitalSignatureManagerMap[kind]
	if !ok {
		return signererrors.InvalidArgument().WithMessage("error during reset of the digital signature manager: the HSM type '%s' is not supported", kind)
	}
	_, closeErr := digitalSignatureManager.Close(ctx, signaturemanager.CloseInput{})
	if closeErr != nil {
		return signererrors.Internal().WithMessage("error closing digital signature manager connection '%s'. Error: %v", kind, closeErr)
	}
	_, openErr := digitalSignatureManager.Open(ctx, signaturemanager.OpenInput{})
	if openErr != nil {
		return signererrors.Internal().WithMessage("error opening digital signature manager connection '%s'. Error: %v", kind, openErr)
	}

	// Deliberately no write back into the map here: see the field comment on digitalSignatureManagerMap.
	return nil
}

func (u *DefaultDigitalSignatureManagerFactory) Create(ctx context.Context, input CreateInput) (signaturemanager.DigitalSignatureManager, error) {
	digitalSignatureManager, ok := u.digitalSignatureManagerMap[input.ModuleKind]
	if !ok {
		return nil, signererrors.InvalidArgument().WithMessage("the provided module kind '%s' is not supported", input.ModuleKind)
	}

	_, openErr := digitalSignatureManager.Open(ctx, signaturemanager.OpenInput{})
	if openErr != nil && !signaturemanager.IsAlreadyInitializedErr(openErr) {
		return nil, signererrors.Internal().WithMessage("failed to open digital signature manager '%s'. Error: %v", input.ModuleKind, openErr)
	}

	return digitalSignatureManager, nil
}

func (u *DefaultDigitalSignatureManagerFactory) Close(ctx context.Context, _ CloseInput) (*CloseOutput, error) {
	for key, digitalSignatureManager := range u.digitalSignatureManagerMap {
		_, err := digitalSignatureManager.Close(ctx, signaturemanager.CloseInput{})
		if err != nil {
			return nil, signererrors.InternalFromErr(err).WithMessage("error closing digital signature manager: '%s'. Error: %v", key, err)
		}
	}
	return &CloseOutput{}, nil
}

var _ DigitalSignatureManagerFactory = new(DefaultDigitalSignatureManagerFactory)

// DefaultDigitalSignatureManagerFactory implements DigitalSignatureManagerFactory to create PKCS11 digital signature
// manager compatible instances.
// It Initializes the pkcs11 library at creation time so that there is one pkcs11.Ctx per digital signature manager supported type.
type DefaultDigitalSignatureManagerFactory struct {
	// digitalSignatureManagerMap is populated once at construction and never written afterwards.
	// It is read by Create on every signing request, concurrently with admin requests reaching Reset,
	// and there is no lock: a write here would be a concurrent map access, which the Go runtime treats
	// as a fatal error that recover cannot intercept, taking the whole signer down. Keep it read-only.
	digitalSignatureManagerMap map[ModuleKind]signaturemanager.DigitalSignatureManager
}

// DefaultDigitalSignatureManagerFactoryOptions options to create a new DigitalSignatureManagerFactory instance.
type DefaultDigitalSignatureManagerFactoryOptions struct {
	// SoftHSMLibrary path to the library to connect to a PKCS11 compatible HSM.
	SoftHSMLibrary *PKCS11Library
	AKVVaultURL    *string
}

// ProvideDefaultDigitalSignatureManagerFactory creates a new DigitalSignatureManagerFactory with the given options.
func ProvideDefaultDigitalSignatureManagerFactory(options DefaultDigitalSignatureManagerFactoryOptions) (*DefaultDigitalSignatureManagerFactory, error) {
	digitalSignatureManagerMap := make(map[ModuleKind]signaturemanager.DigitalSignatureManager)
	if options.SoftHSMLibrary != nil {
		_, err := os.Stat(string(*options.SoftHSMLibrary))
		if os.IsNotExist(err) {
			return nil, signererrors.InvalidArgument().WithMessage("SoftHSM library path does not exist")
		}
		pkcs11Context := pkcs11.New(string(*options.SoftHSMLibrary))
		if pkcs11Context == nil {
			return nil, signererrors.Internal().WithMessage("error instantiating the PKCS11 interface for '%s'", SoftHSMModuleKind)
		}
		errInitialize := pkcs11Context.Initialize()
		if errInitialize != nil {
			return nil, signererrors.Internal().WithMessage("error calling the PKCS11 interface initialize function for '%s'. Error: %v", SoftHSMModuleKind, errInitialize)
		}
		pkcs11HSMSignatureManagerOptions := pkcs11hsm.PKCS11HSMSignatureManagerOptions{
			PkcsContext: pkcs11Context,
		}
		signatureManager, err := pkcs11hsm.ProvidePKCS11HSMSignatureManager(pkcs11HSMSignatureManagerOptions)
		if err != nil {
			return nil, signererrors.InternalFromErr(err)
		}
		digitalSignatureManagerMap[SoftHSMModuleKind] = signatureManager
	}
	if options.AKVVaultURL != nil {
		signatureManager, err := akv.ProvideAKVSignatureManager(akv.AVSignatureManagerOptions{
			AKVVaultURL: *options.AKVVaultURL,
		})
		if err != nil {
			return nil, signererrors.InternalFromErr(err)
		}
		digitalSignatureManagerMap[AKVModuleKind] = signatureManager
	}

	lkvSignatureManager := localkeyvault.ProvideLKVSignatureManager(localkeyvault.LKVSignatureManagerOptions{})
	digitalSignatureManagerMap[LKVModuleKind] = lkvSignatureManager

	if len(digitalSignatureManagerMap) == 0 {
		return nil, signererrors.InvalidArgument().WithMessage("no HSM libraries were provided. At least one is required")
	}

	return &DefaultDigitalSignatureManagerFactory{
		digitalSignatureManagerMap: digitalSignatureManagerMap,
	}, nil
}
