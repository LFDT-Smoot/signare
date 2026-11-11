package pkcs11hsm

import (
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"

	"github.com/miekg/pkcs11"
)

type Curve string

const (
	CurveDefault   Curve = "secp256k1"
	CurveSecp256k1 Curve = "secp256k1"
)

// pkcsErrTranslator maps PKCS#11 return codes onto signature manager errors. The values are shared
// across every request that hits a given code, so they must be treated as immutable: see
// signaturemanager.Error.WithMessage, which returns a copy rather than mutating the receiver.
//
// The persistence layer has the same shape, a dialect error map holding shared *persistence.Error
// values, and its WithMessage still mutates. It is deliberately left alone here: no caller there
// chains WithMessage onto a translated error, so it is latent rather than live, and its TranslateError
// hands out the shared instance directly, so copying at WithMessage alone would not fully de-share it.
// Fixing it belongs with that layer rather than in this change.
var pkcsErrTranslator = map[pkcs11.Error]*signaturemanager.Error{
	pkcs11.CKR_SLOT_ID_INVALID:              signaturemanager.NewInvalidSlotError(),
	pkcs11.CKR_PIN_INCORRECT:                signaturemanager.NewPinIncorrectError(),
	pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED: signaturemanager.NewAlreadyInitializedError(),
}

// PKCS11HSMConnectionDetails configuration to connect to a specific slot in a softHSM instance.
type PKCS11HSMConnectionDetails struct {
	// Configuration configuration to connect to a softHSM instance.
	Configuration PKCS11HSMConfiguration
}

// PKCS11HSMConfiguration configuration to connect to a softHSM instance.
type PKCS11HSMConfiguration struct {
	Curve Curve
}
