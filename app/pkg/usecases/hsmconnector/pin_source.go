package hsmconnector

import (
	"context"
	"fmt"
	"strings"

	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
)

// PinResolver obtains the PIN that a slot's source names. Implementations must not cache: login happens
// per operation, which is what lets a rotated secret take effect without a restart.
type PinResolver interface {
	// Resolve returns the PIN held by the named source, or an error if it cannot be read.
	Resolve(ctx context.Context, source string) (string, error)
}

// maxPinSourceLength bounds a source name to the width of the pin_source column.
const maxPinSourceLength = 256

// slotPin is the PIN for one operation and the breaker key it is judged under. guarded is false for
// module kinds that do not log in with a PIN.
type slotPin struct {
	value   string
	key     pinBreakerKey
	guarded bool
}

// pinFor resolves the PIN for one operation, and refuses to attempt a login while the breaker is open
// against that value. Every login path goes through here, so a PIN lives only for the length of one
// call and never reaches a struct that is logged or serialised.
func (d *DefaultUseCase) pinFor(ctx context.Context, moduleKind ModuleKind, slot string, source string, legacy string) (*slotPin, error) {
	if moduleKind != SoftHSMModuleKind {
		return &slotPin{}, nil
	}

	resolved := slotPin{
		key:     pinBreakerKey{moduleKind: moduleKind, slot: slot},
		guarded: true,
	}

	switch {
	case len(source) > 0:
		if err := ValidatePinSource(source); err != nil {
			return nil, err
		}
		value, err := d.pinResolver.Resolve(ctx, source)
		if err != nil {
			return nil, err
		}
		resolved.value = value
	case len(legacy) > 0:
		// Stored before pin_source existed. Kept for one release so a deployment can upgrade the binary
		// before moving its secrets.
		resolved.value = legacy
	default:
		msg := fmt.Sprintf("slot '%s' has no pin source configured", slot)
		return nil, errors.PreconditionFailed().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
	}

	if d.breaker.blocked(resolved.key, resolved.value) {
		msg := fmt.Sprintf("slot '%s' is not being retried: its PIN was refused by the HSM. Correct the secret it names, then verify the pin source", slot)
		return nil, errors.PreconditionFailed().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
	}

	return &resolved, nil
}

// pinIncorrectError reports a refused PIN as a precondition failure, which the caller can act on,
// rather than an opaque internal error.
func pinIncorrectError(err error, slot string) error {
	msg := fmt.Sprintf("the pin provided for the slot '%s' is not correct", slot)
	return errors.PreconditionFailedFromErr(err).WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
}

// recordLoginOutcome opens the breaker on a refused PIN and closes it on any other outcome. Anything
// else says nothing about the PIN, so it must not leave a breaker open.
func (d *DefaultUseCase) recordLoginOutcome(pin *slotPin, err error) {
	if pin == nil || !pin.guarded {
		return
	}
	if err != nil && signaturemanager.IsPinIncorrectError(err) {
		d.breaker.trip(pin.key, pin.value)
		return
	}
	d.breaker.clear(pin.key)
}

// ValidatePinSource enforces that a PIN source is a single name, not a path. The name is resolved under
// a directory fixed in configuration; a path would let an administrator aim a slot at the database
// password and have the process hand it to the PKCS#11 library. Checked before storing and before
// reading.
func ValidatePinSource(source string) error {
	if len(source) == 0 {
		return errors.InvalidArgument().WithMessage("pin source cannot be empty")
	}
	if len(source) > maxPinSourceLength {
		return errors.InvalidArgument().WithMessage("pin source cannot be longer than %d characters", maxPinSourceLength)
	}
	if strings.ContainsAny(source, `/\`) {
		return errors.InvalidArgument().WithMessage("pin source must be a single name, not a path")
	}
	// Also catches "..data", the directory a Kubernetes secret projection mounts beside the keys.
	if source == "." || strings.HasPrefix(source, "..") {
		return errors.InvalidArgument().WithMessage("pin source cannot be '.' or start with '..'")
	}
	for _, r := range source {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return errors.InvalidArgument().WithMessage("pin source may only contain letters, digits, '.', '_' and '-'")
		}
	}
	return nil
}
