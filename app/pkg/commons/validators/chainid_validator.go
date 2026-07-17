package validators

import (
	"github.com/asaskevich/govalidator"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
)

// setChainIDValidator registers the "chainID" validator, which accepts a chain ID that is a valid
// EIP-155 value (>= 1) and rejects zero and negative values. It is the single source of truth for
// that rule across both the decimal (entities.Int256, application config) and hex
// (entities.HexInt256, signing path) representations.
//
// Note for value-typed (non-pointer) fields: govalidator treats a zero value as "empty" and skips
// custom validators for it, so this validator never sees a 0 and cannot reject it on its own. Pair
// it with `required` (e.g. `valid:"required,chainID"`) to reject 0; this validator then rejects the
// remaining invalid (negative) values. Pointer and hex fields are passed in even when zero, so for
// those the validator rejects 0 directly; a nil pointer means "not set" and is left to other
// validators (e.g. an edit that leaves the chain ID unchanged).
func setChainIDValidator() {
	govalidator.CustomTypeTagMap.Set("chainID", func(i any, _ any) bool {
		switch v := i.(type) {
		case entities.Int256:
			return v.Sign() >= 1
		case *entities.Int256:
			return v == nil || v.Sign() >= 1
		case entities.HexInt256:
			return v.Sign() >= 1
		case *entities.HexInt256:
			return v == nil || v.Sign() >= 1
		default:
			return false
		}
	})
}
