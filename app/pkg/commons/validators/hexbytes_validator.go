package validators

import (
	"github.com/asaskevich/govalidator"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
)

func setHexBytesValidator() {
	govalidator.CustomTypeTagMap.Set("hexBytes", func(i any, _ any) bool {
		hexBytes, ok := i.(entities.HexBytes)
		if !ok {
			return false
		}
		if hexBytes.String() == "" || hexBytes.String() == "0x" {
			return false
		}
		return true
	})
}
