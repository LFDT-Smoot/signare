package validators

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/entities"

	"github.com/asaskevich/govalidator"
)

// createChainIDField mirrors CreateApplicationInput.ChainID: a value type that must be present and
// a valid EIP-155 chain ID. `required` rejects the zero value (which govalidator treats as empty and
// never passes to the custom validator); `chainID` rejects non-positive non-zero values.
type createChainIDField struct {
	ChainID entities.Int256 `valid:"required,chainID"`
}

// editChainIDField mirrors EditApplicationInput.ChainID: an optional pointer. A nil pointer means the
// chain ID is not being edited and is accepted; a non-nil pointer must be a valid EIP-155 chain ID.
type editChainIDField struct {
	ChainID *entities.Int256 `valid:"chainID"`
}

// hexChainIDField mirrors a signing-layer hex chain ID (entities.HexInt256). It guards against the
// fail-closed trap where the validator only matched the decimal representation and rejected every
// valid hex chain ID by falling through to the default case.
type hexChainIDField struct {
	ChainID *entities.HexInt256 `valid:"chainID"`
}

type anyChainIDField struct {
	ChainID any `valid:"chainID"`
}

func TestChainIDValidator(t *testing.T) {
	setChainIDValidator()

	tests := []struct {
		name string
		have any
		want bool
	}{
		{
			name: "value: chainID 1 is valid",
			have: createChainIDField{ChainID: *entities.NewInt256FromInt(1)},
			want: true,
		},
		{
			name: "value: large positive chainID is valid",
			have: createChainIDField{ChainID: *entities.NewInt256FromInt(44844)},
			want: true,
		},
		{
			name: "value: chainID 0 is rejected",
			have: createChainIDField{ChainID: *entities.NewInt256FromInt(0)},
			want: false,
		},
		{
			name: "value: negative chainID is rejected",
			have: createChainIDField{ChainID: *entities.NewInt256FromInt(-1)},
			want: false,
		},
		{
			name: "pointer: nil chainID is valid (not edited)",
			have: editChainIDField{ChainID: nil},
			want: true,
		},
		{
			name: "pointer: chainID 1 is valid",
			have: editChainIDField{ChainID: entities.NewInt256FromInt(1)},
			want: true,
		},
		{
			name: "pointer: chainID 0 is rejected",
			have: editChainIDField{ChainID: entities.NewInt256FromInt(0)},
			want: false,
		},
		{
			name: "pointer: negative chainID is rejected",
			have: editChainIDField{ChainID: entities.NewInt256FromInt(-1)},
			want: false,
		},
		{
			name: "hex pointer: chainID 1 is valid",
			have: hexChainIDField{ChainID: entities.NewHexInt256(big.NewInt(1))},
			want: true,
		},
		{
			name: "hex pointer: chainID 0 is rejected",
			have: hexChainIDField{ChainID: entities.NewHexInt256(big.NewInt(0))},
			want: false,
		},
		{
			name: "hex pointer: nil chainID is valid (not set)",
			have: hexChainIDField{ChainID: nil},
			want: true,
		},
		{
			name: "wrong type is rejected",
			have: anyChainIDField{ChainID: "1"},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ok, _ := govalidator.ValidateStruct(tt.have)
			require.Equal(t, tt.want, ok)
		})
	}
}
