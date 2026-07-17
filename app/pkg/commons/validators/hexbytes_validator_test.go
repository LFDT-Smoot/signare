package validators

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/entities"

	"github.com/asaskevich/govalidator"
)

type RequiredHexBytesTestType struct {
	HexBytes any `valid:"hexBytes"`
}

func TestRequiredHexBytesValidator(t *testing.T) {
	setHexBytesValidator()
	validHexBytes, err := entities.NewHexBytesFromString("b10b000391cbd4b286665c7ae19ca0c058aef0152ca0ade120b716879b5eec90")
	require.NoError(t, err)

	tests := []struct {
		name string
		have RequiredHexBytesTestType
		want bool
	}{
		{
			name: "valid hexBytes",
			have: RequiredHexBytesTestType{
				HexBytes: validHexBytes,
			},
			want: true,
		},
		{
			name: "empty hexBytes",
			have: RequiredHexBytesTestType{
				HexBytes: entities.NewHexBytes([]byte("")),
			},
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
