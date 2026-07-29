package address_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
)

var (
	validAddrString = "970e8128ab834e8eac17ab8e3812f010678cf791"

	expectedAddressEIP55 = "0x970E8128AB834E8EAC17Ab8E3812F010678CF791"
	zeroAddressString    = "0x0000000000000000000000000000000000000000"
)

func TestNewFromHexString(t *testing.T) {
	var err error
	var got address.Address

	t.Run("invalid addresses", func(t *testing.T) {
		got, err = address.NewFromHexString("invalid address format")
		require.Error(t, err)
		require.Equal(t, address.ZeroAddress, got)
		require.Equal(t, zeroAddressString, got.String())

		// valid length, invalid hex characters
		got, err = address.NewFromHexString("0xz70z8128zb834e8enc17az8e3812k010678zf791")
		require.Error(t, err)
		require.Equal(t, address.ZeroAddress, got)
		require.Equal(t, zeroAddressString, got.String())
		got, err = address.NewFromHexString("z70z8128zb834e8enc17az8e3812k010678zf791")
		require.Error(t, err)
		require.Equal(t, address.ZeroAddress, got)
		require.Equal(t, zeroAddressString, got.String())

		got, err = address.NewFromHexString("")
		require.Error(t, err)
		require.Equal(t, address.ZeroAddress, got)
		require.Equal(t, zeroAddressString, got.String())
	})

	t.Run("valid addresses", func(t *testing.T) {
		got, err = address.NewFromHexString(validAddrString)
		require.NoError(t, err)
		require.Equal(t, expectedAddressEIP55, got.String())

		got, err = address.NewFromHexString("0x" + validAddrString)
		require.NoError(t, err)
		require.Equal(t, expectedAddressEIP55, got.String())

		got, err = address.NewFromHexString("0X" + validAddrString)
		require.NoError(t, err)
		require.Equal(t, expectedAddressEIP55, got.String())
	})
}

func TestNewFromHexStringChecksum(t *testing.T) {
	t.Run("accepts non-checksummed addresses", func(t *testing.T) {
		// All-lowercase and all-uppercase carry no checksum information and are accepted as-is.
		for _, in := range []string{
			validAddrString,
			"0x" + validAddrString,
			"0X" + validAddrString,
			strings.ToUpper(validAddrString),
			"0x" + strings.ToUpper(validAddrString),
		} {
			got, err := address.NewFromHexStringChecksum(in)
			require.NoError(t, err, "input %q", in)
			require.Equal(t, expectedAddressEIP55, got.String())
		}
	})

	t.Run("accepts a correctly checksummed mixed-case address", func(t *testing.T) {
		got, err := address.NewFromHexStringChecksum(expectedAddressEIP55)
		require.NoError(t, err)
		require.Equal(t, expectedAddressEIP55, got.String())
	})

	t.Run("rejects a mixed-case address with a bad checksum", func(t *testing.T) {
		// expectedAddressEIP55 has '970E...'; flipping that 'E' to lowercase breaks the checksum while
		// keeping the string mixed-case, so the checksum is verified and must fail.
		badChecksum := "0x970e8128AB834E8EAC17Ab8E3812F010678CF791"
		got, err := address.NewFromHexStringChecksum(badChecksum)
		require.Error(t, err)
		require.Equal(t, address.ZeroAddress, got)
	})

	t.Run("rejects invalid hex", func(t *testing.T) {
		got, err := address.NewFromHexStringChecksum("invalid address format")
		require.Error(t, err)
		require.Equal(t, address.ZeroAddress, got)
	})
}
