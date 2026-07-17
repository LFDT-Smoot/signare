package signaturemanager_test

import (
	"math/big"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"

	curves "github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// TestDeriveAddressFromPublicKey_RejectsMalformedInput guards the shared derivation
// chokepoint: a valid 0x04-prefixed 65-byte key derives, while malformed inputs that would
// otherwise panic (empty) or silently drop a byte (bare 64-byte X||Y) are rejected.
func TestDeriveAddressFromPublicKey_RejectsMalformedInput(t *testing.T) {
	_, pub := curves.PrivKeyFromBytes(big.NewInt(1).FillBytes(make([]byte, 32)))
	valid := pub.SerializeUncompressed()

	addr, err := signaturemanager.DeriveAddressFromPublicKey(valid)
	require.NoError(t, err)
	require.NotNil(t, addr)

	t.Run("empty input", func(t *testing.T) {
		_, err := signaturemanager.DeriveAddressFromPublicKey(nil)
		require.Error(t, err)
		require.True(t, signaturemanager.IsInvalidArgumentError(err))
	})
	t.Run("bare 64-byte X||Y without prefix", func(t *testing.T) {
		_, err := signaturemanager.DeriveAddressFromPublicKey(valid[1:])
		require.Error(t, err)
		require.True(t, signaturemanager.IsInvalidArgumentError(err))
	})
	t.Run("wrong prefix byte", func(t *testing.T) {
		bad := append([]byte{}, valid...)
		bad[0] = 0x03
		_, err := signaturemanager.DeriveAddressFromPublicKey(bad)
		require.Error(t, err)
		require.True(t, signaturemanager.IsInvalidArgumentError(err))
	})
}
