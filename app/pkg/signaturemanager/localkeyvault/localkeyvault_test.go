package localkeyvault_test

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	signererrors "github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager/localkeyvault"

	curves "github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// privateKeyFromInt returns d as a fixed-width 32-byte big-endian private key.
func privateKeyFromInt(d *big.Int) entities.HexBytes {
	return entities.HexBytes(d.FillBytes(make([]byte, 32)))
}

func deriveAddress(t *testing.T, priv entities.HexBytes) (string, error) {
	t.Helper()
	sm := localkeyvault.ProvideLKVSignatureManager(localkeyvault.LKVSignatureManagerOptions{})
	out, err := sm.DeriveAddressFromPrivateKey(context.Background(), signaturemanager.DeriveAddressFromPrivateKeyInput{
		PrivateKey: priv,
	})
	if err != nil {
		return "", err
	}
	return out.Address.String(), nil
}

// addressFromCoordinates hashes the given X||Y bytes the same way the manager does and
// returns the resulting EIP-55 address string.
func addressFromCoordinates(t *testing.T, xy []byte) string {
	t.Helper()
	hash, err := entities.HashKeccak256(xy)
	require.NoError(t, err)
	addr, err := address.NewFromRawBytes(hash.Bytes()[12:])
	require.NoError(t, err)
	return addr.String()
}

// TestDeriveAddressFromPrivateKey_KnownAnswerVectors checks LKV against published
// secp256k1 -> Ethereum address vectors, with no go-ethereum dependency.
func TestDeriveAddressFromPrivateKey_KnownAnswerVectors(t *testing.T) {
	vectors := []struct {
		d        int64
		expected string
	}{
		{1, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"},
		{2, "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF"},
		{3, "0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69"},
	}
	for _, v := range vectors {
		t.Run(fmt.Sprintf("d=%d", v.d), func(t *testing.T) {
			got, err := deriveAddress(t, privateKeyFromInt(big.NewInt(v.d)))
			require.NoError(t, err)
			require.Equal(t, v.expected, got)
		})
	}
}

// TestDeriveAddressFromPrivateKey_LeadingZeroCoordinate is the CRY-1 regression guard: a
// key whose public-key X or Y coordinate has a zero top byte must still derive the correct
// fixed-width address, not the pre-fix big.Int.Bytes() concatenation.
func TestDeriveAddressFromPrivateKey_LeadingZeroCoordinate(t *testing.T) {
	priv, x, y := findLeadingZeroCoordinateKey(t)

	// Correct: each coordinate left-padded to 32 bytes.
	correct := addressFromCoordinates(t, append(x.FillBytes(make([]byte, 32)), y.FillBytes(make([]byte, 32))...))
	// Pre-fix bug: big.Int.Bytes() strips the leading zero byte, shortening and misaligning X||Y.
	buggy := addressFromCoordinates(t, append(append([]byte{}, x.Bytes()...), y.Bytes()...))
	require.NotEqual(t, correct, buggy, "vector must actually exercise the leading-zero bug")

	got, err := deriveAddress(t, priv)
	require.NoError(t, err)
	require.Equal(t, correct, got, "LKV must derive the fixed-width address")
	require.NotEqual(t, buggy, got, "LKV must not reproduce the pre-fix address")
}

// TestDeriveAddressFromPrivateKey_MatchesSharedHelperPath asserts LKV derives the same
// address as DeriveAddressFromPublicKey(pub.SerializeUncompressed()), the exact call the
// PKCS#11 backend makes. A live HSM session cannot run in a unit test, so this mirrors the
// PKCS#11 derivation path rather than standing up PKCS#11.
func TestDeriveAddressFromPrivateKey_MatchesSharedHelperPath(t *testing.T) {
	for _, d := range []int64{1, 7, 12345, 999983} {
		t.Run(fmt.Sprintf("d=%d", d), func(t *testing.T) {
			priv := privateKeyFromInt(big.NewInt(d))
			_, pub := curves.PrivKeyFromBytes(priv)
			expected, err := signaturemanager.DeriveAddressFromPublicKey(pub.SerializeUncompressed())
			require.NoError(t, err)

			got, err := deriveAddress(t, priv)
			require.NoError(t, err)
			require.Equal(t, expected.String(), got)
		})
	}
}

// TestDeriveAddressFromPrivateKey_Rejections checks scalar-range and length validation. In
// particular D >= N must be rejected, not silently reduced mod N by btcec.
func TestDeriveAddressFromPrivateKey_Rejections(t *testing.T) {
	n := curves.S256().Params().N

	t.Run("D equal to N is rejected", func(t *testing.T) {
		_, err := deriveAddress(t, privateKeyFromInt(new(big.Int).Set(n)))
		require.Error(t, err)
		require.True(t, signererrors.IsInternal(err))
	})
	t.Run("D greater than N is rejected", func(t *testing.T) {
		_, err := deriveAddress(t, privateKeyFromInt(new(big.Int).Add(n, big.NewInt(1))))
		require.Error(t, err)
		require.True(t, signererrors.IsInternal(err))
	})
	t.Run("D of zero is rejected", func(t *testing.T) {
		_, err := deriveAddress(t, entities.HexBytes(make([]byte, 32)))
		require.Error(t, err)
		require.True(t, signererrors.IsInternal(err))
	})
	t.Run("wrong length is rejected", func(t *testing.T) {
		_, err := deriveAddress(t, entities.HexBytes(make([]byte, 31)))
		require.Error(t, err)
		require.True(t, signaturemanager.IsInvalidArgumentError(err))
	})
}

// findLeadingZeroCoordinateKey scans d = 1, 2, 3, ... for a private key whose public-key X
// or Y coordinate has a zero most-significant byte (about 1 in 128 keys).
func findLeadingZeroCoordinateKey(t *testing.T) (entities.HexBytes, *big.Int, *big.Int) {
	t.Helper()
	curve := curves.S256()
	for i := int64(1); i < 100000; i++ {
		priv := big.NewInt(i).FillBytes(make([]byte, 32))
		x, y := curve.ScalarBaseMult(priv)
		if len(x.Bytes()) < 32 || len(y.Bytes()) < 32 {
			return entities.HexBytes(priv), x, y
		}
	}
	t.Fatal("no leading-zero coordinate key found in scan range")
	return nil, nil, nil
}
