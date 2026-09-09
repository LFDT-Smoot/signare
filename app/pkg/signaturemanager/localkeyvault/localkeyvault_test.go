package localkeyvault_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	signererrors "github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager/localkeyvault"

	curves "github.com/btcsuite/btcd/btcec/v2"
	btcececdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
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

// signWith signs data with the given key, wired through a slot configuration whose key
// store maps the key's own derived address to it, the way a configured LKV slot does.
func signWith(t *testing.T, priv entities.HexBytes, data entities.HexBytes) ([]byte, address.Address, error) {
	t.Helper()
	_, pub := curves.PrivKeyFromBytes(priv)
	from, err := signaturemanager.DeriveAddressFromPublicKey(pub.SerializeUncompressed())
	require.NoError(t, err)

	sm := localkeyvault.ProvideLKVSignatureManager(localkeyvault.LKVSignatureManagerOptions{})
	out, err := sm.Sign(context.Background(), signaturemanager.SignInput{
		Config: signaturemanager.SlotConfig{
			LocalKeyVault: &signaturemanager.LocalKeyVaultConfig{
				KeyStore: map[address.Address]string{*from: priv.String()},
			},
		},
		From: *from,
		Data: data,
	})
	if err != nil {
		return nil, *from, err
	}
	return out.Signature, *from, nil
}

// TestSign_VerifiesUnderDerivedPublicKey is the core round trip: the emitted r||s must
// verify against the public key derived from the same private key.
func TestSign_VerifiesUnderDerivedPublicKey(t *testing.T) {
	for _, d := range []int64{1, 7, 12345, 999983} {
		t.Run(fmt.Sprintf("d=%d", d), func(t *testing.T) {
			priv := privateKeyFromInt(big.NewInt(d))
			digest := digestOf(t, fmt.Sprintf("payload-%d", d))

			sig, _, err := signWith(t, priv, digest)
			require.NoError(t, err)
			require.Len(t, sig, 64, "signature must be fixed-width r||s")

			_, pub := curves.PrivKeyFromBytes(priv)
			require.True(t, parseRS(t, sig).Verify(digest, pub))
		})
	}
}

// TestSign_RecoversToSigningAddress mirrors the connector's assembleRecoverableSignature
// path: prepend a recovery byte, and one of 27/28 must recover the signing address. This
// is what makes an LKV signature usable as an Ethereum signature.
func TestSign_RecoversToSigningAddress(t *testing.T) {
	priv := privateKeyFromInt(big.NewInt(4242))
	digest := digestOf(t, "recover me")

	sig, from, err := signWith(t, priv, digest)
	require.NoError(t, err)

	var recovered string
	for v := byte(27); v <= 28; v++ {
		compact := append([]byte{v}, sig...)
		pub, _, recoverErr := btcececdsa.RecoverCompact(compact, digest)
		if recoverErr != nil {
			continue
		}
		addr, deriveErr := signaturemanager.DeriveAddressFromPublicKey(pub.SerializeUncompressed())
		require.NoError(t, deriveErr)
		if addr.String() == from.String() {
			recovered = addr.String()
			break
		}
	}
	require.Equal(t, from.String(), recovered, "no recovery byte recovered the signing address")
}

// TestSign_MatchesPublishedRFC6979Vector pins the emitted bytes against a published
// RFC 6979 secp256k1 vector (private key 1, SHA-256 of "Satoshi Nakamoto"), rather than
// against a value this implementation recorded for itself. Determinism alone only proves
// two calls in one build agree; this proves the nonce derivation is the standard one, so
// a btcec change or a swap to a different deterministic scheme fails here.
func TestSign_MatchesPublishedRFC6979Vector(t *testing.T) {
	const (
		expectedR = "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
		expectedS = "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"
	)
	digest := sha256.Sum256([]byte("Satoshi Nakamoto"))

	sig, _, err := signWith(t, privateKeyFromInt(big.NewInt(1)), entities.HexBytes(digest[:]))
	require.NoError(t, err)
	require.Equal(t, expectedR+expectedS, hex.EncodeToString(sig))
}

// TestSign_IsDeterministic guards the RFC6979 nonce: signing the same digest with the
// same key twice must produce identical bytes. A randomised nonce would fail this.
func TestSign_IsDeterministic(t *testing.T) {
	priv := privateKeyFromInt(big.NewInt(31337))
	digest := digestOf(t, "same message")

	first, _, err := signWith(t, priv, digest)
	require.NoError(t, err)
	second, _, err := signWith(t, priv, digest)
	require.NoError(t, err)
	require.Equal(t, first, second)

	other, _, err := signWith(t, priv, digestOf(t, "different message"))
	require.NoError(t, err)
	require.NotEqual(t, first, other, "a different digest must produce a different signature")
}

// TestSign_ProducesLowS guards EIP-2 canonical form. The connector normalises S as well,
// but the backend must not be the thing relying on that.
func TestSign_ProducesLowS(t *testing.T) {
	for _, d := range []int64{1, 2, 3, 7, 4242, 999983} {
		t.Run(fmt.Sprintf("d=%d", d), func(t *testing.T) {
			sig, _, err := signWith(t, privateKeyFromInt(big.NewInt(d)), digestOf(t, fmt.Sprintf("low-s-%d", d)))
			require.NoError(t, err)

			s := new(big.Int).SetBytes(sig[32:])
			halfOrder := new(big.Int).Rsh(curves.S256().Params().N, 1)
			require.LessOrEqual(t, s.Cmp(halfOrder), 0, "S must be in the low half of the curve order")
		})
	}
}

// TestSign_FixedWidthComponents is the width guard: a signature whose R or S has a zero
// most-significant byte must still occupy its full 32 bytes, not be left-truncated.
func TestSign_FixedWidthComponents(t *testing.T) {
	priv, digest := findShortComponentSignature(t)

	sig, _, err := signWith(t, priv, digest)
	require.NoError(t, err)
	require.Len(t, sig, 64, "a short R or S must still be padded to 32 bytes")

	_, pub := curves.PrivKeyFromBytes(priv)
	require.True(t, parseRS(t, sig).Verify(digest, pub), "the padded signature must still verify")
}

// TestSign_Rejections covers the key-store lookup failures and the scalar-range guards.
func TestSign_Rejections(t *testing.T) {
	sm := localkeyvault.ProvideLKVSignatureManager(localkeyvault.LKVSignatureManagerOptions{})
	from, err := address.NewFromHexString("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
	require.NoError(t, err)
	digest := digestOf(t, "anything")

	signWithStore := func(store map[address.Address]string) error {
		var config signaturemanager.SlotConfig
		if store != nil {
			config.LocalKeyVault = &signaturemanager.LocalKeyVaultConfig{KeyStore: store}
		}
		_, signErr := sm.Sign(context.Background(), signaturemanager.SignInput{
			Config: config,
			From:   from,
			Data:   digest,
		})
		return signErr
	}

	n := curves.S256().Params().N

	t.Run("absent local key vault config is rejected", func(t *testing.T) {
		require.Error(t, signWithStore(nil))
	})
	t.Run("nil key store is rejected", func(t *testing.T) {
		err := signWithStore(map[address.Address]string(nil))
		require.Error(t, err)
	})
	t.Run("address missing from the key store is rejected", func(t *testing.T) {
		require.Error(t, signWithStore(map[address.Address]string{}))
	})
	t.Run("D equal to N is rejected", func(t *testing.T) {
		err := signWithStore(map[address.Address]string{from: privateKeyFromInt(new(big.Int).Set(n)).String()})
		require.Error(t, err)
		require.True(t, signererrors.IsInternal(err))
	})
	t.Run("D greater than N is rejected", func(t *testing.T) {
		err := signWithStore(map[address.Address]string{from: privateKeyFromInt(new(big.Int).Add(n, big.NewInt(1))).String()})
		require.Error(t, err)
		require.True(t, signererrors.IsInternal(err))
	})
	t.Run("D of zero is rejected", func(t *testing.T) {
		err := signWithStore(map[address.Address]string{from: entities.HexBytes(make([]byte, 32)).String()})
		require.Error(t, err)
		require.True(t, signererrors.IsInternal(err))
	})
	t.Run("wrong length is rejected", func(t *testing.T) {
		err := signWithStore(map[address.Address]string{from: entities.HexBytes(make([]byte, 31)).String()})
		require.Error(t, err)
		require.True(t, signererrors.IsInternal(err))
	})
	t.Run("malformed hex is rejected", func(t *testing.T) {
		err := signWithStore(map[address.Address]string{from: "0xnothexatall"})
		require.Error(t, err)
	})
}

// digestOf returns a 32-byte Keccak-256 digest, the shape the signing backends are handed.
func digestOf(t *testing.T, message string) entities.HexBytes {
	t.Helper()
	hash, err := entities.HashKeccak256([]byte(message))
	require.NoError(t, err)
	return entities.HexBytes(hash.Bytes())
}

// parseRS rebuilds a btcec signature from fixed-width r||s so it can be verified.
func parseRS(t *testing.T, sig []byte) *btcececdsa.Signature {
	t.Helper()
	require.Len(t, sig, 64)
	var r, s curves.ModNScalar
	require.False(t, r.SetByteSlice(sig[:32]), "R must not overflow the curve order")
	require.False(t, s.SetByteSlice(sig[32:]), "S must not overflow the curve order")
	return btcececdsa.NewSignature(&r, &s)
}

// findShortComponentSignature scans for a key and digest whose signature has an R or S
// with a zero most-significant byte (about 1 in 128), so the padding is actually exercised.
func findShortComponentSignature(t *testing.T) (entities.HexBytes, entities.HexBytes) {
	t.Helper()
	priv := privateKeyFromInt(big.NewInt(7))
	key, _ := curves.PrivKeyFromBytes(priv)
	for i := 0; i < 100000; i++ {
		digest := digestOf(t, fmt.Sprintf("short-component-%d", i))
		sig := btcececdsa.Sign(key, digest)
		r, s := sig.R(), sig.S()
		rBytes, sBytes := r.Bytes(), s.Bytes()
		if rBytes[0] == 0 || sBytes[0] == 0 {
			return priv, digest
		}
	}
	t.Fatal("no signature with a short R or S found in scan range")
	return nil, nil
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
