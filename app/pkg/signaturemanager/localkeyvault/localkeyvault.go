package localkeyvault

import (
	"context"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"

	curves "github.com/btcsuite/btcd/btcec/v2"
	btcececdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

const privateKeyLengthBytes = 32

// LKVSignatureManager implements the DigitalSignatureManager interface.
// DO NOT use a Local Key Vault in production environment.
type LKVSignatureManager struct {
}

// LKVSignatureManagerOptions defines options to create a new instance of PKCS11HSMSignatureManager.
type LKVSignatureManagerOptions struct {
}

var _ signaturemanager.DigitalSignatureManager = (*LKVSignatureManager)(nil)

func ProvideLKVSignatureManager(_ LKVSignatureManagerOptions) *LKVSignatureManager {
	return &LKVSignatureManager{}
}

// GenerateKey is not implemented: the key store lives in the slot configuration, which this manager
// cannot write. The slot use case generates Local Key Vault keys with NewKey instead.
func (sm *LKVSignatureManager) GenerateKey(_ context.Context, _ signaturemanager.GenerateKeyInput) (*signaturemanager.GenerateKeyOutput, error) {
	return nil, signaturemanager.NewNotImplementedError()
}

func (sm *LKVSignatureManager) RemoveKey(_ context.Context, _ signaturemanager.RemoveKeyInput) (*signaturemanager.RemoveKeyOutput, error) {
	return nil, signaturemanager.NewNotImplementedError()
}

func (sm *LKVSignatureManager) ListKeys(_ context.Context, _ signaturemanager.ListKeysInput) (*signaturemanager.ListKeysOutput, error) {
	return nil, signaturemanager.NewNotImplementedError()
}

func (sm *LKVSignatureManager) Sign(_ context.Context, input signaturemanager.SignInput) (*signaturemanager.SignOutput, error) {
	if input.Config.LocalKeyVault == nil || input.Config.LocalKeyVault.KeyStore == nil {
		return nil, signaturemanager.NewInternalError().WithMessage("cannot obtain private key to sign")
	}

	privateKeyStr, ok := input.Config.LocalKeyVault.KeyStore[input.From]
	if !ok {
		return nil, signaturemanager.NewInternalError().WithMessage("cannot obtain private key to sign")
	}

	privateKeyBytes, err := entities.NewHexBytesFromString(privateKeyStr)
	if err != nil {
		return nil, errors.InternalFromErr(err)
	}

	privateKey, err := parsePrivateKeyScalar(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	defer privateKey.Zero()

	// Sign on secp256k1 via btcec, the same library the connector uses to recover the
	// signature. crypto/ecdsa routes every non-NIST curve to its math/big legacy path,
	// which is documented as being for deprecated custom curves, is not constant time,
	// and is refused outright in FIPS 140-only mode.
	signature := btcececdsa.Sign(privateKey, input.Data)

	// Serialize as fixed-width r||s. The connector prepends the recovery byte and
	// normalises S; btcec already emits the low-S form.
	r, s := signature.R(), signature.S()
	rBytes, sBytes := r.Bytes(), s.Bytes()

	return &signaturemanager.SignOutput{
		Signature: append(rBytes[:], sBytes[:]...),
	}, nil
}

func (sm *LKVSignatureManager) Close(_ context.Context, _ signaturemanager.CloseInput) (*signaturemanager.CloseOutput, error) {
	return &signaturemanager.CloseOutput{}, nil
}

func (sm *LKVSignatureManager) Open(_ context.Context, _ signaturemanager.OpenInput) (*signaturemanager.OpenOutput, error) {
	return &signaturemanager.OpenOutput{}, nil
}

func (sm *LKVSignatureManager) IsAlive(_ context.Context, _ signaturemanager.IsAliveInput) (*signaturemanager.IsAliveOutput, error) {
	return &signaturemanager.IsAliveOutput{
		IsAlive: true,
	}, nil
}

// NewKey generates a secp256k1 private key from crypto/rand and returns it with its address. It is the
// only way a key enters a Local Key Vault: no API accepts a raw private key.
func NewKey() (entities.HexBytes, *address.Address, error) {
	privateKey, err := curves.NewPrivateKey()
	if err != nil {
		return nil, nil, errors.InternalFromErr(err)
	}
	defer privateKey.Zero()

	serialized := entities.HexBytes(privateKey.Serialize())
	derivedAddress, err := deriveAddress(serialized)
	if err != nil {
		return nil, nil, err
	}
	return serialized, derivedAddress, nil
}

// deriveAddress returns the address of a fixed-width private key. It goes through the shared
// DeriveAddressFromPublicKey on the fixed-width uncompressed public key, the same path PKCS#11 uses:
// hand-rolling X||Y with big.Int.Bytes() drops leading zero bytes and misaligns the coordinates.
func deriveAddress(privateKeyBytes entities.HexBytes) (*address.Address, error) {
	privateKey, err := parsePrivateKeyScalar(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	defer privateKey.Zero()

	derivedAddress, err := signaturemanager.DeriveAddressFromPublicKey(privateKey.PubKey().SerializeUncompressed())
	if err != nil {
		return nil, errors.Internal().WithMessage("failed deriving address from public key: %v", err)
	}
	return derivedAddress, nil
}

// parsePrivateKeyScalar parses a fixed-width big-endian private key into a secp256k1 scalar, rejecting
// a wrong length and the two out-of-range cases. SetByteSlice reports overflow, meaning D >= N, in
// constant time; PrivKeyFromBytes would silently reduce such a scalar mod N and sign with a key other
// than the one stored. Every key reaching here comes from the key store or NewKey, so a bad one is an
// internal error.
func parsePrivateKeyScalar(privateKey entities.HexBytes) (*curves.PrivateKey, error) {
	if len(privateKey) != privateKeyLengthBytes {
		return nil, errors.Internal().WithMessage("invalid private key length '%v'", len(privateKey))
	}
	var scalar curves.ModNScalar
	if overflow := scalar.SetByteSlice(privateKey); overflow || scalar.IsZero() {
		return nil, errors.Internal().WithMessage("invalid private key: D is zero or not less than N")
	}
	return curves.PrivKeyFromScalar(&scalar), nil
}
