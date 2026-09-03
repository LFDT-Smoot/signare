package localkeyvault

import (
	"context"
	"fmt"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
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

func (sm *LKVSignatureManager) GenerateKey(_ context.Context, _ signaturemanager.GenerateKeyInput) (*signaturemanager.GenerateKeyOutput, error) {
	return nil, signaturemanager.NewNotImplementedError()
}

func (sm *LKVSignatureManager) DeriveAddressFromPrivateKey(_ context.Context, input signaturemanager.DeriveAddressFromPrivateKeyInput) (*signaturemanager.DeriveAddressFromPrivateKeyOutput, error) {
	if len(input.PrivateKey) != privateKeyLengthBytes {
		return nil, signaturemanager.NewInvalidArgumentError().WithMessage(fmt.Sprintf("invalid private key length '%v'", len(input.PrivateKey)))
	}

	privateKey, err := parsePrivateKeyScalar(input.PrivateKey)
	if err != nil {
		return nil, err
	}
	defer privateKey.Zero()

	// Derive the address from the fixed-width uncompressed public key via the shared
	// helper, the same path PKCS#11 uses. Hand-rolling X||Y with big.Int.Bytes() drops
	// leading zero bytes and misaligns the coordinates (CRY-1).
	derivedAddress, err := signaturemanager.DeriveAddressFromPublicKey(privateKey.PubKey().SerializeUncompressed())
	if err != nil {
		return nil, errors.Internal().WithMessage("failed deriving address from public key: %v", err)
	}

	return &signaturemanager.DeriveAddressFromPrivateKeyOutput{
		Address: *derivedAddress,
	}, nil
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

	if len(privateKeyBytes) != privateKeyLengthBytes {
		return nil, errors.Internal().WithMessage("invalid private key length '%v'", len(privateKeyBytes))
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

// parsePrivateKeyScalar parses a fixed-width big-endian private key into a secp256k1
// scalar, rejecting the two out-of-range cases. SetByteSlice reports overflow, meaning
// D >= N, in constant time; PrivKeyFromBytes would silently reduce such a scalar mod N
// and sign with a key other than the one supplied. Callers own the length check, because
// the classification differs: an operator's slot configuration is an internal error, a
// caller-supplied key on the import path is an invalid argument.
func parsePrivateKeyScalar(privateKey entities.HexBytes) (*curves.PrivateKey, error) {
	var scalar curves.ModNScalar
	if overflow := scalar.SetByteSlice(privateKey); overflow || scalar.IsZero() {
		return nil, errors.Internal().WithMessage("invalid private key: D is zero or not less than N")
	}
	return curves.PrivKeyFromScalar(&scalar), nil
}
