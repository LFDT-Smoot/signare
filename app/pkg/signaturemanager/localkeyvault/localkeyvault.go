package localkeyvault

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"

	curves "github.com/btcsuite/btcd/btcec/v2"
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

	curve := curves.S256()
	d := new(big.Int).SetBytes(input.PrivateKey)
	// validate that D < N. btcec.PrivKeyFromBytes silently reduces an out-of-range
	// scalar mod N, so this rejection must happen before deriving the public key.
	if d.Cmp(curve.Params().N) >= 0 {
		return nil, errors.Internal().WithMessage("invalid private key: D >= N")
	}
	// D cannot be zero or negative
	if d.Sign() <= 0 {
		return nil, errors.Internal().WithMessage("invalid private key: D is zero or negative")
	}

	// Derive the address from the fixed-width uncompressed public key via the shared
	// helper, the same path PKCS#11 uses. Hand-rolling X||Y with big.Int.Bytes() drops
	// leading zero bytes and misaligns the coordinates (CRY-1).
	_, publicKey := curves.PrivKeyFromBytes(input.PrivateKey)
	derivedAddress, err := signaturemanager.DeriveAddressFromPublicKey(publicKey.SerializeUncompressed())
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

	curve := curves.S256()
	privateKey := new(ecdsa.PrivateKey)
	privateKey.Curve = curve
	privateKey.D = new(big.Int).SetBytes(privateKeyBytes)
	// validate that privateKey.D < N
	if privateKey.D.Cmp(curve.Params().N) >= 0 {
		return nil, errors.Internal().WithMessage("invalid private key: D >= N")
	}
	// privateKey.D cannot be zero or negative
	if privateKey.D.Sign() <= 0 {
		return nil, errors.Internal().WithMessage("invalid private key: D is zero or negative")
	}
	privateKey.X, privateKey.Y = curve.ScalarBaseMult(privateKeyBytes)
	if privateKey.X == nil {
		return nil, errors.Internal().WithMessage("invalid private key: X has no value")
	}
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, input.Data)
	if err != nil {
		return nil, errors.InternalFromErr(err)
	}

	rBytes := r.Bytes()
	rPadded := make([]byte, 32-len(rBytes))
	rPadded = append(rPadded, rBytes...)

	sBytes := s.Bytes()
	sPadded := make([]byte, 32-len(sBytes))
	sPadded = append(sPadded, sBytes...)

	signature := append(rPadded, sPadded...)

	return &signaturemanager.SignOutput{
		Signature: signature,
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
