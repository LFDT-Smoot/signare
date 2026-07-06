package hsmconnector

import (
	"encoding/hex"
	"math/big"

	"github.com/hyperledger-labs/signare/app/pkg/entities"
	"github.com/hyperledger-labs/signare/app/pkg/internal/errors"

	curves "github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/sha3"
)

func generateEthereumSignature(signature []byte, chainID entities.HexInt256) *EthereumSignature {
	r := new(big.Int).SetBytes(signature[1:33])
	s := new(big.Int).SetBytes(signature[33:signatureLength])

	// The legacy Hash() always appends the EIP-155 suffix, so v must always be the EIP-155 value for
	// the signed hash and v to stay consistent. chainID is guaranteed >= 1 by the SignTx guard.
	ethV := int64(signature[0]) - signatureVMin // the EC recovery library encodes V as 27 or 28; Ethereum expects 0 or 1
	// calculate the V value based on https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md#specification
	v := big.NewInt(ethV + 35)
	mul := new(big.Int).Mul(chainID.BigInt(), big.NewInt(2))
	v.Add(v, mul)

	return &EthereumSignature{
		V: entities.Int256{
			Int: *v,
		},
		R: entities.Int256{
			Int: *r,
		},
		S: entities.Int256{
			Int: *s,
		},
	}
}

// generateEIP1559TransactionSignature creates a signature for an EIP-1559 (Type 2) transaction.
// For Type 2, V is simply yParity (0 or 1), not the EIP-155 formula.
func generateEIP1559TransactionSignature(signature []byte) *EIP1559TransactionSignature {
	r := new(big.Int).SetBytes(signature[1:33])
	s := new(big.Int).SetBytes(signature[33:signatureLength])

	// yParity is 0 or 1 (convert from bitcoin library's 27/28 range)
	yParity := int64(signature[0]) - signatureVMin

	return &EIP1559TransactionSignature{
		YParity: entities.Int256{Int: *big.NewInt(yParity)},
		R:       entities.Int256{Int: *r},
		S:       entities.Int256{Int: *s},
	}
}

// signatureToLowS ensures that the signature has a low S value as Ethereum requires in EIP-2 https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md.
func signatureToLowS(sig []byte) []byte {
	rVal := new(big.Int)
	sVal := new(big.Int)
	rVal.SetBytes(sig[0 : len(sig)/2])
	sVal.SetBytes(sig[len(sig)/2:])
	if sVal.Cmp(halfOrder()) == 1 {
		sVal.Sub(curves.S256().Params().N, sVal)
	}
	rBytes := rVal.Bytes()
	sBytes := sVal.Bytes()
	ret := make([]byte, len(sig))
	rOffset := len(sig)/2 - len(rBytes)
	sOffset := len(sig)/2 - len(sBytes)
	copy(ret[rOffset:len(sig)/2], rBytes)
	copy(ret[len(sig)/2+sOffset:], sBytes)
	return ret
}

// validateBackendSignature checks that a raw signature returned by a signing backend is a 64-byte
// r||s pair with r and s both in [1, N-1]. The connector is the single trust boundary for backend
// output, so validating here turns a malformed response into a clear bad-gateway error (an upstream
// fault, not an internal one) instead of a misleading downstream "unable to find EC recovery value"
// failure from the recovery loop.
func validateBackendSignature(sig []byte) error {
	const humanReadable = "the signing backend returned a malformed signature"
	if len(sig) != backendSignatureLength {
		return errors.BadGateway().WithMessage("backend returned a malformed signature: expected %d-byte r||s, got %d", backendSignatureLength, len(sig)).SetHumanReadableMessage("%s", humanReadable)
	}
	n := curves.S256().Params().N
	r := new(big.Int).SetBytes(sig[:backendSignatureLength/2])
	s := new(big.Int).SetBytes(sig[backendSignatureLength/2:])
	if r.Sign() <= 0 || r.Cmp(n) >= 0 {
		return errors.BadGateway().WithMessage("backend returned a malformed signature: r out of range [1, N-1]").SetHumanReadableMessage("%s", humanReadable)
	}
	if s.Sign() <= 0 || s.Cmp(n) >= 0 {
		return errors.BadGateway().WithMessage("backend returned a malformed signature: s out of range [1, N-1]").SetHumanReadableMessage("%s", humanReadable)
	}
	return nil
}

// unmarshalECDSAKey converts bytes to a secp256k1 public key.
func unmarshalECDSAKey(pubKeyBytes []byte) (*curves.PublicKey, error) {
	pk, err := curves.ParsePubKey(pubKeyBytes)
	if err != nil {
		return nil, errors.Internal().WithMessage("unable to parse public key. Error: %v", err)
	}

	return pk, nil
}

// halfOrder returns half the order of the secp256k1 curve.
func halfOrder() *big.Int {
	return new(big.Int).Rsh(curves.S256().Params().N, 1)
}

// hashKeccak256 returns the keccak256 hash of the input data
func hashKeccak256(data []byte) ([]byte, error) {
	d := sha3.NewLegacyKeccak256()
	if _, err := d.Write(data); err != nil {
		return nil, err
	}
	return d.Sum(nil), nil
}

// ToHex converts to the 65-byte [R || S || V] format (Ethereum Standard)
func (s *EthereumSignature) ToHex() string {
	rBytes := s.R.Bytes()
	sBytes := s.S.Bytes()
	vBytes := s.V.Bytes()
	buffer := make([]byte, 65)
	// R (Bytes 0-31)
	copy(buffer[32-len(rBytes):32], rBytes)
	// S (Bytes 32-63)
	copy(buffer[32+32-len(sBytes):64], sBytes)
	// V (Byte 64)
	if len(vBytes) > 0 {
		buffer[64] = vBytes[len(vBytes)-1]
	}
	return "0x" + hex.EncodeToString(buffer)
}
