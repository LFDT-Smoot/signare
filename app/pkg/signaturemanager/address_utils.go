package signaturemanager

import (
	"golang.org/x/crypto/sha3"

	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
)

// uncompressedPublicKeyLength is the byte length of a 0x04-prefixed uncompressed secp256k1 public key.
const uncompressedPublicKeyLength = 65

func DeriveAddressFromPublicKey(publicKeyBytes []byte) (*address.Address, error) {
	// Guard this shared derivation chokepoint: callers must pass a 0x04-prefixed uncompressed
	// public key (0x04 || X || Y). Without this, publicKeyBytes[1:] panics on an empty slice
	// and a bare 64-byte X || Y would silently drop a byte and derive a wrong address.
	if len(publicKeyBytes) != uncompressedPublicKeyLength || publicKeyBytes[0] != 0x04 {
		return nil, NewInvalidArgumentError().WithMessage("invalid uncompressed public key")
	}
	keccak, err := hashKeccak256(publicKeyBytes[1:])
	if err != nil {
		return nil, err
	}
	addr, err := address.NewFromRawBytes(keccak[12:])
	if err != nil {
		return nil, err
	}
	return addr, nil
}

// hashKeccak256 returns the keccak256 hash of the input data
func hashKeccak256(data []byte) ([]byte, error) {
	d := sha3.NewLegacyKeccak256()
	if _, err := d.Write(data); err != nil {
		return nil, err
	}
	return d.Sum(nil), nil
}
