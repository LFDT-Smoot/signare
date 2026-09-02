// Package eip191 builds the digest defined by EIP-191 for personal messages, the format produced by
// the personal_sign wallet method and consumed by Sign-In With Ethereum (EIP-4361) verifiers.
package eip191

import (
	"strconv"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
)

// personalMessagePrefix is the EIP-191 version byte 0x45 ("E") preamble.
//
// The leading 0x19 is the point of the scheme: it is not a valid first byte of an RLP-encoded
// transaction, so a signature produced over a personal message can never be replayed as a
// transaction, and vice versa.
const personalMessagePrefix = "\x19Ethereum Signed Message:\n"

// HashPersonalMessage returns the 32-byte digest that a personal_sign signature is taken over:
//
//	keccak256("\x19Ethereum Signed Message:\n" || len(message) || message)
//
// len(message) is the byte length of message rendered as ASCII decimal, not a fixed-width field. The
// message is treated as opaque bytes and is never interpreted as text, so no encoding normalisation
// is applied and a caller gets exactly the digest their bytes imply.
//
// An empty message is hashed rather than rejected, since that is what the definition says. Whether an
// empty message should be signable at all is a policy question and belongs to the caller.
func HashPersonalMessage(message []byte) ([]byte, error) {
	// Pre-size for the prefix, the longest possible decimal length, and the message, so the digest is
	// built in a single allocation.
	prefixed := make([]byte, 0, len(personalMessagePrefix)+20+len(message))
	prefixed = append(prefixed, personalMessagePrefix...)
	prefixed = strconv.AppendInt(prefixed, int64(len(message)), 10)
	prefixed = append(prefixed, message...)

	digest, err := entities.HashKeccak256(prefixed)
	if err != nil {
		return nil, err
	}
	return *digest, nil
}
