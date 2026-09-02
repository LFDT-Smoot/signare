package eip191_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/usecases/eip191"
)

// The expected digests below are known-answer vectors produced by an independent Keccak-256
// implementation written from the FIPS-202 permutation spec, not by this package. That implementation
// was first validated against the universally published keccak256("") digest
// c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 before any vector was taken from
// it, so these values are a genuine cross-check rather than a recording of current behaviour.
//
// No go-ethereum: signare owns its Ethereum layer for licensing reasons, so vectors are cross-checked
// offline and pinned here, following the pattern of the existing EIP-155 and EIP-712 vectors.
func TestHashPersonalMessage_KnownAnswerVectors(t *testing.T) {
	tests := []struct {
		name    string
		message []byte
		want    string
	}{
		{
			// The length prefix is "0", not an absence. Pinning this stops an implementation that skips
			// the length field entirely for an empty message from passing.
			name:    "empty message",
			message: []byte{},
			want:    "5f35dce98ba4fba25530a026ed80b2cecdaa31091ba4958b99b52ea1d068adad",
		},
		{
			name:    "single zero byte",
			message: []byte{0x00},
			want:    "de4cdc789ddc73a0a79bd8cf489c37d5254a1e14a0fb771ce4e77c0206c3d0e1",
		},
		{
			name:    "Hello World",
			message: []byte("Hello World"),
			want:    "a1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2",
		},
		{
			// Two decimal digits: catches a fixed-width or single-digit length encoding.
			name:    "ten bytes",
			message: []byte("0123456789"),
			want:    "91e26c79ff38a9cd1035942268ee3d72eaccb7e19e833121d3714716f1402c0a",
		},
		{
			// Three decimal digits.
			name:    "one hundred bytes",
			message: []byte(strings.Repeat("a", 100)),
			want:    "90b496d4433ae2fe10bba2f73ca6a210a57d8499db0ae5dfb05f3fbeeff2b0cf",
		},
		{
			// Four decimal digits, and larger than one keccak rate block.
			name:    "one thousand bytes",
			message: []byte(strings.Repeat("b", 1000)),
			want:    "40f924a57a5b25b0b74a2afa545c208c4560858254bde0778c36a0e69e8ba806",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			digest, err := eip191.HashPersonalMessage(test.message)
			require.NoError(t, err)
			require.Len(t, digest, 32)
			require.Equal(t, test.want, hex.EncodeToString(digest))
		})
	}
}

// The length in the prefix is a byte count, not a rune count. A multi-byte message whose rune count
// differs from its byte count would produce a digest no standard verifier agrees with.
func TestHashPersonalMessage_LengthIsBytesNotRunes(t *testing.T) {
	multiByte := []byte("héllo")
	require.Len(t, multiByte, 6, "fixture must be 6 bytes but 5 runes for this test to mean anything")

	fromMultiByte, err := eip191.HashPersonalMessage(multiByte)
	require.NoError(t, err)

	// A five-byte message must not collide with the six-byte one.
	fromFiveBytes, err := eip191.HashPersonalMessage([]byte("hello"))
	require.NoError(t, err)

	require.NotEqual(t, hex.EncodeToString(fromFiveBytes), hex.EncodeToString(fromMultiByte))
}

// The digest must depend on the message boundary, not just on the concatenation. Without the length
// field, "12" + "3" and "1" + "23" would be indistinguishable; this pins that they are not.
func TestHashPersonalMessage_LengthPrefixDisambiguates(t *testing.T) {
	first, err := eip191.HashPersonalMessage([]byte("12"))
	require.NoError(t, err)
	second, err := eip191.HashPersonalMessage([]byte("1"))
	require.NoError(t, err)

	require.NotEqual(t, hex.EncodeToString(first), hex.EncodeToString(second))
}

func TestHashPersonalMessage_IsDeterministic(t *testing.T) {
	message := []byte("sign in to example.com")
	first, err := eip191.HashPersonalMessage(message)
	require.NoError(t, err)
	second, err := eip191.HashPersonalMessage(message)
	require.NoError(t, err)

	require.Equal(t, hex.EncodeToString(first), hex.EncodeToString(second))
	require.Equal(t, []byte("sign in to example.com"), message, "input must not be mutated")
}

// A SIWE (EIP-4361) message is the motivating use case: multi-line, mixed content, and its byte
// length crosses into three digits.
func TestHashPersonalMessage_SIWEShapedMessage(t *testing.T) {
	siwe := "example.com wants you to sign in with your Ethereum account:\n" +
		"0x0000000000000000000000000000000000000001\n\n" +
		"Sign in.\n\n" +
		"URI: https://example.com\nVersion: 1\nChain ID: 1\n" +
		"Nonce: 32891756\nIssued At: 2026-08-27T00:00:00Z"

	digest, err := eip191.HashPersonalMessage([]byte(siwe))
	require.NoError(t, err)
	require.Len(t, digest, 32)
}
