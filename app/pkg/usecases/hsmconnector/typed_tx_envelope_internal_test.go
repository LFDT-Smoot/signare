package hsmconnector

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/commons/rlp"
	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"

	"github.com/stretchr/testify/require"
)

// rlpListContents strips the RLP list header from encoded, returning just the concatenated encodings of
// its items. Only list payloads are expected here, so anything else is a test failure.
func rlpListContents(t *testing.T, encoded []byte) []byte {
	t.Helper()
	require.NotEmpty(t, encoded)
	switch first := encoded[0]; {
	case first >= 0xc0 && first <= 0xf7: // short list: header is the single length byte
		return encoded[1:]
	case first >= 0xf8: // long list: header is the length-of-length byte plus that many length bytes
		return encoded[1+int(first-0xf7):]
	default:
		t.Fatalf("expected an RLP list, got a payload starting with 0x%02x", first)
		return nil
	}
}

// TestTypedTxSignedEncodingCommitsToTheHashedFields guards the invariant that makes a typed transaction
// safe to broadcast: the fields the signature was taken over must be exactly the leading fields of the
// bytes that go on the wire, in the same order, under the same type prefix.
//
// If Hash and RLPEncode ever derive their field lists separately again and those lists drift, both calls
// still succeed and the transaction still signs cleanly — a node just recovers a different sender. This
// test compares the two encodings directly, so it fails on any such drift regardless of which field
// moved, rather than only for the fixtures the golden vectors happen to pin.
func TestTypedTxSignedEncodingCommitsToTheHashedFields(t *testing.T) {
	chainID, err := entities.NewHexInt256FromString("0x2a")
	require.NoError(t, err)
	gasPrice, err := entities.NewHexInt256FromString("0x3b9aca00")
	require.NoError(t, err)
	maxFeePerGas, err := entities.NewHexInt256FromString("0x77359400")
	require.NoError(t, err)
	maxPriorityFeePerGas, err := entities.NewHexInt256FromString("0x3b9aca00")
	require.NoError(t, err)
	gas, err := entities.NewHexUInt64FromString("0x5208")
	require.NoError(t, err)
	nonce, err := entities.NewHexUInt64FromString("0x11")
	require.NoError(t, err)
	value, err := entities.NewHexInt256FromString("0xde0b6b3a7640000")
	require.NoError(t, err)
	data, err := entities.NewHexBytesFromString("0xa9059cbb")
	require.NoError(t, err)
	to, err := address.NewFromHexString("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	require.NoError(t, err)

	storageKey := entities.HexBytes32{}
	storageKey[31] = 0x01
	accessList := AccessList{
		{Address: to, StorageKeys: []entities.HexBytes32{storageKey}},
	}
	signature := &YParityTransactionSignature{
		YParity: *entities.NewInt256(big.NewInt(1)),
		R:       *entities.NewInt256(big.NewInt(0x1234)),
		S:       *entities.NewInt256(big.NewInt(0x5678)),
	}

	tests := []struct {
		name       string
		wantPrefix byte
		envelope   func() (*typedTxEnvelope, error)
		hash       func() (*entities.HexBytes, error)
		encode     func() (*entities.HexBytes, error)
	}{
		{
			name:       "EIP-2930",
			wantPrefix: eip2930TypePrefix,
			envelope: func() (*typedTxEnvelope, error) {
				return eip2930Fixture(chainID, nonce, gasPrice, gas, to, value, data, accessList, signature).envelope()
			},
			hash: func() (*entities.HexBytes, error) {
				return eip2930Fixture(chainID, nonce, gasPrice, gas, to, value, data, accessList, signature).Hash()
			},
			encode: func() (*entities.HexBytes, error) {
				return eip2930Fixture(chainID, nonce, gasPrice, gas, to, value, data, accessList, signature).RLPEncode()
			},
		},
		{
			name:       "EIP-1559",
			wantPrefix: eip1559TypePrefix,
			envelope: func() (*typedTxEnvelope, error) {
				return eip1559Fixture(chainID, nonce, maxFeePerGas, maxPriorityFeePerGas, gas, to, value, data, accessList, signature).envelope()
			},
			hash: func() (*entities.HexBytes, error) {
				return eip1559Fixture(chainID, nonce, maxFeePerGas, maxPriorityFeePerGas, gas, to, value, data, accessList, signature).Hash()
			},
			encode: func() (*entities.HexBytes, error) {
				return eip1559Fixture(chainID, nonce, maxFeePerGas, maxPriorityFeePerGas, gas, to, value, data, accessList, signature).RLPEncode()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope, envErr := tt.envelope()
			require.NoError(t, envErr)
			require.Equal(t, tt.wantPrefix, envelope.prefix)

			signed, encodeErr := tt.encode()
			require.NoError(t, encodeErr)
			signedBytes := signed.Bytes()

			// The wire bytes must carry the declared type prefix.
			require.Equal(t, tt.wantPrefix, signedBytes[0])

			// The hashed payload must be the same prefix over the same field list.
			payloadRLP, rlpErr := rlp.Encode(envelope.fields)
			require.NoError(t, rlpErr)
			wantHash, hashErr := hashKeccak256(append([]byte{tt.wantPrefix}, payloadRLP...))
			require.NoError(t, hashErr)
			gotHash, txHashErr := tt.hash()
			require.NoError(t, txHashErr)
			require.Equal(t, entities.NewHexBytes(wantHash).Encode(), gotHash.Encode())

			// The signed list must begin with exactly the hashed list's items, so the three signature
			// values are the only difference between what was signed and what is broadcast.
			hashedItems := rlpListContents(t, payloadRLP)
			signedItems := rlpListContents(t, signedBytes[1:])
			require.Truef(t, bytes.HasPrefix(signedItems, hashedItems),
				"signed field list does not begin with the hashed field list\n hashed: %x\n signed: %x", hashedItems, signedItems)

			// And the remainder must be exactly yParity, R and S.
			wantSignatureItems, sigErr := rlp.Encode([]interface{}{
				signature.YParity.BigInt(), signature.R.BigInt(), signature.S.BigInt(),
			})
			require.NoError(t, sigErr)
			require.Equal(t, rlpListContents(t, wantSignatureItems), signedItems[len(hashedItems):])
		})
	}
}

func eip2930Fixture(chainID *entities.HexInt256, nonce entities.HexUInt64, gasPrice *entities.HexInt256, gas entities.HexUInt64, to address.Address, value *entities.HexInt256, data entities.HexBytes, accessList AccessList, signature *YParityTransactionSignature) EIP2930Transaction {
	return EIP2930Transaction{
		To:         &to,
		Gas:        gas,
		GasPrice:   *gasPrice,
		Value:      value,
		Data:       data,
		Nonce:      nonce,
		ChainID:    *chainID,
		AccessList: accessList,
		Signature:  signature,
	}
}

func eip1559Fixture(chainID *entities.HexInt256, nonce entities.HexUInt64, maxFeePerGas *entities.HexInt256, maxPriorityFeePerGas *entities.HexInt256, gas entities.HexUInt64, to address.Address, value *entities.HexInt256, data entities.HexBytes, accessList AccessList, signature *YParityTransactionSignature) EIP1559Transaction {
	return EIP1559Transaction{
		To:                   &to,
		Gas:                  gas,
		MaxFeePerGas:         *maxFeePerGas,
		MaxPriorityFeePerGas: *maxPriorityFeePerGas,
		Value:                value,
		Data:                 data,
		Nonce:                nonce,
		ChainID:              *chainID,
		AccessList:           accessList,
		Signature:            signature,
	}
}
