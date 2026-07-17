package hsmconnector

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/stretchr/testify/require"
)

// TestEIP155KnownAnswerVector pins the legacy signing path to the published EIP-155 specification
// example (https://eips.ethereum.org/EIPS/eip-155#example): a transaction signed with the example
// private key on chain ID 1. It proves that the signed hash and the emitted v are mutually
// consistent EIP-155 values, with no dependency on go-ethereum. This is the regression guard for
// CRY-2: before the fix, chain ID 0 produced an EIP-155 hash with a pre-EIP-155 v (27/28).
func TestEIP155KnownAnswerVector(t *testing.T) {
	to, err := address.NewFromHexString("0x3535353535353535353535353535353535353535")
	require.NoError(t, err)
	gas, err := entities.NewHexUInt64FromString("0x5208") // 21000
	require.NoError(t, err)
	gasPrice, err := entities.NewHexInt256FromString("0x4a817c800") // 20 Gwei
	require.NoError(t, err)
	value, err := entities.NewHexInt256FromString("0xde0b6b3a7640000") // 1 ETH
	require.NoError(t, err)
	data, err := entities.NewHexBytesFromString("0x")
	require.NoError(t, err)
	nonce, err := entities.NewHexUInt64FromString("0x9")
	require.NoError(t, err)
	chainID, err := entities.NewHexInt256FromString("0x1")
	require.NoError(t, err)

	tx := EthereumTransaction{
		To:       &to,
		Gas:      gas,
		GasPrice: *gasPrice,
		Value:    value,
		Data:     data,
		Nonce:    nonce,
		ChainID:  *chainID,
	}

	// 1. The signed hash must equal the published EIP-155 vector.
	const expectedHash = "0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
	hash, err := tx.Hash()
	require.NoError(t, err)
	require.Equal(t, expectedHash, hash.Encode())

	// 2. Signing that hash with the example key must reproduce the published v, r, s.
	keyBytes, err := hex.DecodeString("4646464646464646464646464646464646464646464646464646464646464646")
	require.NoError(t, err)
	privKey, _ := btcec.PrivKeyFromBytes(keyBytes)
	// SignCompact returns [V(27+recid) || R || S] as a low-S RFC-6979 signature, the same shape the
	// connector assembles from a backend signature before generateEthereumSignature is applied.
	compact := ecdsa.SignCompact(privKey, hash.Bytes(), false)

	sig := generateEthereumSignature(compact, *chainID)

	expectedR, ok := new(big.Int).SetString("28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276", 16)
	require.True(t, ok)
	expectedS, ok := new(big.Int).SetString("67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83", 16)
	require.True(t, ok)

	require.Equal(t, int64(37), sig.V.Int64())
	require.Zerof(t, sig.R.Cmp(expectedR), "r mismatch: got %x", &sig.R.Int)
	require.Zerof(t, sig.S.Cmp(expectedS), "s mismatch: got %x", &sig.S.Int)
}
