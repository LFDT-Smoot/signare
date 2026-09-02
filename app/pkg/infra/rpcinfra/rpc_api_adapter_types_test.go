package rpcinfra_test

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra/rpcerrors"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/eip712"

	"github.com/stretchr/testify/require"
)

// Regression for API-1: a single positional parameter that is not an object must
// return an InvalidParams error instead of panicking on the type assertion.
func TestProcessParams_NonObjectPositionalParamReturnsInvalidParams(t *testing.T) {
	tests := []struct {
		name   string
		params rpcinfra.JSONRPCParams
	}{
		{name: "import account", params: &rpcinfra.ImportAccountRequestParams{}},
		{name: "remove account", params: &rpcinfra.RemoveAccountRequestParams{}},
		{name: "sign transaction", params: &rpcinfra.SignTXRequestParams{}},
		{name: "sign typed data", params: &rpcinfra.SignTypedDataRequestParams{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := json.RawMessage(`["x"]`)
			var rpcErr *rpcerrors.RPCError
			require.NotPanics(t, func() {
				rpcErr = rpcinfra.ProcessParams(raw, tt.params)
			})
			require.NotNil(t, rpcErr)
			require.Equal(t, rpcerrors.InvalidParamsErrorCode, rpcErr.Code)
		})
	}
}

// Guard against overcorrection: a well-formed object positional parameter must
// still be parsed successfully.
func TestProcessParams_ObjectPositionalParamSucceeds(t *testing.T) {
	t.Run("import account", func(t *testing.T) {
		params := &rpcinfra.ImportAccountRequestParams{}
		require.Nil(t, rpcinfra.ProcessParams(json.RawMessage(`[{"privateKey":"deadbeef"}]`), params))
		require.Equal(t, "deadbeef", params.PrivateKey)
	})
	t.Run("remove account", func(t *testing.T) {
		params := &rpcinfra.RemoveAccountRequestParams{}
		require.Nil(t, rpcinfra.ProcessParams(json.RawMessage(`[{"address":"0xabc"}]`), params))
		require.Equal(t, "0xabc", params.Address)
	})
	t.Run("sign transaction", func(t *testing.T) {
		params := &rpcinfra.SignTXRequestParams{}
		require.Nil(t, rpcinfra.ProcessParams(json.RawMessage(`[{"from":"0xabc","data":"0x","nonce":"0x1"}]`), params))
		require.Equal(t, "0xabc", params.From)
	})
	t.Run("sign typed data", func(t *testing.T) {
		params := &rpcinfra.SignTypedDataRequestParams{}
		raw := json.RawMessage(`[{"address":"0xabc","typedData":{"primaryType":"Mail","types":{"EIP712Domain":[{"name":"name","type":"string"}],"Mail":[{"name":"contents","type":"string"}]},"domain":{"name":"test","chainId":"0x1"},"message":{"contents":"hello"}}}]`)
		require.Nil(t, rpcinfra.ProcessParams(raw, params))
		require.Equal(t, "0xabc", params.Address)
		require.Equal(t, "Mail", params.TypedData.PrimaryType)
		require.NoError(t, params.ValidateParams())
	})
}

func TestSignTXRequestParams_AccessListPresenceIsPreserved(t *testing.T) {
	const mandatoryFields = `"from":"0xabc","data":"0x","nonce":"0x1"`

	t.Run("omitted accessList stays nil", func(t *testing.T) {
		params := &rpcinfra.SignTXRequestParams{}
		require.Nil(t, rpcinfra.ProcessParams(json.RawMessage(`[{`+mandatoryFields+`}]`), params))
		require.Nil(t, params.AccessList)
	})

	t.Run("empty accessList becomes a non-nil empty slice", func(t *testing.T) {
		params := &rpcinfra.SignTXRequestParams{}
		require.Nil(t, rpcinfra.ProcessParams(json.RawMessage(`[{`+mandatoryFields+`,"accessList":[]}]`), params))
		require.NotNil(t, params.AccessList)
		require.Empty(t, params.AccessList)
	})

	t.Run("populated accessList keeps its entries", func(t *testing.T) {
		params := &rpcinfra.SignTXRequestParams{}
		raw := json.RawMessage(`[{` + mandatoryFields + `,"accessList":[{"address":"0xcccccccccccccccccccccccccccccccccccccccc","storageKeys":["0x0000000000000000000000000000000000000000000000000000000000000001"]}]}]`)
		require.Nil(t, rpcinfra.ProcessParams(raw, params))
		require.Len(t, params.AccessList, 1)
		require.Equal(t, "0xcccccccccccccccccccccccccccccccccccccccc", params.AccessList[0].Address)
		require.Equal(t, []string{"0x0000000000000000000000000000000000000000000000000000000000000001"}, params.AccessList[0].StorageKeys)
	})
}

// TestSignTypedDataRequestParams_ValidateParams guards the validation surface exposed to the handler:
// the account address is mandatory and the typed data must declare the structure eip712 requires.
func TestSignTypedDataRequestParams_ValidateParams(t *testing.T) {
	t.Run("missing address", func(t *testing.T) {
		params := &rpcinfra.SignTypedDataRequestParams{}
		require.Nil(t, rpcinfra.ProcessParams(json.RawMessage(`[{"address":"","typedData":{"primaryType":"Mail","types":{"EIP712Domain":[],"Mail":[]},"domain":{},"message":{}}}]`), params))
		require.Error(t, params.ValidateParams())
	})
	t.Run("typed data missing primaryType", func(t *testing.T) {
		params := &rpcinfra.SignTypedDataRequestParams{}
		require.Nil(t, rpcinfra.ProcessParams(json.RawMessage(`[{"address":"0xabc","typedData":{"types":{"EIP712Domain":[]},"domain":{},"message":{}}}]`), params))
		require.Error(t, params.ValidateParams())
	})
}

// TestSignTypedDataRequestParams_PreservesLargeMessageIntegers guards that an integer message field is
// decoded as json.Number rather than float64, so a value above 2^53 (here 2^53+1) is not silently
// rounded before it reaches the EIP-712 encoder. Decoded through float64 the value would become
// 9007199254740992.
func TestSignTypedDataRequestParams_PreservesLargeMessageIntegers(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "array form", raw: `[{"address":"0xabc","typedData":{"primaryType":"Order","types":{"EIP712Domain":[],"Order":[{"name":"amount","type":"uint256"}]},"domain":{},"message":{"amount":9007199254740993}}}]`},
		{name: "object form", raw: `{"address":"0xabc","typedData":{"primaryType":"Order","types":{"EIP712Domain":[],"Order":[{"name":"amount","type":"uint256"}]},"domain":{},"message":{"amount":9007199254740993}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := &rpcinfra.SignTypedDataRequestParams{}
			require.Nil(t, rpcinfra.ProcessParams(json.RawMessage(tt.raw), params))
			require.Equal(t, json.Number("9007199254740993"), params.TypedData.Message["amount"])
		})
	}
}

// TestSignTypedData_RawJSONToEncodedWord spans the whole path a request travels: raw JSON-RPC params
// with a uint256 message field above 2^53, decoded via ProcessParams, then EIP-712 ABI-encoded. It
// asserts the resulting 32-byte word is the exact value (ends in 0x01), guarding decode and encode
// together, which neither the decode-only nor the encode-only test does alone.
func TestSignTypedData_RawJSONToEncodedWord(t *testing.T) {
	params := &rpcinfra.SignTypedDataRequestParams{}
	raw := json.RawMessage(`[{"address":"0xabc","typedData":{"primaryType":"Order","types":{"EIP712Domain":[],"Order":[{"name":"amount","type":"uint256"}]},"domain":{},"message":{"amount":9007199254740993}}}]`)
	require.Nil(t, rpcinfra.ProcessParams(raw, params))

	word, err := eip712.Types{}.EncodeField("uint256", params.TypedData.Message["amount"])
	require.NoError(t, err)

	want := make([]byte, 32)
	exact, ok := new(big.Int).SetString("9007199254740993", 10)
	require.True(t, ok)
	exactBytes := exact.Bytes()
	copy(want[32-len(exactBytes):], exactBytes)
	require.Equal(t, want, word)
	require.Equal(t, byte(0x01), word[31], "last byte must be 0x01; 0x00 would mean the value was rounded down to 2^53")
}
