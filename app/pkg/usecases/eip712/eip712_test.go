package eip712_test

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger-labs/signare/app/pkg/usecases/eip712"
)

// specTypes holds the canonical Ether Mail example from https://eips.ethereum.org/assets/eip-712/Example.js
var specTypes = eip712.Types{
	"EIP712Domain": []eip712.Type{
		{Name: "name", Type: "string"},
		{Name: "version", Type: "string"},
		{Name: "chainId", Type: "uint256"},
		{Name: "verifyingContract", Type: "address"},
	},
	"Person": []eip712.Type{
		{Name: "name", Type: "string"},
		{Name: "wallet", Type: "address"},
	},
	"Mail": []eip712.Type{
		{Name: "from", Type: "Person"},
		{Name: "to", Type: "Person"},
		{Name: "contents", Type: "string"},
	},
}

func TestEIP712EncodeType(t *testing.T) {
	t.Run("simple type with no struct dependencies", func(t *testing.T) {
		types := eip712.Types{
			"Person": []eip712.Type{
				{Name: "name", Type: "string"},
				{Name: "wallet", Type: "address"},
			},
		}
		got, err := types.EncodeType("Person")
		require.NoError(t, err)
		require.Equal(t, "Person(string name,address wallet)", got)
	})

	t.Run("type with struct dependency sorted alphabetically after primary", func(t *testing.T) {
		got, err := specTypes.EncodeType("Mail")
		require.NoError(t, err)
		require.Equal(t, "Mail(Person from,Person to,string contents)Person(string name,address wallet)", got)
	})

	t.Run("array of struct dependency included", func(t *testing.T) {
		types := eip712.Types{
			"Item":  []eip712.Type{{Name: "value", Type: "uint256"}},
			"Order": []eip712.Type{{Name: "items", Type: "Item[]"}},
		}
		got, err := types.EncodeType("Order")
		require.NoError(t, err)
		require.Equal(t, "Order(Item[] items)Item(uint256 value)", got)
	})
}

func TestEIP712TypeHash(t *testing.T) {
	// Reference value from https://eips.ethereum.org/assets/eip-712/Example.js
	const wantMailTypeHash = "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2"
	hash, err := specTypes.TypeHash("Mail")
	require.NoError(t, err)
	require.Equal(t, wantMailTypeHash, hex.EncodeToString(hash))
}

func TestEIP712EncodeField(t *testing.T) {
	t.Run("bool true encodes as 32 bytes with final byte 1", func(t *testing.T) {
		got, err := eip712.Types{}.EncodeField("bool", true)
		require.NoError(t, err)
		require.Len(t, got, 32)
		want := make([]byte, 32)
		want[31] = 1
		require.Equal(t, want, got)
	})

	t.Run("bool false encodes as 32 zero bytes", func(t *testing.T) {
		got, err := eip712.Types{}.EncodeField("bool", false)
		require.NoError(t, err)
		require.Equal(t, make([]byte, 32), got)
	})

	t.Run("uint256 as float64 right-padded to 32 bytes", func(t *testing.T) {
		got, err := eip712.Types{}.EncodeField("uint256", float64(42))
		require.NoError(t, err)
		want := make([]byte, 32)
		want[31] = 42
		require.Equal(t, want, got)
	})

	t.Run("uint256 as decimal string", func(t *testing.T) {
		got, err := eip712.Types{}.EncodeField("uint256", "1000000000000000000")
		require.NoError(t, err)
		require.Equal(t, "0000000000000000000000000000000000000000000000000de0b6b3a7640000", hex.EncodeToString(got))
	})

	t.Run("uint256 as hex string", func(t *testing.T) {
		got, err := eip712.Types{}.EncodeField("uint256", "0x1")
		require.NoError(t, err)
		want := make([]byte, 32)
		want[31] = 1
		require.Equal(t, want, got)
	})

	t.Run("uint256 as *big.Int", func(t *testing.T) {
		got, err := eip712.Types{}.EncodeField("uint256", big.NewInt(255))
		require.NoError(t, err)
		want := make([]byte, 32)
		want[31] = 255
		require.Equal(t, want, got)
	})

	t.Run("int256 as int", func(t *testing.T) {
		got, err := eip712.Types{}.EncodeField("int256", 7)
		require.NoError(t, err)
		want := make([]byte, 32)
		want[31] = 7
		require.Equal(t, want, got)
	})

	t.Run("address left-padded to 32 bytes", func(t *testing.T) {
		got, err := eip712.Types{}.EncodeField("address", "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
		require.NoError(t, err)
		require.Equal(t, "000000000000000000000000cccccccccccccccccccccccccccccccccccccccc", hex.EncodeToString(got))
	})

	t.Run("string hashed with keccak256", func(t *testing.T) {
		got, err := eip712.Types{}.EncodeField("string", "hello")
		require.NoError(t, err)
		// keccak256("hello")
		require.Equal(t, "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8", hex.EncodeToString(got))
	})

	t.Run("empty string hashed with keccak256", func(t *testing.T) {
		got, err := eip712.Types{}.EncodeField("string", "")
		require.NoError(t, err)
		// keccak256("")
		require.Equal(t, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", hex.EncodeToString(got))
	})

	t.Run("bytes hashed with keccak256", func(t *testing.T) {
		got, err := eip712.Types{}.EncodeField("bytes", "0xdeadbeef")
		require.NoError(t, err)
		// keccak256(0xdeadbeef)
		require.Equal(t, "d4fd4e189132273036449fc9e11198c739161b4c0116a9a2dccdfa1c492006f1", hex.EncodeToString(got))
	})

	t.Run("bytes32 left-aligned and zero-padded to 32 bytes", func(t *testing.T) {
		got, err := eip712.Types{}.EncodeField("bytes32", "0xdeadbeef")
		require.NoError(t, err)
		require.Equal(t, "deadbeef00000000000000000000000000000000000000000000000000000000", hex.EncodeToString(got))
	})

	t.Run("nested struct produces a 32-byte hash", func(t *testing.T) {
		got, err := specTypes.EncodeField("Person", map[string]interface{}{
			"name":   "Cow",
			"wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
		})
		require.NoError(t, err)
		require.Len(t, got, 32)
	})

	t.Run("string array produces a 32-byte hash", func(t *testing.T) {
		got, err := eip712.Types{}.EncodeField("string[]", []interface{}{"hello", "world"})
		require.NoError(t, err)
		require.Len(t, got, 32)
	})
}

func TestEIP712EncodeField_Errors(t *testing.T) {
	t.Run("float64 exceeding 2^53 precision returns error", func(t *testing.T) {
		_, err := eip712.Types{}.EncodeField("uint256", float64(1<<54))
		require.Error(t, err)
		require.Contains(t, err.Error(), "float64 precision")
	})

	t.Run("negative integer not supported", func(t *testing.T) {
		_, err := eip712.Types{}.EncodeField("int256", -1)
		require.Error(t, err)
	})

	t.Run("address with wrong byte length", func(t *testing.T) {
		_, err := eip712.Types{}.EncodeField("address", "0xdeadbeef")
		require.Error(t, err)
	})

	t.Run("address non-hex string", func(t *testing.T) {
		_, err := eip712.Types{}.EncodeField("address", "hello world")
		require.Error(t, err)
	})

	t.Run("address non-string type", func(t *testing.T) {
		_, err := eip712.Types{}.EncodeField("address", 42)
		require.Error(t, err)
	})

	t.Run("string field with non-string value returns error", func(t *testing.T) {
		_, err := eip712.Types{}.EncodeField("string", 42)
		require.Error(t, err)
		require.Contains(t, err.Error(), "string field")
	})

	t.Run("bool field with non-bool value returns error", func(t *testing.T) {
		_, err := eip712.Types{}.EncodeField("bool", "true")
		require.Error(t, err)
		require.Contains(t, err.Error(), "bool field")
	})

	t.Run("unsupported type returns error", func(t *testing.T) {
		_, err := eip712.Types{}.EncodeField("tuple", "value")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported type")
	})
}

// TestEIP712HashTypedData_SpecVectors verifies the full EIP-712 hashing pipeline against
// the canonical example at https://eips.ethereum.org/assets/eip-712/Example.js.
func TestEIP712HashTypedData_SpecVectors(t *testing.T) {
	domain := eip712.EIP712Domain{
		Name:              "Ether Mail",
		Version:           "1",
		ChainId:           big.NewInt(1),
		VerifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
	}
	message := eip712.EIP712Message{
		"from": map[string]interface{}{
			"name":   "Cow",
			"wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
		},
		"to": map[string]interface{}{
			"name":   "Bob",
			"wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
		},
		"contents": "Hello, Bob!",
	}
	typedData := eip712.TypedData{
		Types:       specTypes,
		PrimaryType: "Mail",
		Domain:      domain,
		Message:     message,
	}

	t.Run("encodeType", func(t *testing.T) {
		got, err := specTypes.EncodeType("Mail")
		require.NoError(t, err)
		require.Equal(t, "Mail(Person from,Person to,string contents)Person(string name,address wallet)", got)
	})

	t.Run("typeHash", func(t *testing.T) {
		got, err := specTypes.TypeHash("Mail")
		require.NoError(t, err)
		require.Equal(t, "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2", hex.EncodeToString(got))
	})

	t.Run("domain separator", func(t *testing.T) {
		got, err := specTypes.HashStruct("EIP712Domain", map[string]interface{}{
			"name":              "Ether Mail",
			"version":           "1",
			"chainId":           big.NewInt(1),
			"verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
		})
		require.NoError(t, err)
		require.Equal(t, "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f", hex.EncodeToString(got))
	})

	t.Run("struct hash and sign hash", func(t *testing.T) {
		structHash, signHash, err := eip712.HashTypedData(typedData)
		require.NoError(t, err)
		require.Equal(t, "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e", hex.EncodeToString(structHash))
		require.Equal(t, "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2", hex.EncodeToString(signHash))
	})
}

func TestEIP712DomainUnmarshalJSON(t *testing.T) {
	t.Run("hex string chainId", func(t *testing.T) {
		var d eip712.EIP712Domain
		require.NoError(t, json.Unmarshal([]byte(`{"name":"Test","chainId":"0x1"}`), &d))
		require.NotNil(t, d.ChainId)
		require.Equal(t, int64(1), d.ChainId.Int64())
	})

	t.Run("decimal string chainId", func(t *testing.T) {
		var d eip712.EIP712Domain
		require.NoError(t, json.Unmarshal([]byte(`{"name":"Test","chainId":"1337"}`), &d))
		require.NotNil(t, d.ChainId)
		require.Equal(t, int64(1337), d.ChainId.Int64())
	})

	t.Run("numeric chainId", func(t *testing.T) {
		var d eip712.EIP712Domain
		require.NoError(t, json.Unmarshal([]byte(`{"name":"Test","chainId":1}`), &d))
		require.NotNil(t, d.ChainId)
		require.Equal(t, int64(1), d.ChainId.Int64())
	})

	t.Run("absent chainId field is nil", func(t *testing.T) {
		var d eip712.EIP712Domain
		require.NoError(t, json.Unmarshal([]byte(`{"name":"Test"}`), &d))
		require.Nil(t, d.ChainId)
		require.Equal(t, "Test", d.Name)
	})

	t.Run("all optional fields populated", func(t *testing.T) {
		var d eip712.EIP712Domain
		input := `{"name":"A","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC","salt":"0xdeadbeef"}`
		require.NoError(t, json.Unmarshal([]byte(input), &d))
		require.Equal(t, "A", d.Name)
		require.Equal(t, "1", d.Version)
		require.Equal(t, int64(1), d.ChainId.Int64())
		require.Equal(t, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC", d.VerifyingContract)
		require.Equal(t, "0xdeadbeef", d.Salt)
	})

	t.Run("null chainId field is nil", func(t *testing.T) {
		var d eip712.EIP712Domain
		require.NoError(t, json.Unmarshal([]byte(`{"name":"Test","chainId":null}`), &d))
		require.Nil(t, d.ChainId)
	})

	t.Run("invalid hex chainId returns error", func(t *testing.T) {
		var d eip712.EIP712Domain
		require.Error(t, json.Unmarshal([]byte(`{"chainId":"0xgg"}`), &d))
	})

	t.Run("invalid decimal string chainId returns error", func(t *testing.T) {
		var d eip712.EIP712Domain
		require.Error(t, json.Unmarshal([]byte(`{"chainId":"abc"}`), &d))
	})
}

func TestTypedDataValidate(t *testing.T) {
	validTypes := eip712.Types{
		"EIP712Domain": {{Name: "name", Type: "string"}},
		"Mail":         {{Name: "contents", Type: "string"}},
	}

	t.Run("valid", func(t *testing.T) {
		td := eip712.TypedData{Types: validTypes, PrimaryType: "Mail"}
		require.NoError(t, td.Validate())
	})

	t.Run("empty typed data is rejected", func(t *testing.T) {
		require.Error(t, eip712.TypedData{}.Validate())
	})

	t.Run("empty primaryType", func(t *testing.T) {
		td := eip712.TypedData{Types: validTypes, PrimaryType: ""}
		require.Error(t, td.Validate())
	})

	t.Run("primaryType not declared in types", func(t *testing.T) {
		td := eip712.TypedData{Types: validTypes, PrimaryType: "Unknown"}
		require.Error(t, td.Validate())
	})

	t.Run("missing EIP712Domain definition", func(t *testing.T) {
		td := eip712.TypedData{
			Types:       eip712.Types{"Mail": {{Name: "contents", Type: "string"}}},
			PrimaryType: "Mail",
		}
		require.Error(t, td.Validate())
	})
}

// TestEIP712EncodeInteger_Precision guards against silently signing the wrong value for integers around
// the float64 boundary. 2^53+1 cannot be represented exactly as float64 (it rounds to 2^53), so it must
// be carried as json.Number to encode exactly, and the float64 path at that magnitude must be rejected
// rather than rounded.
func TestEIP712EncodeInteger_Precision(t *testing.T) {
	encodeExpected := func(decimal string) []byte {
		i, ok := new(big.Int).SetString(decimal, 10)
		require.True(t, ok)
		out := make([]byte, 32)
		b := i.Bytes()
		copy(out[32-len(b):], b)
		return out
	}

	t.Run("json.Number preserves 2^53+1 exactly", func(t *testing.T) {
		got, err := eip712.Types{}.EncodeField("uint256", json.Number("9007199254740993"))
		require.NoError(t, err)
		require.Equal(t, encodeExpected("9007199254740993"), got)
	})

	t.Run("json.Number preserves a full-width uint256", func(t *testing.T) {
		const maxUint256 = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
		got, err := eip712.Types{}.EncodeField("uint256", json.Number(maxUint256))
		require.NoError(t, err)
		require.Equal(t, encodeExpected(maxUint256), got)
	})

	t.Run("float64 at or above 2^53 is rejected, not rounded", func(t *testing.T) {
		_, err := eip712.Types{}.EncodeField("uint256", float64(9007199254740993))
		require.Error(t, err)
		require.Contains(t, err.Error(), "float64 precision")
	})

	t.Run("float64 below 2^53 still encodes", func(t *testing.T) {
		got, err := eip712.Types{}.EncodeField("uint256", float64(42))
		require.NoError(t, err)
		require.Equal(t, encodeExpected("42"), got)
	})

	t.Run("invalid decimal string is rejected instead of signing zero", func(t *testing.T) {
		_, err := eip712.Types{}.EncodeField("uint256", "not-a-number")
		require.Error(t, err)
	})

	t.Run("json.Number that is not an integer is rejected", func(t *testing.T) {
		_, err := eip712.Types{}.EncodeField("uint256", json.Number("1.5"))
		require.Error(t, err)
	})
}
