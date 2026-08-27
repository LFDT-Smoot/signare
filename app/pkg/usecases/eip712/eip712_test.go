package eip712_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/usecases/eip712"
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

// domainOnlyTypes is a minimal valid EIP712Domain definition, used by the unbounded-recursion tests
// so each case declares only the types under test.
func domainOnlyTypes() eip712.Types {
	return eip712.Types{
		"EIP712Domain": []eip712.Type{{Name: "name", Type: "string"}},
	}
}

func hashTypedDataFor(types eip712.Types, primaryType string, message eip712.EIP712Message) (eip712.TypedData, error) {
	data := eip712.TypedData{
		Types:       types,
		PrimaryType: primaryType,
		Domain:      eip712.EIP712Domain{Name: "test"},
		Message:     message,
	}
	return data, data.Validate()
}

// A type that refers to itself has no finite encoding. Before the fix, Validate passed it and
// HashTypedData recursed until the goroutine stack overflowed, which is a Go fatal error that
// recover cannot intercept, so it took the whole process down.
func TestTypedDataValidate_RejectsSelfReferencingType(t *testing.T) {
	types := domainOnlyTypes()
	types["Loop"] = []eip712.Type{{Name: "self", Type: "Loop"}}

	_, err := hashTypedDataFor(types, "Loop", eip712.EIP712Message{})

	require.Error(t, err)
	require.Contains(t, err.Error(), "cyclic definition")
	require.Contains(t, err.Error(), "Loop")
}

func TestTypedDataValidate_RejectsIndirectCycle(t *testing.T) {
	types := domainOnlyTypes()
	types["A"] = []eip712.Type{{Name: "b", Type: "B"}}
	types["B"] = []eip712.Type{{Name: "c", Type: "C"}}
	types["C"] = []eip712.Type{{Name: "a", Type: "A"}}

	_, err := hashTypedDataFor(types, "A", eip712.EIP712Message{})

	require.Error(t, err)
	require.Contains(t, err.Error(), "cyclic definition")
}

// Array notation must not hide a cycle: Node.children is Node[], so the base type still refers back.
func TestTypedDataValidate_RejectsCycleThroughArrayType(t *testing.T) {
	types := domainOnlyTypes()
	types["Node"] = []eip712.Type{{Name: "children", Type: "Node[]"}}

	_, err := hashTypedDataFor(types, "Node", eip712.EIP712Message{})

	require.Error(t, err)
	require.Contains(t, err.Error(), "cyclic definition")
}

// A cycle reachable only through the domain type is rejected too, since the domain separator is
// encoded on every digest.
func TestTypedDataValidate_RejectsCycleReachableFromDomain(t *testing.T) {
	types := eip712.Types{
		"EIP712Domain": []eip712.Type{{Name: "meta", Type: "Meta"}},
		"Meta":         []eip712.Type{{Name: "self", Type: "Meta"}},
		"Msg":          []eip712.Type{{Name: "text", Type: "string"}},
	}

	_, err := hashTypedDataFor(types, "Msg", eip712.EIP712Message{"text": "hi"})

	require.Error(t, err)
	require.Contains(t, err.Error(), "cyclic definition")
}

// A cyclic type that neither the domain nor the primary type can reach is never encoded, so it is
// left alone rather than failing a payload that would hash correctly.
func TestTypedDataValidate_AllowsUnreachableCycle(t *testing.T) {
	types := domainOnlyTypes()
	types["Msg"] = []eip712.Type{{Name: "text", Type: "string"}}
	types["Orphan"] = []eip712.Type{{Name: "self", Type: "Orphan"}}

	data, err := hashTypedDataFor(types, "Msg", eip712.EIP712Message{"text": "hi"})
	require.NoError(t, err)

	_, _, hashErr := eip712.HashTypedData(data)
	require.NoError(t, hashErr)
}

// A diamond is not a cycle: Top reaches Leaf by two distinct paths and must still encode.
func TestTypedDataValidate_AllowsDiamondDependency(t *testing.T) {
	types := domainOnlyTypes()
	types["Top"] = []eip712.Type{{Name: "left", Type: "Mid1"}, {Name: "right", Type: "Mid2"}}
	types["Mid1"] = []eip712.Type{{Name: "leaf", Type: "Leaf"}}
	types["Mid2"] = []eip712.Type{{Name: "leaf", Type: "Leaf"}}
	types["Leaf"] = []eip712.Type{{Name: "text", Type: "string"}}

	message := eip712.EIP712Message{
		"left":  map[string]interface{}{"leaf": map[string]interface{}{"text": "l"}},
		"right": map[string]interface{}{"leaf": map[string]interface{}{"text": "r"}},
	}
	data, err := hashTypedDataFor(types, "Top", message)
	require.NoError(t, err)

	_, _, hashErr := eip712.HashTypedData(data)
	require.NoError(t, hashErr)
}

// The headline vector the cycle check does not catch: an acyclic, shallow type graph whose encoding
// still expands exponentially. Eleven types with a fanout of eight is roughly 8^10 struct encodings
// from about 2.4 KB of type definitions. Only the total-work budget stops this.
func TestHashTypedData_RejectsExponentialTypeExpansion(t *testing.T) {
	const levels = 10
	const fanout = 8

	types := domainOnlyTypes()
	for level := 0; level < levels; level++ {
		fields := make([]eip712.Type, fanout)
		for field := 0; field < fanout; field++ {
			fields[field] = eip712.Type{
				Name: fmt.Sprintf("f%d", field),
				Type: fmt.Sprintf("T%d", level+1),
			}
		}
		types[fmt.Sprintf("T%d", level)] = fields
	}
	// A zero-field struct is a legal type and, unlike every scalar, encodes successfully from a nil
	// value. That is what lets all 8^10 branches bottom out instead of erroring at the first leaf.
	types[fmt.Sprintf("T%d", levels)] = []eip712.Type{}

	data, err := hashTypedDataFor(types, "T0", eip712.EIP712Message{})
	require.NoError(t, err, "an acyclic graph must pass validation; the budget is what stops it")

	_, _, hashErr := eip712.HashTypedData(data)
	require.Error(t, hashErr)
	require.Contains(t, hashErr.Error(), "struct encodings")
}

// The depth cap backstops nesting that comes from the message rather than the type graph, which the
// cycle check cannot see.
func TestHashTypedData_RejectsExcessiveArrayNesting(t *testing.T) {
	const depth = 40

	arrayType := "string"
	for i := 0; i < depth; i++ {
		arrayType += "[]"
	}
	types := domainOnlyTypes()
	types["Msg"] = []eip712.Type{{Name: "deep", Type: arrayType}}

	var value interface{} = "leaf"
	for i := 0; i < depth; i++ {
		value = []interface{}{value}
	}

	data, err := hashTypedDataFor(types, "Msg", eip712.EIP712Message{"deep": value})
	require.NoError(t, err)

	_, _, hashErr := eip712.HashTypedData(data)
	require.Error(t, hashErr)
	require.Contains(t, hashErr.Error(), "maximum depth")
}

// A type string ending in a closing bracket with no opening one is not array notation. Before the
// fix it reached fieldType[:strings.LastIndex(fieldType, "[")] with an index of -1 and panicked.
func TestEncodeField_MalformedArrayTypeReturnsError(t *testing.T) {
	for _, fieldType := range []string{"]", "foo]", "uint256]"} {
		t.Run(fieldType, func(t *testing.T) {
			types := domainOnlyTypes()
			types["Msg"] = []eip712.Type{{Name: "x", Type: fieldType}}

			data, err := hashTypedDataFor(types, "Msg", eip712.EIP712Message{"x": "anything"})
			require.NoError(t, err)

			require.NotPanics(t, func() {
				_, _, hashErr := eip712.HashTypedData(data)
				require.Error(t, hashErr)
				require.Contains(t, hashErr.Error(), "unsupported type")
			})
		})
	}
}

// fanoutChain adds a chain of types named prefix0..prefixN where each level has `fanout` fields of
// the next, and the last level is a zero-field struct. Encoding prefix0 from a nil value costs
// (fanout^(levels+1) - 1) / (fanout - 1) struct encodings, so it is a way to spend a chosen,
// calculable amount of the budget.
func fanoutChain(types eip712.Types, prefix string, levels, fanout int) string {
	for level := 0; level < levels; level++ {
		fields := make([]eip712.Type, fanout)
		for field := 0; field < fanout; field++ {
			fields[field] = eip712.Type{
				Name: fmt.Sprintf("f%d", field),
				Type: fmt.Sprintf("%s%d", prefix, level+1),
			}
		}
		types[fmt.Sprintf("%s%d", prefix, level)] = fields
	}
	types[fmt.Sprintf("%s%d", prefix, levels)] = []eip712.Type{}
	return prefix + "0"
}

// The budget spans a whole digest rather than resetting per struct, so it cannot be doubled by
// splitting the work across the domain separator and the message.
//
// This is built so each half alone stays under the budget while the two together exceed it: the
// domain and the message each carry an identical expansion. If the state were created per hashStruct
// rather than per HashTypedData, both halves would fit and no error would be raised.
func TestHashTypedData_BudgetIsSharedAcrossDomainAndMessage(t *testing.T) {
	// (9^6-1)/8 = 66430 struct encodings per half: under maxStructEncodings alone, over it combined.
	const levels, fanout = 5, 9

	// One half on its own must succeed, otherwise the combined case proves nothing.
	t.Run("one half alone is under the budget", func(t *testing.T) {
		types := eip712.Types{"EIP712Domain": []eip712.Type{{Name: "name", Type: "string"}}}
		primary := fanoutChain(types, "M", levels, fanout)

		data, err := hashTypedDataFor(types, primary, eip712.EIP712Message{})
		require.NoError(t, err)

		_, _, hashErr := eip712.HashTypedData(data)
		require.NoError(t, hashErr, "one half must fit within the budget on its own")
	})

	t.Run("both halves together exceed it", func(t *testing.T) {
		types := eip712.Types{}
		domainHeavy := fanoutChain(types, "D", levels, fanout)
		primary := fanoutChain(types, "M", levels, fanout)
		// The domain separator hashes EIP712Domain, and toFieldMap never supplies this field, so it
		// expands from a nil value exactly like the message half does.
		types["EIP712Domain"] = []eip712.Type{{Name: "heavy", Type: domainHeavy}}

		data, err := hashTypedDataFor(types, primary, eip712.EIP712Message{})
		require.NoError(t, err)

		_, _, hashErr := eip712.HashTypedData(data)
		require.Error(t, hashErr, "a shared budget must reject what two independent budgets would allow")
		require.Contains(t, hashErr.Error(), "struct encodings")
	})
}

// The depth cap has to reject the explosive case without rejecting legitimate nesting, so pin both
// sides of the boundary. Without these, a future > / >= slip at the edge would go unnoticed.
func TestHashTypedData_DepthBoundary(t *testing.T) {
	// nestedChain builds primary -> L1 -> ... -> L(depth-1) -> string, i.e. `depth` encodeField levels.
	nestedChain := func(depth int) (eip712.Types, string, eip712.EIP712Message) {
		types := domainOnlyTypes()
		for level := 1; level < depth; level++ {
			types[fmt.Sprintf("L%d", level)] = []eip712.Type{
				{Name: "n", Type: fmt.Sprintf("L%d", level+1)},
			}
		}
		types[fmt.Sprintf("L%d", depth)] = []eip712.Type{{Name: "leaf", Type: "string"}}

		message := eip712.EIP712Message{"leaf": "bottom"}
		for level := depth; level > 1; level-- {
			message = eip712.EIP712Message{"n": map[string]interface{}(message)}
		}
		return types, "L1", message
	}

	t.Run("at the limit it still encodes", func(t *testing.T) {
		types, primary, message := nestedChain(32)
		data, err := hashTypedDataFor(types, primary, message)
		require.NoError(t, err)

		_, _, hashErr := eip712.HashTypedData(data)
		require.NoError(t, hashErr, "32 levels is the documented limit and must be accepted")
	})

	t.Run("one past the limit is rejected", func(t *testing.T) {
		types, primary, message := nestedChain(33)
		data, err := hashTypedDataFor(types, primary, message)
		require.NoError(t, err)

		_, _, hashErr := eip712.HashTypedData(data)
		require.Error(t, hashErr)
		require.Contains(t, hashErr.Error(), "maximum depth")
	})
}

// Memoizing the per-type hash must not change any digest: it is a cost optimisation, not a semantic
// one. A message that encodes the same type many times is where a broken cache would show up.
func TestHashTypedData_RepeatedTypeEncodesConsistently(t *testing.T) {
	types := domainOnlyTypes()
	types["Item"] = []eip712.Type{{Name: "v", Type: "string"}}
	types["Bag"] = []eip712.Type{{Name: "items", Type: "Item[]"}}

	single, err := hashTypedDataFor(types, "Bag", eip712.EIP712Message{
		"items": []interface{}{map[string]interface{}{"v": "a"}},
	})
	require.NoError(t, err)
	_, singleDigest, hashErr := eip712.HashTypedData(single)
	require.NoError(t, hashErr)

	repeated, err := hashTypedDataFor(types, "Bag", eip712.EIP712Message{
		"items": []interface{}{
			map[string]interface{}{"v": "a"},
			map[string]interface{}{"v": "a"},
		},
	})
	require.NoError(t, err)
	_, repeatedDigest, hashErr := eip712.HashTypedData(repeated)
	require.NoError(t, hashErr)

	require.NotEqual(t, hex.EncodeToString(singleDigest), hex.EncodeToString(repeatedDigest),
		"a second element must change the digest; equality would mean the cache elided real work")
}
