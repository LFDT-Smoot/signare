package eip712

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strings"

	"golang.org/x/crypto/sha3"
)

// TypedData represents the EIP-712 structured data.
type TypedData struct {
	Types       Types         `json:"types"`
	PrimaryType string        `json:"primaryType"`
	Domain      EIP712Domain  `json:"domain"`
	Message     EIP712Message `json:"message"`
}

// Types maps each type name to its ordered list of field definitions.
type Types map[string][]Type

// Type describes a single named field within an EIP-712 struct type.
type Type struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// EIP712Domain holds the signing domain parameters that scope an EIP-712 signature.
type EIP712Domain struct {
	Name              string   `json:"name,omitempty"`
	Version           string   `json:"version,omitempty"`
	ChainId           *big.Int `json:"chainId,omitempty"`
	VerifyingContract string   `json:"verifyingContract,omitempty"`
	Salt              string   `json:"salt,omitempty"`
}

// UnmarshalJSON handles chainId as either a bare JSON integer or a quoted hex/decimal string.
func (d *EIP712Domain) UnmarshalJSON(data []byte) error {
	type Alias EIP712Domain
	aux := &struct {
		ChainId *json.RawMessage `json:"chainId"`
		*Alias
	}{
		Alias: (*Alias)(d),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if aux.ChainId == nil {
		return nil
	}
	raw := strings.TrimSpace(string(*aux.ChainId))
	if raw == "null" {
		return nil
	}
	i := new(big.Int)
	if strings.HasPrefix(raw, "\"") {
		s := raw[1 : len(raw)-1]
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			if _, ok := i.SetString(s[2:], 16); !ok {
				return fmt.Errorf("invalid hex chainId: %s", s)
			}
		} else {
			if _, ok := i.SetString(s, 10); !ok {
				return fmt.Errorf("invalid chainId: %s", s)
			}
		}
	} else {
		if _, ok := i.SetString(raw, 10); !ok {
			return fmt.Errorf("invalid chainId: %s", raw)
		}
	}
	d.ChainId = i
	return nil
}

func (d EIP712Domain) toFieldMap() map[string]interface{} {
	type field struct {
		key string
		val interface{}
		set bool
	}
	defined := []field{
		{"name", d.Name, d.Name != ""},
		{"version", d.Version, d.Version != ""},
		{"chainId", d.ChainId, d.ChainId != nil},
		{"verifyingContract", d.VerifyingContract, d.VerifyingContract != ""},
		{"salt", d.Salt, d.Salt != ""},
	}
	out := make(map[string]interface{})
	for _, f := range defined {
		if f.set {
			out[f.key] = f.val
		}
	}
	return out
}

// EIP712Message is the structured message payload to be signed, keyed by field name.
type EIP712Message map[string]interface{}

// Validate checks that the typed data declares the minimum structure required to compute an
// EIP-712 digest: a non-empty primaryType that is present in Types, and an EIP712Domain type
// definition. Without these, HashTypedData hashes a degenerate empty structure instead of
// rejecting the input. It does not re-derive the encoding; HashStruct still surfaces deeper errors.
func (d TypedData) Validate() error {
	if d.PrimaryType == "" {
		return errors.New("typed data primaryType must not be empty")
	}
	if len(d.Types) == 0 {
		return errors.New("typed data types must not be empty")
	}
	if _, ok := d.Types[d.PrimaryType]; !ok {
		return fmt.Errorf("typed data types missing a definition for primaryType %q", d.PrimaryType)
	}
	if _, ok := d.Types["EIP712Domain"]; !ok {
		return errors.New("typed data types missing the EIP712Domain definition")
	}
	return nil
}

func hashKeccak256(data []byte) ([]byte, error) {
	d := sha3.NewLegacyKeccak256()
	if _, err := d.Write(data); err != nil {
		return nil, err
	}
	return d.Sum(nil), nil
}

// HashStruct returns the keccak256 hash of the ABI-encoded struct (typeHash || encodeData).
func (t Types) HashStruct(primaryType string, data map[string]interface{}) ([]byte, error) {
	encodedData, err := t.EncodeData(primaryType, data)
	if err != nil {
		return nil, err
	}
	return hashKeccak256(encodedData)
}

// EncodeData returns typeHash concatenated with the ABI encoding of each field value.
func (t Types) EncodeData(primaryType string, data map[string]interface{}) ([]byte, error) {
	var buffer bytes.Buffer
	typeHash, err := t.TypeHash(primaryType)
	if err != nil {
		return nil, err
	}
	buffer.Write(typeHash)

	fields := t[primaryType]
	for _, field := range fields {
		val := data[field.Name]
		encoded, err := t.EncodeField(field.Type, val)
		if err != nil {
			return nil, err
		}
		buffer.Write(encoded)
	}

	return buffer.Bytes(), nil
}

// TypeHash returns keccak256(encodeType(primaryType)).
func (t Types) TypeHash(primaryType string) ([]byte, error) {
	encodedType, err := t.EncodeType(primaryType)
	if err != nil {
		return nil, err
	}
	return hashKeccak256([]byte(encodedType))
}

// EncodeType returns the canonical type string for primaryType with all dependencies appended in alphabetical order.
func (t Types) EncodeType(primaryType string) (string, error) {
	deps := t.Dependencies(primaryType)
	// Sort dependencies (alphabetical except primaryType)
	sort.Strings(deps)
	// Move primaryType to the front
	for i, d := range deps {
		if d == primaryType {
			deps = append([]string{primaryType}, append(deps[:i], deps[i+1:]...)...)
			break
		}
	}
	var result strings.Builder
	for _, dep := range deps {
		result.WriteString(dep)
		result.WriteString("(")
		fields := t[dep]
		for i, field := range fields {
			if i > 0 {
				result.WriteString(",")
			}
			result.WriteString(field.Type)
			result.WriteString(" ")
			result.WriteString(field.Name)
		}
		result.WriteString(")")
	}
	return result.String(), nil
}

// Dependencies returns all custom struct types referenced by primaryType, including itself.
func (t Types) Dependencies(primaryType string) []string {
	deps := make(map[string]bool)
	t.findDependencies(primaryType, deps)
	var list []string
	for dep := range deps {
		list = append(list, dep)
	}
	return list
}

func (t Types) findDependencies(primaryType string, deps map[string]bool) {
	if deps[primaryType] {
		return
	}
	fields := t[primaryType]
	if fields == nil {
		return
	}
	deps[primaryType] = true
	for _, field := range fields {
		// Clean type name from array notation
		baseType := field.Type
		if i := strings.Index(baseType, "["); i != -1 {
			baseType = baseType[:i]
		}
		if t[baseType] != nil {
			t.findDependencies(baseType, deps)
		}
	}
}

// EncodeField ABI-encodes a single field value according to the EIP-712 encoding rules for fieldType.
func (t Types) EncodeField(fieldType string, value interface{}) ([]byte, error) {
	if t[fieldType] != nil {
		// Nested struct
		m, ok := value.(map[string]interface{})
		if !ok {
			// Try to handle case where it's already a struct or another type
			j, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal(j, &m); err != nil {
				return nil, err
			}
		}
		return t.HashStruct(fieldType, m)
	}

	if strings.HasSuffix(fieldType, "]") {
		// Array
		subType := fieldType[:strings.LastIndex(fieldType, "[")]
		val := reflect.ValueOf(value)
		if val.Kind() != reflect.Slice && val.Kind() != reflect.Array {
			return nil, fmt.Errorf("expected slice/array for %s, got %T", fieldType, value)
		}
		var encoded []byte
		for i := 0; i < val.Len(); i++ {
			fieldEncoded, err := t.EncodeField(subType, val.Index(i).Interface())
			if err != nil {
				return nil, err
			}
			encoded = append(encoded, fieldEncoded...)
		}
		return hashKeccak256(encoded)
	}

	switch fieldType {
	case "address":
		return encodeAddress(value)
	case "string":
		s, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("string field requires a string value, got %T", value)
		}
		return hashKeccak256([]byte(s))
	case "bytes":
		b, err := decodeBytes(value)
		if err != nil {
			return nil, err
		}
		return hashKeccak256(b)
	case "bool":
		b, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("bool field requires a bool value, got %T", value)
		}
		res := make([]byte, 32)
		if b {
			res[31] = 1
		}
		return res, nil
	}

	if strings.HasPrefix(fieldType, "uint") || strings.HasPrefix(fieldType, "int") {
		return encodeInteger(value)
	}

	if strings.HasPrefix(fieldType, "bytes") && len(fieldType) > 5 {
		b, err := decodeBytes(value)
		if err != nil {
			return nil, err
		}
		res := make([]byte, 32)
		copy(res, b)
		return res, nil
	}

	return nil, fmt.Errorf("unsupported type %s", fieldType)
}

func encodeAddress(value interface{}) ([]byte, error) {
	s, ok := value.(string)
	if !ok {
		return nil, errors.New("address must be a string")
	}
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 20 {
		return nil, fmt.Errorf("invalid address length: %d", len(b))
	}
	res := make([]byte, 32)
	copy(res[12:], b)
	return res, nil
}

func encodeInteger(value interface{}) ([]byte, error) {
	var bi *big.Int
	switch v := value.(type) {
	case string:
		bi = new(big.Int)
		if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
			if _, ok := bi.SetString(v[2:], 16); !ok {
				return nil, fmt.Errorf("invalid hex integer value %q", v)
			}
		} else if _, ok := bi.SetString(v, 10); !ok {
			return nil, fmt.Errorf("invalid integer value %q", v)
		}
	case json.Number:
		// Numbers decoded with json.Decoder.UseNumber arrive here as their exact literal, so integers
		// above 2^53 (which float64 cannot represent exactly) are preserved rather than silently rounded.
		bi = new(big.Int)
		if _, ok := bi.SetString(v.String(), 10); !ok {
			return nil, fmt.Errorf("invalid integer value %q", v.String())
		}
	case float64:
		// float64 cannot represent integers at or above 2^53 exactly, so a value in that range is
		// ambiguous (it may be a rounded larger integer). Reject it and require the caller to pass such
		// values as strings or as json.Number.
		if v >= 1<<53 {
			return nil, errors.New("integer value at or above 2^53 exceeds float64 precision: pass such uint256 values as strings")
		}
		bi = big.NewInt(int64(v))
	case int64:
		bi = big.NewInt(v)
	case int:
		bi = big.NewInt(int64(v))
	case *big.Int:
		bi = v
	default:
		return nil, fmt.Errorf("unsupported integer type %T", value)
	}
	res := make([]byte, 32)
	b := bi.Bytes()
	if bi.Sign() < 0 {
		// For EIP-712 we mostly deal with uint256
		return nil, errors.New("negative integers not supported in this simplified implementation")
	}
	if len(b) > 32 {
		return nil, errors.New("integer overflow")
	}
	copy(res[32-len(b):], b)
	return res, nil
}

func decodeBytes(value interface{}) ([]byte, error) {
	s, ok := value.(string)
	if !ok {
		if b, ok := value.([]byte); ok {
			return b, nil
		}
		return nil, errors.New("bytes must be a string or []byte")
	}
	if strings.HasPrefix(s, "0x") {
		return hex.DecodeString(s[2:])
	}
	return hex.DecodeString(s)
}

// HashTypedData returns (structHash, prefixedHash) where prefixedHash is the final digest to sign:
// keccak256("\x19\x01" || domainSeparator || structHash).
func HashTypedData(data TypedData) ([]byte, []byte, error) {
	domainSeparator, err := data.Types.HashStruct("EIP712Domain", data.Domain.toFieldMap())
	if err != nil {
		return nil, nil, err
	}
	dataHash, err := data.Types.HashStruct(data.PrimaryType, data.Message)
	if err != nil {
		return nil, nil, err
	}

	var buffer bytes.Buffer
	buffer.Write([]byte("\x19\x01"))
	buffer.Write(domainSeparator)
	buffer.Write(dataHash)

	prefixedDataHash, err := hashKeccak256(buffer.Bytes())
	if err != nil {
		return nil, nil, err
	}
	return dataHash, prefixedDataHash, nil
}
