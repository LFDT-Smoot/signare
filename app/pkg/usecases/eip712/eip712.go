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

// eip712DomainType is the name of the mandatory domain type, whose hash forms the domain separator.
const eip712DomainType = "EIP712Domain"

const (
	// maxTypeDepth bounds how deep the struct and array encoding walk may descend. Real EIP-712
	// payloads nest a handful of levels, so this is far beyond any legitimate message while keeping
	// the walk's stack usage bounded. Validate rejects cyclic types before encoding starts; this is
	// the backstop for the paths that reach the encoder without it, and for deeply nested arrays,
	// whose depth comes from the message rather than from the type graph.
	maxTypeDepth = 32
	// maxStructEncodings bounds the total number of struct encodings performed for one digest. A type
	// graph can be acyclic and shallow yet expand exponentially: a type with N struct-typed fields
	// repeated to depth D encodes N^D structs, which a cycle check and a depth cap both pass. A few
	// kilobytes of type definitions are enough to make that expansion effectively unbounded, so the
	// total work has to be capped in its own right.
	//
	// The limit is set well above what the 1 MiB entrypoint body cap can legitimately ask for, since a
	// message is at least a few bytes per encoded struct, so a well-formed payload cannot reach it. It
	// is far below the exponential case, which runs to the billions. Each encoding is cheap because the
	// type hash is memoized per digest (see encodeState.typeHashes), so the ceiling bounds total work
	// rather than merely the count.
	maxStructEncodings = 100000
)

// encodeState carries the per-digest limits across the mutually recursive encoding walk. One state
// spans a whole HashTypedData call, so the domain separator and the message share a single budget.
type encodeState struct {
	depth  int
	budget int
	// typeHashes memoizes keccak256(encodeType(name)) for the duration of one digest.
	typeHashes map[string][]byte
}

func newEncodeState() *encodeState {
	return &encodeState{budget: maxStructEncodings, typeHashes: make(map[string][]byte)}
}

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
// EIP-712 digest: a non-empty primaryType that is present in Types, an EIP712Domain type
// definition, and an acyclic type graph. Without these, HashTypedData hashes a degenerate empty
// structure, or fails to terminate, instead of rejecting the input. It does not re-derive the
// encoding; HashStruct still surfaces deeper errors.
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
	if _, ok := d.Types[eip712DomainType]; !ok {
		return errors.New("typed data types missing the EIP712Domain definition")
	}
	// A struct type that refers back to itself, directly or through a chain, has no finite encoding:
	// hashStruct would descend into it forever. Only the two types actually encoded are walked, so an
	// unreachable cyclic definition is left alone rather than failing a payload that would encode fine.
	for _, root := range []string{eip712DomainType, d.PrimaryType} {
		if cycle := d.Types.findCycle(root); cycle != "" {
			return fmt.Errorf("typed data types contain a cyclic definition: %s", cycle)
		}
	}
	return nil
}

// findCycle returns a human-readable path describing the first cycle reachable from root in the
// struct-type graph, or an empty string when the reachable graph is acyclic. Non-struct field types
// and references to undeclared types are leaves.
func (t Types) findCycle(root string) string {
	onPath := make(map[string]bool)
	settled := make(map[string]bool)
	return t.findCycleFrom(root, nil, onPath, settled)
}

func (t Types) findCycleFrom(typeName string, path []string, onPath, settled map[string]bool) string {
	if onPath[typeName] {
		return strings.Join(append(path, typeName), " -> ")
	}
	if settled[typeName] || t[typeName] == nil {
		return ""
	}
	onPath[typeName] = true
	path = append(path, typeName)
	for _, field := range t[typeName] {
		if cycle := t.findCycleFrom(baseTypeName(field.Type), path, onPath, settled); cycle != "" {
			return cycle
		}
	}
	onPath[typeName] = false
	settled[typeName] = true
	return ""
}

// baseTypeName strips array notation, so "Person[2][]" resolves to the struct type "Person".
func baseTypeName(fieldType string) string {
	if i := strings.Index(fieldType, "["); i != -1 {
		return fieldType[:i]
	}
	return fieldType
}

func hashKeccak256(data []byte) ([]byte, error) {
	d := sha3.NewLegacyKeccak256()
	if _, err := d.Write(data); err != nil {
		return nil, err
	}
	return d.Sum(nil), nil
}

// HashStruct returns the keccak256 hash of the ABI-encoded struct (typeHash || encodeData).
//
// The walk is bounded by maxTypeDepth and maxStructEncodings and returns an error rather than
// recursing without limit, so a cyclic or explosively wide type graph is rejected instead of
// exhausting the goroutine stack. Each call starts a fresh budget.
func (t Types) HashStruct(primaryType string, data map[string]interface{}) ([]byte, error) {
	return t.hashStruct(primaryType, data, newEncodeState())
}

func (t Types) hashStruct(primaryType string, data map[string]interface{}, state *encodeState) ([]byte, error) {
	encodedData, err := t.encodeData(primaryType, data, state)
	if err != nil {
		return nil, err
	}
	return hashKeccak256(encodedData)
}

// EncodeData returns typeHash concatenated with the ABI encoding of each field value.
//
// Bounded by maxTypeDepth and maxStructEncodings; see HashStruct. Each call starts a fresh budget.
func (t Types) EncodeData(primaryType string, data map[string]interface{}) ([]byte, error) {
	return t.encodeData(primaryType, data, newEncodeState())
}

// typeHash returns TypeHash(name), reusing the value already computed for this digest if there is one.
//
// Types is immutable while a digest is computed, so the hash of a given type name is stable and caching
// it changes no output. It matters for cost: without it every struct encoding rebuilds and hashes the
// canonical type string, whose length grows with the whole reachable type graph, so a message with many
// structs of the same type multiplies a large hash by the number of encodings.
func (t Types) typeHash(name string, state *encodeState) ([]byte, error) {
	if cached, ok := state.typeHashes[name]; ok {
		return cached, nil
	}
	hash, err := t.TypeHash(name)
	if err != nil {
		return nil, err
	}
	state.typeHashes[name] = hash
	return hash, nil
}

func (t Types) encodeData(primaryType string, data map[string]interface{}, state *encodeState) ([]byte, error) {
	if state.budget <= 0 {
		return nil, fmt.Errorf("typed data expands to more than the maximum of %d struct encodings", maxStructEncodings)
	}
	state.budget--

	var buffer bytes.Buffer
	typeHash, err := t.typeHash(primaryType, state)
	if err != nil {
		return nil, err
	}
	buffer.Write(typeHash)

	fields := t[primaryType]
	for _, field := range fields {
		val := data[field.Name]
		encoded, err := t.encodeField(field.Type, val, state)
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
		baseType := baseTypeName(field.Type)
		if t[baseType] != nil {
			t.findDependencies(baseType, deps)
		}
	}
}

// EncodeField ABI-encodes a single field value according to the EIP-712 encoding rules for fieldType.
//
// Bounded by maxTypeDepth and maxStructEncodings; see HashStruct. Each call starts a fresh budget.
func (t Types) EncodeField(fieldType string, value interface{}) ([]byte, error) {
	return t.encodeField(fieldType, value, newEncodeState())
}

func (t Types) encodeField(fieldType string, value interface{}, state *encodeState) ([]byte, error) {
	if state.depth >= maxTypeDepth {
		return nil, fmt.Errorf("typed data nesting exceeds the maximum depth of %d", maxTypeDepth)
	}
	state.depth++
	defer func() { state.depth-- }()

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
		return t.hashStruct(fieldType, m, state)
	}

	if strings.HasSuffix(fieldType, "]") {
		// Array
		openBracket := strings.LastIndex(fieldType, "[")
		if openBracket < 0 {
			// A closing bracket with no opening one is not array notation; slicing on -1 would panic.
			return nil, fmt.Errorf("unsupported type %s", fieldType)
		}
		subType := fieldType[:openBracket]
		val := reflect.ValueOf(value)
		if val.Kind() != reflect.Slice && val.Kind() != reflect.Array {
			return nil, fmt.Errorf("expected slice/array for %s, got %T", fieldType, value)
		}
		var encoded []byte
		for i := 0; i < val.Len(); i++ {
			fieldEncoded, err := t.encodeField(subType, val.Index(i).Interface(), state)
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
	// One state for the whole digest, so the domain separator and the message share a single budget
	// and a caller cannot double the permitted work by splitting it across the two.
	state := newEncodeState()
	domainSeparator, err := data.Types.hashStruct(eip712DomainType, data.Domain.toFieldMap(), state)
	if err != nil {
		return nil, nil, err
	}
	dataHash, err := data.Types.hashStruct(data.PrimaryType, data.Message, state)
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
