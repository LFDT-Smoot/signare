package rpcinfra

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/lfdt-smoot/signare/app/pkg/infra/httpinfra"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra/rpcerrors"

	"github.com/gorilla/mux"
)

const (
	SupportedRPCVersion = "2.0"
)

// RPCHandler defines JSON-RPC method handler functions
type RPCHandler func(ctx context.Context, request RPCRequest) (any, *rpcerrors.RPCError)

// DefaultRPCRouter defines a JSON-RPC router that handles multiple requests.
type DefaultRPCRouter struct {
	// Router for HTTP
	router *mux.Router
	// rpcHandlers registered JSON-RPC method handlers
	rpcHandlers map[string]RPCHandler
	// defaultRPCInfraResponseHandler handles the RPC responses of the server
	defaultRPCInfraResponseHandler httpinfra.HTTPResponseHandler
}

// RPCRequest represents a JSON-RPC request object as defined in: https://www.jsonrpc.org/specification
type RPCRequest struct {
	// RPCVersion specifies the version of the JSON-RPC protocol. Must be exactly "2.0".
	RPCVersion string `json:"jsonrpc"`
	// ID defines a unique identifier established by the client.
	ID any `json:"id"`
	// Method defines the name of the method to be invoked.
	Method string `json:"method"`
	// Params defines a structured value that holds the parameter values to be used during the invocation of the method.
	Params json.RawMessage `json:"params"`
}

// RPCResponse represents a JSON-RPC response object as defined in: https://www.jsonrpc.org/specification
type RPCResponse struct {
	// RPCVersion specifies the version of the JSON-RPC protocol. Must be exactly "2.0".
	RPCVersion string `json:"jsonrpc"`
	// ID contains the client established request id or null.
	ID any `json:"id"`
	// Error contains the error if there was an error triggered during the request.
	Error *rpcerrors.RPCError `json:"error,omitempty"`
	// Result contains the result of the called method.
	// It MUST be defined in a successful response, and it MUST not be defined if there was an error triggered
	// during the request.
	Result any `json:"result,omitempty"`
}

// JSONRPCParams defines methods for processing JSON-RPC request parameters.
type JSONRPCParams interface {
	// SetParamsFrom validates the request parameters against the provided interface and if the validation is correct,
	// completes the JSONRPCParams with the interface values.
	SetParamsFrom([]any) error
	// ValidateParams checks if all the parameters are defined in the JSONRPCParams struct and if the validation fails,
	// it returns an error.
	ValidateParams() error
}

// ProcessParams processes the params data structure from the RPCRequest.
func ProcessParams(reqParams json.RawMessage, rpcParams JSONRPCParams) *rpcerrors.RPCError {
	// Checked before anything decodes the payload, because which of the two decodes below runs
	// determines how an ambiguously named field resolves.
	if err := rejectAmbiguousParams(reqParams); err != nil {
		return rpcerrors.NewInvalidParamsFromErr(err)
	}
	err := json.Unmarshal(reqParams, rpcParams)
	if err == nil {
		return nil
	}
	if _, decodesBothForms := rpcParams.(json.Unmarshaler); decodesBothForms {
		// The type already accepts every shape SetParamsFrom would, so its error is the final word.
		// Falling through would replace a message naming the offending field with a generic one.
		return rpcerrors.NewInvalidParamsFromErr(paramsDecodeError(err))
	}
	// If the unmarshall fails, we try to unmarshall it into an interface and set the JSONRPCParams from there.
	posParams := make([]any, 0)
	if err = json.Unmarshal(reqParams, &posParams); err != nil {
		return rpcerrors.NewInvalidParamsFromErr(err)
	}
	if err = rpcParams.SetParamsFrom(posParams); err != nil {
		return rpcerrors.NewInvalidParamsFromErr(err)
	}
	return nil
}

// paramsDecodeError names the offending field for a type mismatch, matching the per-field messages
// the positional decode used to produce, and keeps encoding/json's internal type names out of the
// response. Any other failure is reported as-is.
func paramsDecodeError(err error) error {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) && typeErr.Field != "" {
		return fmt.Errorf("[%s] must be of type %s", typeErr.Field, typeErr.Type)
	}
	return err
}

// SingleParamsObject returns the one object a params payload carries, from either the positional array
// form ([{...}]) or the bare object form ({...}), and rejects an object that names a field twice.
// Authorization and signing both resolve the account through it, so they cannot read a different one.
func SingleParamsObject(params json.RawMessage) (json.RawMessage, error) {
	object := paramsObject(params)
	if object == nil {
		return nil, errors.New("a single object is expected")
	}
	if err := rejectAmbiguousFieldNames(object); err != nil {
		return nil, err
	}
	return object, nil
}

// rejectAmbiguousParams fails if the payload is a single object naming a field twice. Any other shape
// is passed over, so a method taking no params is unaffected.
func rejectAmbiguousParams(params json.RawMessage) error {
	object := paramsObject(params)
	if object == nil {
		return nil
	}
	return rejectAmbiguousFieldNames(object)
}

// paramsObject returns the single JSON object a params payload carries, or nil if it does not carry
// exactly one.
func paramsObject(params json.RawMessage) json.RawMessage {
	object := bytes.TrimSpace(params)
	if len(object) > 0 && object[0] == '[' {
		var positional []json.RawMessage
		if err := json.Unmarshal(object, &positional); err != nil || len(positional) != 1 {
			return nil
		}
		object = bytes.TrimSpace(positional[0])
	}
	if len(object) == 0 || object[0] != '{' {
		return nil
	}
	return object
}

// rejectAmbiguousFieldNames fails if two of an object's keys fold to the same name, which is how
// encoding/json matches a key to a struct field. Such an object decodes two ways, so it is refused
// rather than resolved.
//
// Only the object's own keys are checked; values are skipped whole, since nested caller data such as
// an EIP-712 message may legitimately differ only by case. Keys are caller-supplied and bounded only
// by the body limit, so the scan is one pass with a map lookup, never a pairwise comparison.
func rejectAmbiguousFieldNames(object json.RawMessage) error {
	decoder := json.NewDecoder(bytes.NewReader(object))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return errors.New("a single object is expected")
	}

	seen := make(map[string]string)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return errors.New("a single object is expected")
		}
		folded := foldName(name)
		if previous, duplicate := seen[folded]; duplicate {
			return fmt.Errorf("params name the same field twice: %q and %q",
				truncateFieldName(previous), truncateFieldName(name))
		}
		seen[folded] = name

		var value json.RawMessage
		if err = decoder.Decode(&value); err != nil {
			return err
		}
	}
	return nil
}

// foldName canonicalises a key as encoding/json does: ASCII letters upper-cased, every other rune
// replaced by the lowest in its simple-fold orbit. Equal folded names means the same struct field.
func foldName(name string) string {
	var folded strings.Builder
	folded.Grow(len(name))
	for _, r := range name {
		switch {
		case 'a' <= r && r <= 'z':
			r -= 'a' - 'A'
		case r >= utf8.RuneSelf:
			r = foldRune(r)
		}
		folded.WriteRune(r)
	}
	return folded.String()
}

// foldRune returns the lowest rune in r's simple-fold orbit. SimpleFold walks the orbit upwards and
// wraps to its smallest member, so the first value that does not increase is that member.
func foldRune(r rune) rune {
	for {
		next := unicode.SimpleFold(r)
		if next <= r {
			return next
		}
		r = next
	}
}

// maxReportedFieldNameRunes bounds how much of a caller-supplied key name reaches the server log. The
// caller quotes it too, so control characters cannot break up a log line.
const maxReportedFieldNameRunes = 64

func truncateFieldName(name string) string {
	runes := 0
	for i := range name {
		runes++
		if runes > maxReportedFieldNameRunes {
			return name[:i] + "..."
		}
	}
	return name
}
