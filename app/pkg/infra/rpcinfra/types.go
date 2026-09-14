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
	if err := json.Unmarshal(reqParams, rpcParams); err != nil {
		// If the unmarshall fails, we try to unmarshall it into an interface and set the JSONRPCParams from there.
		posParams := make([]any, 0)
		if err = json.Unmarshal(reqParams, &posParams); err != nil {
			return rpcerrors.NewInvalidParamsFromErr(err)
		}
		if err = rpcParams.SetParamsFrom(posParams); err != nil {
			return rpcerrors.NewInvalidParamsFromErr(err)
		}
	}
	return nil
}

// SingleParamsObject returns the one object a params payload carries, accepting both the positional
// array form ([{...}]) and the bare object form ({...}), and rejects an object that names a field
// ambiguously.
//
// Every party that reads the signing account out of a request has to agree on which account it is, or
// the policy enforcement point authorizes one account and the handler signs with another. The two
// still decode the payload separately; what this removes is the input on which their decodes disagree.
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

// rejectAmbiguousParams fails if a params payload carries a single object that names a field
// ambiguously. A payload of any other shape is passed over, so a method taking no params, or params
// this package does not model as one object, is left to its own decoding.
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
// encoding/json decides that a key matches a struct field.
//
// Such an object decodes two ways. A struct decode keeps the last matching key, so {"from":a,"From":b}
// yields b, while a map[string]any decode keeps both and a lookup of "from" yields a. Refusing the
// object is the only resolution that cannot be read two ways.
//
// Only the object's own keys are checked. Values are skipped whole, because nested objects carry
// caller data, an EIP-712 message among them, where two keys differing by case are distinct and
// legitimate.
//
// Keys are attacker-controlled and bounded only by the request body limit, so the scan is a single
// pass with a map lookup per key. Comparing each key against every earlier one would be quadratic in
// a value the caller chooses.
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

// foldName canonicalises a key the way encoding/json does when matching it to a struct field: ASCII
// letters upper-cased, every other rune replaced by the lowest rune in its Unicode simple-fold orbit.
// Two keys match the same field exactly when their folded names are equal, so one map keyed by the
// folded name detects a collision in a single pass.
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

// foldRune returns the lowest rune in r's simple-fold orbit. unicode.SimpleFold walks the orbit in
// increasing order and wraps round to its smallest member, so the first value that does not increase
// is that member.
func foldRune(r rune) rune {
	for {
		next := unicode.SimpleFold(r)
		if next <= r {
			return next
		}
		r = next
	}
}

// maxReportedFieldNameRunes bounds how much of a key name is reported back. Names are caller-supplied
// and bounded only by the request body limit, and this error reaches the server log, so the name is
// truncated here and quoted by the caller so that control characters cannot break up a log line.
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
