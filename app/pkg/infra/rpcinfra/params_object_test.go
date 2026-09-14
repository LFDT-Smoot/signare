package rpcinfra_test

import (
	"encoding/json"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra"

	"github.com/stretchr/testify/require"
)

func TestSingleParamsObject_UnwrapsBothParamForms(t *testing.T) {
	tests := map[string]string{
		"positional array": `[{"from":"0xabc"}]`,
		"bare object":      `{"from":"0xabc"}`,
		"padded array":     "  [ \n {\"from\":\"0xabc\"} ] ",
	}

	for name, params := range tests {
		t.Run(name, func(t *testing.T) {
			object, err := rpcinfra.SingleParamsObject(json.RawMessage(params))
			require.NoError(t, err)

			var decoded struct {
				From string `json:"from"`
			}
			require.NoError(t, json.Unmarshal(object, &decoded))
			require.Equal(t, "0xabc", decoded.From)
		})
	}
}

// TestSingleParamsObject_RejectsAmbiguousFieldNames covers the names that encoding/json resolves to
// one struct field while an exact map lookup keeps them apart. Both orderings matter: a struct decode
// keeps the last match, so which spelling wins depends on the order they appear in.
func TestSingleParamsObject_RejectsAmbiguousFieldNames(t *testing.T) {
	tests := map[string]string{
		"capitalised second":    `[{"from":"0xa","From":"0xb"}]`,
		"capitalised first":     `[{"From":"0xa","from":"0xb"}]`,
		"upper case":            `[{"from":"0xa","FROM":"0xb"}]`,
		"mixed case":            `[{"fRoM":"0xa","FrOm":"0xb"}]`,
		"exact duplicate":       `[{"from":"0xa","from":"0xb"}]`,
		"non adjacent":          `[{"from":"0xa","nonce":"0x1","FROM":"0xb"}]`,
		"kelvin sign fold":      "[{\"k\":\"0xa\",\"K\":\"0xb\"}]",
		"long s fold":           "[{\"s\":\"0xa\",\"ſ\":\"0xb\"}]",
		"bare object form":      `{"address":"0xa","Address":"0xb"}`,
		"differs only by case2": `[{"maxFeePerGas":"0x1","MaxFeePerGas":"0x2"}]`,
	}

	for name, params := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := rpcinfra.SingleParamsObject(json.RawMessage(params))
			require.ErrorContains(t, err, "name the same field twice")

			require.Error(t, rpcinfra.RejectAmbiguousParams(json.RawMessage(params)))
		})
	}
}

// TestSingleParamsObject_AllowsAmbiguityBelowTheTopLevel guards against over-rejecting. An EIP-712
// message is caller data whose keys are matched literally, so two members differing only by case are
// distinct and legitimate there.
func TestSingleParamsObject_AllowsAmbiguityBelowTheTopLevel(t *testing.T) {
	params := `[{"address":"0xa","typedData":{"message":{"amount":1,"Amount":2},"nested":{"x":{"k":1,"K":2}}}}]`

	object, err := rpcinfra.SingleParamsObject(json.RawMessage(params))
	require.NoError(t, err)
	require.NotEmpty(t, object)
	require.NoError(t, rpcinfra.RejectAmbiguousParams(json.RawMessage(params)))

	// A value that is itself an object is skipped whole, not descended into.
	_, err = rpcinfra.SingleParamsObject(json.RawMessage(`[{"from":{"from":"0xa","From":"0xb"}}]`))
	require.NoError(t, err)
}

func TestSingleParamsObject_RejectsShapesThatAreNotOneObject(t *testing.T) {
	tests := map[string]string{
		"empty array":     `[]`,
		"two objects":     `[{"from":"0xa"},{"from":"0xb"}]`,
		"array of string": `["0xa"]`,
		"bare string":     `"0xa"`,
		"null":            `null`,
		"empty":           ``,
		"nested array":    `[[{"from":"0xa"}]]`,
		"number in array": `[1]`,
	}

	for name, params := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := rpcinfra.SingleParamsObject(json.RawMessage(params))
			require.ErrorContains(t, err, "a single object is expected")
		})
	}
}

// TestRejectAmbiguousParams_PassesOverOtherShapes keeps the check out of the way of methods whose
// params are not a single object, including the methods that take none at all.
func TestRejectAmbiguousParams_PassesOverOtherShapes(t *testing.T) {
	for _, params := range []string{`[]`, `null`, ``, `[{"a":1},{"b":2}]`, `["x"]`, `{}`} {
		require.NoErrorf(t, rpcinfra.RejectAmbiguousParams(json.RawMessage(params)),
			"params %q must be left to the per-method decoding", params)
	}
}

// TestProcessParams_RejectsAmbiguousParams checks the guard runs ahead of either decode, since which
// decode runs is what determines how an ambiguous field resolves.
func TestProcessParams_RejectsAmbiguousParams(t *testing.T) {
	var params rpcinfra.SignTXRequestParams
	rpcErr := rpcinfra.ProcessParams(json.RawMessage(`[{"from":"0xa","From":"0xb","data":"0x","nonce":"0x1"}]`), &params)

	require.NotNil(t, rpcErr)
	require.Empty(t, params.From, "an ambiguous request must not populate the signing account")
}

func TestProcessParams_AcceptsWellFormedParams(t *testing.T) {
	tests := map[string]string{
		"positional array": `[{"from":"0xabc","data":"0x","nonce":"0x1"}]`,
		"bare object":      `{"from":"0xabc","data":"0x","nonce":"0x1"}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			var params rpcinfra.SignTXRequestParams
			require.Nil(t, rpcinfra.ProcessParams(json.RawMessage(body), &params))
			require.Equal(t, "0xabc", params.From)
			require.Equal(t, "0x1", params.Nonce)
		})
	}
}
