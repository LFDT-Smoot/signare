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

// TestProcessParams_BothFormsResolveFieldNamesAlike pins the alignment: the positional array form
// used to match field names exactly while the object form matched them by fold, so the same body was
// valid in one form and rejected in the other.
func TestProcessParams_BothFormsResolveFieldNamesAlike(t *testing.T) {
	bodies := map[string]string{
		"canonical":    `{"from":"0xabc","data":"0x","nonce":"0x1"}`,
		"folded from":  `{"From":"0xabc","data":"0x","nonce":"0x1"}`,
		"folded nonce": `{"from":"0xabc","data":"0x","NONCE":"0x1"}`,
		"folded both":  `{"FROM":"0xabc","data":"0x","Nonce":"0x1"}`,
		"data omitted": `{"from":"0xabc","nonce":"0x1"}`,
		"folded gas":   `{"from":"0xabc","nonce":"0x1","GasPrice":"0x2"}`,
	}

	for name, object := range bodies {
		t.Run(name, func(t *testing.T) {
			var fromObject, fromArray rpcinfra.SignTXRequestParams
			require.Nil(t, rpcinfra.ProcessParams(json.RawMessage(object), &fromObject))
			require.Nil(t, rpcinfra.ProcessParams(json.RawMessage("["+object+"]"), &fromArray))

			require.Equal(t, fromObject, fromArray, "both param forms must decode to the same params")
			require.Equal(t, "0xabc", fromArray.From)
			require.Equal(t, "0x1", fromArray.Nonce)
		})
	}
}

// TestValidateParams_AppliesToBothForms covers the checks that were previously enforced on the
// positional form only.
func TestValidateParams_AppliesToBothForms(t *testing.T) {
	bodies := map[string]string{
		"fee ordering":        `{"from":"0xabc","nonce":"0x1","maxFeePerGas":"0x1","maxPriorityFeePerGas":"0x2"}`,
		"access list entry":   `{"from":"0xabc","nonce":"0x1","accessList":[{"storageKeys":[]}]}`,
		"authorization entry": `{"from":"0xabc","nonce":"0x1","authorizationList":[{"storageKeys":[]}]}`,
	}

	for name, object := range bodies {
		t.Run(name, func(t *testing.T) {
			for form, params := range map[string]string{"object": object, "array": "[" + object + "]"} {
				var decoded rpcinfra.SignTXRequestParams
				require.Nilf(t, rpcinfra.ProcessParams(json.RawMessage(params), &decoded), "%s form should decode", form)
				require.Errorf(t, decoded.ValidateParams(), "%s form should fail validation", form)
			}
		})
	}
}

// TestProcessParams_TypeErrorNamesTheField keeps the per-field decode messages the positional
// extraction used to produce. Collapsing onto a struct decode would otherwise report a generic
// failure, or leak encoding/json's internal type names.
func TestProcessParams_TypeErrorNamesTheField(t *testing.T) {
	tests := map[string]struct{ params, message string }{
		"from":     {`[{"from":123,"data":"0x","nonce":"0x1"}]`, "[from] must be of type string"},
		"gas":      {`[{"from":"0xa","gas":true,"nonce":"0x1"}]`, "[gas] must be of type string"},
		"object":   {`{"from":"0xa","value":[],"nonce":"0x1"}`, "[value] must be of type string"},
		"nonce":    {`[{"from":"0xa","nonce":{}}]`, "[nonce] must be of type string"},
		"noObject": {`[]`, "only one object is expected"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var params rpcinfra.SignTXRequestParams
			rpcErr := rpcinfra.ProcessParams(json.RawMessage(tt.params), &params)
			require.NotNil(t, rpcErr)
			require.Contains(t, rpcErr.Error(), tt.message)
			require.NotContains(t, rpcErr.Error(), "Go struct field", "internal type names must not reach the client")
		})
	}
}
