package rpcinfra

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/eip712"
)

// GenerateAccountRequestParams request definition
type GenerateAccountRequestParams struct {
	// ApplicationID requesting the Ethereum account generation.
	ApplicationID string
}

type ImportAccountRequestParams struct {
	// ApplicationID performing the Ethereum account import. Taken from the request context, never from the body.
	ApplicationID string `json:"-"`
	// PrivateKey is the hexadecimal string representation of the 256-bit Ethereum account private key.
	PrivateKey string `json:"privateKey"`
}

// UnmarshalJSON decodes the eth_importAccount params from either the positional array form ([{...}])
// or a single object ({...}), so both forms resolve a field name the same way.
func (p *ImportAccountRequestParams) UnmarshalJSON(data []byte) error {
	object := paramsObject(data)
	if object == nil {
		return errors.New("only one object is expected")
	}
	// The local type sheds this method, so the decode below does not recurse.
	type params ImportAccountRequestParams
	var decoded params
	if err := json.Unmarshal(object, &decoded); err != nil {
		return err
	}
	*p = ImportAccountRequestParams(decoded)
	return nil
}

// SetParamsFrom is the JSONRPCParams fallback. See SignTXRequestParams.SetParamsFrom.
func (p *ImportAccountRequestParams) SetParamsFrom(params []any) error {
	if len(params) != 1 {
		return fmt.Errorf("only one object is expected")
	}
	if _, ok := params[0].(map[string]any); !ok {
		return errors.New("a single object is expected")
	}
	return errors.New("could not decode eth_importAccount params; expected a single object with [privateKey]")
}

func (p *ImportAccountRequestParams) ValidateParams() error {
	if len(p.PrivateKey) == 0 {
		return errors.New("[privateKey] cannot be nil")
	}
	return nil
}

// RemoveAccountRequestParams request definition
type RemoveAccountRequestParams struct {
	// ApplicationID requesting the Ethereum account removal. Taken from the request context, never from the body.
	ApplicationID string `json:"-"`
	// Address is the Ethereum account to be removed.
	Address string `json:"address"`
}

// UnmarshalJSON decodes the eth_removeAccount params from either the positional array form ([{...}])
// or a single object ({...}), so both forms resolve a field name the same way.
func (p *RemoveAccountRequestParams) UnmarshalJSON(data []byte) error {
	object := paramsObject(data)
	if object == nil {
		return errors.New("only one object is expected")
	}
	// The local type sheds this method, so the decode below does not recurse.
	type params RemoveAccountRequestParams
	var decoded params
	if err := json.Unmarshal(object, &decoded); err != nil {
		return err
	}
	*p = RemoveAccountRequestParams(decoded)
	return nil
}

// SetParamsFrom is the JSONRPCParams fallback. See SignTXRequestParams.SetParamsFrom.
func (p *RemoveAccountRequestParams) SetParamsFrom(params []any) error {
	if len(params) != 1 {
		return fmt.Errorf("only one object is expected")
	}
	if _, ok := params[0].(map[string]any); !ok {
		return errors.New("a single object is expected")
	}
	return errors.New("could not decode eth_removeAccount params; expected a single object with [address]")
}

func (p *RemoveAccountRequestParams) ValidateParams() error {
	if len(p.Address) == 0 {
		return errors.New("[address] cannot be nil")
	}
	return nil
}

// ListAccountsRequestParams request definition
type ListAccountsRequestParams struct {
	ApplicationID string
}

// SignTXRequestParams request definition
type SignTXRequestParams struct {
	// ApplicationID is taken from the request context, never from the body.
	ApplicationID string `json:"-"`
	// From address
	From string `json:"from"`
	// To address
	To *string `json:"to"`
	// Gas amount to use for transaction execution
	Gas *string `json:"gas"`
	// GasPrice to use for each paid gas. Legacy (Type 0) and EIP-2930 (Type 1) only.
	GasPrice *string `json:"gasPrice"`
	// Value amount sent with this transaction
	Value *string `json:"value"`
	// Data arguments packed according to json rpc standard
	Data string `json:"data"`
	// Nonce integer to identify request
	Nonce string `json:"nonce"`
	// ChainID integer identifier of the blockchain ID
	ChainID *string `json:"chainId"`
	// MaxFeePerGas is the maximum total fee per gas. EIP-1559 (Type 2) only.
	MaxFeePerGas *string `json:"maxFeePerGas"`
	// MaxPriorityFeePerGas is the maximum priority fee per gas (tip). EIP-1559 (Type 2) only.
	MaxPriorityFeePerGas *string `json:"maxPriorityFeePerGas"`
	// AccessList is a list of addresses and storage keys. EIP-2930 (Type 1) and EIP-1559 (Type 2) only.
	AccessList []AccessListParamEntry `json:"accessList"`
	// MaxFeePerBlobGas is the maximum fee per blob gas the sender is willing to pay. EIP-4844 (Type 3) only.
	MaxFeePerBlobGas *string `json:"maxFeePerBlobGas"`
	// BlobVersionedHashes is the list of versioned hashes of the blobs attached to the transaction. EIP-4844 (Type 3) only.
	BlobVersionedHashes []string `json:"blobVersionedHashes"`
	// AuthorizationList is a list of authorizations. EIP-7702 (Type 4) only.
	AuthorizationList []AuthorizationListParamEntry `json:"authorizationList"`
}

// AccessListParamEntry represents a single access list entry in the RPC request.
type AccessListParamEntry struct {
	Address     string   `json:"address"`
	StorageKeys []string `json:"storageKeys"`
}

// AuthorizationListParamEntry represents a single authorization list entry in the RPC request. EIP-7702 (Type 4) only.
type AuthorizationListParamEntry struct {
	Address     string   `json:"address"`
	StorageKeys []string `json:"storageKeys"`
}

// UnmarshalJSON decodes the eth_signTransaction params from either the positional array form
// ([{...}]) or a single object ({...}). One unwrap and one struct decode for both, so a field name
// resolves the same way either way, and matches what authorization read.
func (p *SignTXRequestParams) UnmarshalJSON(data []byte) error {
	object := paramsObject(data)
	if object == nil {
		return errors.New("only one object is expected")
	}
	// The local type sheds this method, so the decode below does not recurse.
	type params SignTXRequestParams
	var decoded params
	if err := json.Unmarshal(object, &decoded); err != nil {
		return err
	}
	*p = SignTXRequestParams(decoded)
	return nil
}

// SetParamsFrom is the JSONRPCParams fallback, reached only once UnmarshalJSON has rejected the
// params. Re-reading them from a map here is what used to disagree with authorization, so it errors.
func (p *SignTXRequestParams) SetParamsFrom(params []any) error {
	if len(params) != 1 {
		return fmt.Errorf("only one object is expected")
	}
	if _, ok := params[0].(map[string]any); !ok {
		return errors.New("a single object is expected")
	}
	return errors.New("could not decode eth_signTransaction params; expected a single object")
}

// ValidateParams holds the rules that were previously enforced on the positional form only, since
// that was the form with the hand-rolled extraction. Both forms reach them here.
func (p *SignTXRequestParams) ValidateParams() error {
	if len(p.From) == 0 {
		return errors.New("[from] cannot be nil")
	}
	if len(p.Nonce) == 0 {
		return errors.New("[nonce] cannot be nil")
	}
	if p.GasPrice != nil && p.MaxFeePerGas != nil {
		return errors.New("cannot specify both [gasPrice] and [maxFeePerGas]")
	}
	if p.MaxFeePerGas != nil && p.MaxPriorityFeePerGas != nil {
		// An unparseable fee is left to the adapter, which reports it per field.
		maxFee, errFee := entities.NewInt256FromString(*p.MaxFeePerGas)
		maxPriority, errPriority := entities.NewInt256FromString(*p.MaxPriorityFeePerGas)
		if errFee == nil && errPriority == nil && maxFee.BigInt().Cmp(maxPriority.BigInt()) < 0 {
			return errors.New("[maxFeePerGas] must be greater than [maxPriorityFeePerGas]")
		}
	}
	for i, entry := range p.AccessList {
		if len(entry.Address) == 0 {
			return fmt.Errorf("[accessList] entry %d is missing required field [address]", i)
		}
	}
	for i, entry := range p.AuthorizationList {
		if len(entry.Address) == 0 {
			return fmt.Errorf("[authorizationList] entry %d is missing required field [address]", i)
		}
	}
	return nil
}

// SignTypedDataRequestParams request definition for eth_signTypedData.
type SignTypedDataRequestParams struct {
	// ApplicationID performing the typed data signature. Taken from the request context, never from the body.
	ApplicationID string `json:"-"`
	// Address of the account that will sign the typed data.
	Address string `json:"address"`
	// TypedData is the EIP-712 typed structured data to be signed.
	TypedData eip712.TypedData `json:"typedData"`
}

// signTypedDataParamsObject is the shape of a single eth_signTypedData param object.
type signTypedDataParamsObject struct {
	Address   string           `json:"address"`
	TypedData eip712.TypedData `json:"typedData"`
}

// UnmarshalJSON decodes the eth_signTypedData params, accepting either the positional array form
// ([{...}]) or a single object ({...}). It decodes with UseNumber so integer message fields survive as
// json.Number instead of being forced through float64, which would silently round values above 2^53
// before signing. This is the primary decode path (ProcessParams tries it before the []any fallback).
func (p *SignTypedDataRequestParams) UnmarshalJSON(data []byte) error {
	object := paramsObject(data)
	if object == nil {
		return errors.New("only one object is expected")
	}
	var obj signTypedDataParamsObject
	if err := decodeUsingNumber(object, &obj); err != nil {
		return err
	}
	p.Address = obj.Address
	p.TypedData = obj.TypedData
	return nil
}

// decodeUsingNumber decodes JSON into v with numbers preserved as json.Number rather than float64.
func decodeUsingNumber(data []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return decoder.Decode(v)
}

func (p *SignTypedDataRequestParams) SetParamsFrom(params []any) error {
	// SetParamsFrom is the JSONRPCParams fallback, reached only when UnmarshalJSON has already rejected
	// the raw params. By this point numbers have been decoded to float64, so integer precision above 2^53
	// is already lost and cannot be recovered here. Rather than re-decode and risk silently signing a
	// rounded value, return an error. Well-formed requests never reach this path; they are decoded
	// losslessly by UnmarshalJSON.
	if len(params) != 1 {
		return fmt.Errorf("only one object is expected")
	}
	if _, ok := params[0].(map[string]any); !ok {
		return errors.New("a single object is expected")
	}
	return errors.New("could not decode eth_signTypedData params; expected a single object with [address] and [typedData]")
}

func (p *SignTypedDataRequestParams) ValidateParams() error {
	if len(p.Address) == 0 {
		return errors.New("[address] cannot be nil")
	}
	return p.TypedData.Validate()
}

// PersonalSignRequestParams request definition for personal_sign.
//
// The shape is a named object, matching eth_signTransaction and eth_signTypedData, rather than the
// positional [message, address] form wallets use for personal_sign. Signare's client is a gateway
// rather than a wallet, and naming the fields removes the argument-order confusion between
// personal_sign and eth_sign, which take their two arguments in opposite orders.
type PersonalSignRequestParams struct {
	// ApplicationID performing the signature. Taken from the request context, never from the body.
	ApplicationID string `json:"-"`
	// Address of the account that will sign the message.
	Address string `json:"address"`
	// Message is the 0x-prefixed hex encoding of the raw bytes to sign.
	Message string `json:"message"`
}

// UnmarshalJSON decodes the personal_sign params from either the positional array form ([{...}]) or a
// single object ({...}). One struct decode for both, matching what authorization read.
func (p *PersonalSignRequestParams) UnmarshalJSON(data []byte) error {
	object := paramsObject(data)
	if object == nil {
		return errors.New("only one object is expected")
	}
	// The local type sheds this method, so the decode below does not recurse.
	type params PersonalSignRequestParams
	var decoded params
	if err := json.Unmarshal(object, &decoded); err != nil {
		return err
	}
	*p = PersonalSignRequestParams(decoded)
	return nil
}

// SetParamsFrom is the JSONRPCParams fallback, reached only when UnmarshalJSON has already rejected
// the raw params. See SignTXRequestParams.SetParamsFrom.
func (p *PersonalSignRequestParams) SetParamsFrom(params []any) error {
	if len(params) != 1 {
		return fmt.Errorf("only one object is expected")
	}
	if _, ok := params[0].(map[string]any); !ok {
		return errors.New("a single object is expected")
	}
	return errors.New("could not decode personal_sign params; expected a single object with [address] and [message]")
}

func (p *PersonalSignRequestParams) ValidateParams() error {
	if len(p.Address) == 0 {
		return errors.New("[address] cannot be nil")
	}
	if len(p.Message) == 0 {
		return errors.New("[message] cannot be nil")
	}
	// The 0x prefix is required rather than optional. entities.NewHexBytesFromString accepts input with
	// or without it, which would make a plain-text message that happens to be valid hex ("cafe") decode
	// to bytes instead of being rejected, and the caller would sign something they did not intend.
	if !strings.HasPrefix(p.Message, "0x") {
		return errors.New("[message] must be a 0x-prefixed hex string")
	}
	if len(p.Message) == 2 {
		return errors.New("[message] cannot be empty")
	}
	return nil
}
