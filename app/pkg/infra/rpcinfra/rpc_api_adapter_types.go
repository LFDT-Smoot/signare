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
	// ApplicationID performing the Ethereum account import.
	ApplicationID string
	// PrivateKey is the hexadecimal string representation of the 256-bit Ethereum account private key.
	PrivateKey string `json:"privateKey"`
}

func (p *ImportAccountRequestParams) SetParamsFrom(params []any) error {
	if len(params) != 1 {
		return fmt.Errorf("only one object is expected")
	}
	paramMap, ok := params[0].(map[string]any)
	if !ok {
		return errors.New("a single object is expected")
	}
	privateKeyParam, ok := paramMap["privateKey"]
	if !ok {
		return errors.New("missing required field [privateKey]")
	}
	privateKey, ok := privateKeyParam.(string)
	if !ok {
		return errors.New("[privateKey] must be of type string")
	}
	p.PrivateKey = privateKey
	return nil
}

func (p *ImportAccountRequestParams) ValidateParams() error {
	if len(p.PrivateKey) == 0 {
		return errors.New("[privateKey] cannot be nil")
	}
	return nil
}

// RemoveAccountRequestParams request definition
type RemoveAccountRequestParams struct {
	// ApplicationID requesting the Ethereum account removal.
	ApplicationID string
	// Address is the Ethereum account to be removed.
	Address string `json:"address"`
}

func (p *RemoveAccountRequestParams) SetParamsFrom(params []any) error {
	if len(params) != 1 {
		return fmt.Errorf("only one object is expected")
	}
	paramMap, ok := params[0].(map[string]any)
	if !ok {
		return errors.New("a single object is expected")
	}
	addressParam, ok := paramMap["address"]
	if !ok {
		return errors.New("missing required field [address]")
	}
	address, ok := addressParam.(string)
	if !ok {
		return errors.New("[address] must be of type string")
	}
	p.Address = address
	return nil
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
	ApplicationID string
	// From address
	From string `json:"from"`
	// To address
	To *string `json:"to"`
	// Gas amount to use for transaction execution
	Gas *string `json:"gas"`
	// GasPrice to use for each paid gas. Legacy (Type 0) only.
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
	// AccessList is a list of addresses and storage keys. EIP-1559 (Type 2) only.
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

func (p *SignTXRequestParams) SetParamsFrom(params []any) error {
	if len(params) != 1 {
		return fmt.Errorf("only one object is expected")
	}
	paramMap, ok := params[0].(map[string]any)
	if !ok {
		return errors.New("a single object is expected")
	}

	// Required fields
	fromParam, ok := paramMap["from"]
	if !ok {
		return errors.New("missing required field [from]")
	}
	from, ok := fromParam.(string)
	if !ok {
		return errors.New("[from] must be of type string")
	}
	p.From = from

	dataParam, ok := paramMap["data"]
	if !ok {
		return errors.New("missing required field [data]")
	}
	data, ok := dataParam.(string)
	if !ok {
		return errors.New("[data] must be of type string")
	}
	p.Data = data

	nonceParam, ok := paramMap["nonce"]
	if !ok {
		return errors.New("missing required field [nonce]")
	}
	nonce, ok := nonceParam.(string)
	if !ok {
		return errors.New("[nonce] must be of type string")
	}
	p.Nonce = nonce

	// Optional fields
	var to, gas, gasPrice, value, chainID string

	toParam, ok := paramMap["to"]
	if ok {
		to, ok = toParam.(string)
		if !ok {
			return errors.New("[to] must be of type string")
		}
		p.To = &to
	}

	gasParam, ok := paramMap["gas"]
	if ok {
		gas, ok = gasParam.(string)
		if !ok {
			return errors.New("[gas] must be of type string")
		}
		p.Gas = &gas
	}

	gasPriceParam, ok := paramMap["gasPrice"]
	if ok {
		gasPrice, ok = gasPriceParam.(string)
		if !ok {
			return errors.New("[gasPrice] must be of type string")
		}
		p.GasPrice = &gasPrice
	}

	valueParam, ok := paramMap["value"]
	if ok {
		value, ok = valueParam.(string)
		if !ok {
			return errors.New("[value] must be of type string")
		}
		p.Value = &value
	}

	chainIDParam, ok := paramMap["chainId"]
	if ok {
		chainID, ok = chainIDParam.(string)
		if !ok {
			return errors.New("[chainId] must be of type string")
		}
		p.ChainID = &chainID
	}

	// EIP-1559 fields
	var maxFeePerGas, maxPriorityFeePerGas string

	maxFeePerGasParam, ok := paramMap["maxFeePerGas"]
	if ok {
		maxFeePerGas, ok = maxFeePerGasParam.(string)
		if !ok {
			return errors.New("[maxFeePerGas] must be of type string")
		}
		p.MaxFeePerGas = &maxFeePerGas
	}

	maxPriorityFeePerGasParam, ok := paramMap["maxPriorityFeePerGas"]
	if ok {
		maxPriorityFeePerGas, ok = maxPriorityFeePerGasParam.(string)
		if !ok {
			return errors.New("[maxPriorityFeePerGas] must be of type string")
		}
		p.MaxPriorityFeePerGas = &maxPriorityFeePerGas
	}

	if p.MaxFeePerGas != nil && p.MaxPriorityFeePerGas != nil {
		maxFee, errFee := entities.NewInt256FromString(*p.MaxFeePerGas)
		maxPriority, errPriority := entities.NewInt256FromString(*p.MaxPriorityFeePerGas)
		if errFee == nil && errPriority == nil {
			if maxFee.BigInt().Cmp(maxPriority.BigInt()) < 0 {
				return errors.New("[maxFeePerGas] must be greater than [maxPriorityFeePerGas]")
			}
		}
	}

	if err := p.setAccessListParam(paramMap); err != nil {
		return err
	}

	// EIP-4844 fields
	if err := p.setEIP4844Params(paramMap); err != nil {
		return err
	}

	// EIP-7702 fields
	return p.setAuthorizationListParam(paramMap)
}

func (p *SignTXRequestParams) setAccessListParam(paramMap map[string]any) error {
	accessListParam, ok := paramMap["accessList"]
	if !ok {
		return nil
	}
	accessListRaw, ok := accessListParam.([]interface{})
	if !ok {
		return errors.New("[accessList] must be an array")
	}
	p.AccessList = make([]AccessListParamEntry, 0, len(accessListRaw))
	for _, entry := range accessListRaw {
		entryMap, ok := entry.(map[string]interface{})
		if !ok {
			return errors.New("[accessList] entries must be objects")
		}
		// Validate address
		addrParam, ok := entryMap["address"]
		if !ok {
			return errors.New("[accessList] entry missing required field [address]")
		}
		addrVal, ok := addrParam.(string)
		if !ok {
			return errors.New("[accessList] entry field [address] must be of type string")
		}

		// Validate storageKeys
		keysParam, ok := entryMap["storageKeys"]
		if !ok {
			return errors.New("[accessList] entry missing required field [storageKeys]")
		}
		keysVal, ok := keysParam.([]interface{})
		if !ok {
			return errors.New("[accessList] entry field [storageKeys] must be an array")
		}
		keys := make([]string, len(keysVal))
		for j, k := range keysVal {
			keyStr, ok := k.(string)
			if !ok {
				return errors.New("[accessList] entry field [storageKeys] elements must be of type string")
			}
			keys[j] = keyStr
		}
		p.AccessList = append(p.AccessList, AccessListParamEntry{
			Address:     addrVal,
			StorageKeys: keys,
		})
	}
	return nil
}

func (p *SignTXRequestParams) setEIP4844Params(paramMap map[string]any) error {
	var maxFeePerBlobGas string

	maxFeePerBlobGasParam, ok := paramMap["maxFeePerBlobGas"]
	if ok {
		maxFeePerBlobGas, ok = maxFeePerBlobGasParam.(string)
		if !ok {
			return errors.New("[maxFeePerBlobGas] must be of type string")
		}
		p.MaxFeePerBlobGas = &maxFeePerBlobGas
	}

	blobVersionedHashesParam, ok := paramMap["blobVersionedHashes"]
	if ok {
		blobHashesRaw, ok := blobVersionedHashesParam.([]interface{})
		if !ok {
			return errors.New("[blobVersionedHashes] must be an array")
		}
		p.BlobVersionedHashes = make([]string, 0, len(blobHashesRaw))
		for _, h := range blobHashesRaw {
			hashStr, ok := h.(string)
			if !ok {
				return errors.New("[blobVersionedHashes] entries must be of type string")
			}
			p.BlobVersionedHashes = append(p.BlobVersionedHashes, hashStr)
		}
	}
	return nil
}

func (p *SignTXRequestParams) setAuthorizationListParam(paramMap map[string]any) error {
	authorizationListParam, ok := paramMap["authorizationList"]
	if !ok {
		return nil
	}
	authListRaw, ok := authorizationListParam.([]interface{})
	if !ok {
		return errors.New("[authorizationList] must be an array")
	}
	p.AuthorizationList = make([]AuthorizationListParamEntry, 0, len(authListRaw))
	for _, entry := range authListRaw {
		entryMap, ok := entry.(map[string]interface{})
		if !ok {
			return errors.New("[authorizationList] entries must be objects")
		}
		addrRaw, ok := entryMap["address"]
		if !ok {
			return errors.New("[authorizationList] entries must contain [address]")
		}
		addrVal, ok := addrRaw.(string)
		if !ok {
			return errors.New("[authorizationList] entry [address] must be of type string")
		}
		storageKeysRaw, ok := entryMap["storageKeys"]
		if !ok {
			return errors.New("[authorizationList] entries must contain [storageKeys]")
		}
		keysVal, ok := storageKeysRaw.([]interface{})
		if !ok {
			return errors.New("[authorizationList] entry [storageKeys] must be an array")
		}
		keys := make([]string, len(keysVal))
		for j, k := range keysVal {
			keyStr, ok := k.(string)
			if !ok {
				return errors.New("[authorizationList] entry [storageKeys] elements must be of type string")
			}
			keys[j] = keyStr
		}
		p.AuthorizationList = append(p.AuthorizationList, AuthorizationListParamEntry{
			Address:     addrVal,
			StorageKeys: keys,
		})
	}
	return nil
}

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
	return nil
}

// SignTypedDataRequestParams request definition for eth_signTypedData.
type SignTypedDataRequestParams struct {
	// ApplicationID performing the typed data signature.
	ApplicationID string
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
	trimmed := bytes.TrimSpace(data)
	var obj signTypedDataParamsObject
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var arr []signTypedDataParamsObject
		if err := decodeUsingNumber(trimmed, &arr); err != nil {
			return err
		}
		if len(arr) != 1 {
			return fmt.Errorf("only one object is expected")
		}
		obj = arr[0]
	} else if err := decodeUsingNumber(trimmed, &obj); err != nil {
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
	// ApplicationID performing the signature.
	ApplicationID string
	// Address of the account that will sign the message.
	Address string `json:"address"`
	// Message is the 0x-prefixed hex encoding of the raw bytes to sign.
	Message string `json:"message"`
}

func (p *PersonalSignRequestParams) SetParamsFrom(params []any) error {
	if len(params) != 1 {
		return fmt.Errorf("only one object is expected")
	}
	paramMap, ok := params[0].(map[string]any)
	if !ok {
		return errors.New("a single object is expected")
	}
	addressParam, ok := paramMap["address"]
	if !ok {
		return errors.New("missing required field [address]")
	}
	addressValue, ok := addressParam.(string)
	if !ok {
		return errors.New("[address] must be of type string")
	}
	messageParam, ok := paramMap["message"]
	if !ok {
		return errors.New("missing required field [message]")
	}
	messageValue, ok := messageParam.(string)
	if !ok {
		return errors.New("[message] must be of type string")
	}
	p.Address = addressValue
	p.Message = messageValue
	return nil
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
