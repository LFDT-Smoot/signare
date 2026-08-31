package hsmconnector

import (
	"math/big"

	"github.com/lfdt-smoot/signare/app/pkg/commons/rlp"
	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/eip712"
)

// PKCS11Library path to the library to connect to a PKCS11 compatible HSM.
type PKCS11Library string

// ModuleKind HSM type.
type ModuleKind string

const (
	SoftHSMModuleKind ModuleKind = "SoftHSM"
	AKVModuleKind     ModuleKind = "AKV"
	LKVModuleKind     ModuleKind = "LocalKeyVault"
)

var supportedSigningModules = map[ModuleKind]bool{
	SoftHSMModuleKind: true,
	AKVModuleKind:     true,
	LKVModuleKind:     true,
}

func IsModuleSupported(m ModuleKind) bool {
	_, ok := supportedSigningModules[m]
	return ok
}

// CreateInput input data to create a new instance using the factory.
type CreateInput struct {
	ModuleKind ModuleKind
}

// PKCS11ConnectionDetails HSM connection details.
type PKCS11ConnectionDetails struct {
	// Configuration details for the HSM.
	Configuration PKCS11ConnectionDetailsConfiguration
	// Slot to be accessed.
	Slot string
	// Pin that grants access to the slot.
	Pin string
}

// CloseInput input to close all the signature manager resources.
type CloseInput struct {
}

// CloseOutput input to close all the signature manager resources.
type CloseOutput struct {
}

// PKCS11ConnectionDetailsConfiguration configuration details for the HSM.
type PKCS11ConnectionDetailsConfiguration struct{}

// GenerateAddressInput for account generation requests.
type GenerateAddressInput struct {
	// SlotConnectionData configuration to connect to a slot.
	SlotConnectionData
}

// DeriveAddressFromPrivateKeyInput for account import requests.
type DeriveAddressFromPrivateKeyInput struct {
	// PrivateKey used to generate the address from.
	PrivateKey entities.HexBytes
	// ModuleKind of the Hardware Security Module.
	ModuleKind ModuleKind `valid:"in(SoftHSM|AKV|LocalKeyVault)"`
}

type DeriveAddressFromPrivateKeyOutput struct {
	// Address an Ethereum account to interact with the network.
	Address address.Address `json:"address"`
}

// SlotConnectionData configuration to connect to a slot.
type SlotConnectionData struct {
	// Slot to be accessed.
	Slot string `valid:"optional"`
	// Pin that grants access to the slot.
	Pin string `valid:"optional"`
	// Config of the slot.
	Config SlotConfig `valid:"optional"`
	// ModuleKind of the Hardware Security Module.
	ModuleKind ModuleKind `valid:"in(SoftHSM|AKV|LocalKeyVault)"`
}

// SlotConfig defines the configuration for a particular slot.
type SlotConfig struct {
	AKV           []AKVConfig          `valid:"optional"`
	LocalKeyVault *LocalKeyVaultConfig `valid:"optional"`
}

// AKVConfig defines possible configurations for Azure Key Vault.
type AKVConfig struct {
	// KeyName is the name for the key to use in AKV
	KeyName string `valid:"required"`
	// KeyVersion is the version for the key to use in AKV
	KeyVersion string `valid:"required"`
	// KeyPublicAddress is the public address for the key to use in AKV
	KeyPublicAddress string `valid:"required"`
}

// LocalKeyVaultConfig defines possible configurations for Local Key Vault.
type LocalKeyVaultConfig struct {
	// KeyStore holds the stored addresses and its private keys
	KeyStore map[address.Address]string `valid:"-"`
}

// GenerateAddressOutput for account generation responses.
type GenerateAddressOutput struct {
	// Address an Ethereum account to interact with the network.
	Address address.Address `json:"address"`
}

// RemoveAddressInput for account removal requests.
type RemoveAddressInput struct {
	// SlotConnectionData configuration to connect to a slot.
	SlotConnectionData
	// Address an Ethereum account to interact with the network.
	Address address.Address `valid:"address"`
}

// RemoveAddressOutput for address removal responses.
type RemoveAddressOutput struct {
	// Address an Ethereum account to interact with the network.
	Address address.Address `json:"address"`
}

// ListAddressesInput for account listing requests.
type ListAddressesInput struct {
	// SlotConnectionData configuration to connect to a slot.
	SlotConnectionData
}

// ListAddressesOutput for account listing responses.
type ListAddressesOutput struct {
	// Items is an array of Ethereum accounts to interact with the network.
	Items []address.Address `json:"items"`
}

// SignTxInput for transaction signing requests.
type SignTxInput struct {
	// SlotConnectionData configuration to connect to a slot.
	SlotConnectionData
	// From address.
	From address.Address `valid:"address"`
	// To address.
	To *address.Address `valid:"optional"`
	// Gas amount to use for transaction execution.
	Gas *entities.HexUInt64 `valid:"optional"`
	// GasPrice to use for each paid gas. Legacy (Type 0) and EIP-2930 (Type 1) only.
	GasPrice *entities.HexInt256 `valid:"optional"`
	// Value amount sent with this transaction.
	Value *entities.HexInt256 `valid:"optional"`
	// Data arguments packed according to JSON RPC standard.
	Data entities.HexBytes // it can be empty (byte array of length 0) in eth-transfers
	// Nonce integer to identify request.
	Nonce entities.HexUInt64
	// ChainID integer to identify request.
	ChainID entities.HexInt256
	// MaxFeePerGas is the maximum total fee per gas the sender is willing to pay. EIP-1559 (Type 2) only.
	MaxFeePerGas *entities.HexInt256 `valid:"optional"`
	// MaxPriorityFeePerGas is the maximum fee per gas to give to the miner as a tip. EIP-1559 (Type 2) only.
	MaxPriorityFeePerGas *entities.HexInt256 `valid:"optional"`
	// AccessList is a list of addresses and storage keys the transaction accesses. EIP-2930 (Type 1) and EIP-1559 (Type 2) only.
	AccessList AccessList `valid:"optional"`
	// MaxFeePerBlobGas is the maximum fee per blob gas the sender is willing to pay. EIP-4844 (Type 3) only.
	MaxFeePerBlobGas *entities.HexInt256 `valid:"optional"`
	// BlobVersionedHashes is the list of versioned hashes of the blobs attached to the transaction. EIP-4844 (Type 3) only.
	BlobVersionedHashes []entities.HexBytes32 `valid:"optional"`
	// AuthorizationList is a list of authorizations for EIP-7702 (Type 4) transactions only.
	AuthorizationList AuthorizationList `valid:"optional"`
}

// SignedTransaction is a transaction that has been signed. Hash returns the digest the signature
// commits to and RLPEncode returns the bytes that go on the wire, so RLPEncode always re-derives
// SignTxOutput.SignedTx. Every supported transaction type implements it, which is what lets
// SignTxOutput carry one transaction field instead of one field per type.
type SignedTransaction interface {
	// Hash returns the digest the transaction's signature commits to.
	Hash() (*entities.HexBytes, error)
	// RLPEncode returns the signed transaction as it is broadcast.
	RLPEncode() (*entities.HexBytes, error)
}

// SignTxOutput for transaction signing responses.
type SignTxOutput struct {
	// SignedTx an encrypted transaction with the corresponding private key of the Ethereum account.
	SignedTx string
	// TxType is the transaction type that was signed, one of the entities.TransactionType values.
	// It identifies the concrete type held by Transaction.
	TxType string
	// Transaction is the signed transaction. Its concrete type follows TxType: EthereumTransaction
	// for type 0, EIP2930Transaction for type 1 and EIP1559Transaction for type 2.
	Transaction SignedTransaction
}

// SignTypedDataInput for types data signing requests.
type SignTypedDataInput struct {
	// SlotConnectionData configuration to connect to a slot.
	SlotConnectionData
	// ChainID id of the chain.
	ChainID entities.HexInt256 `valid:"required"`
	// Address of the account that will sign the message inside the TypedData param.
	Address address.Address `valid:"address"`
	// TypedData packed according to JSON RPC schema definition for TypedData param.
	// Skipped by govalidator (no "typedData" custom validator is registered); SignTypedData
	// validates the structure explicitly via TypedData.Validate before signing.
	TypedData eip712.TypedData `valid:"-"`
}

// SignTypedDataOutput for typed data signing responses.
type SignTypedDataOutput struct {
	// SignedData is a hex-encoded signature over EIP712 typed data that was signed with the private key of the Ethereum account corresponding to the given address.
	SignedData string
	// TypedHash is a hex-encoded hash of the typed data, packed according to JSON RPC schema definition for the TypedData param, before adding a prefix and signing it.
	TypedHash string
}

// CloseAllInput input to close all the signature manager resources.
type CloseAllInput struct {
}

// CloseAllOutput input to close all the signature manager resources.
type CloseAllOutput struct {
}

// IsAliveInput input to check the availability of the HSM slot.
type IsAliveInput struct {
	// Slot to be accessed.
	Slot string `valid:"required"`
	// Pin that grants access to the slot.
	Pin string `valid:"required"`
	// ModuleKind of the Hardware Security Module.
	ModuleKind ModuleKind `valid:"in(SoftHSM)"`
}

// IsAliveOutput whether the slot is available.
type IsAliveOutput struct {
	// IsAlive is true if the slot is reachable.
	IsAlive bool
}

// ResetInput input to reset the connection with the HSM library.
type ResetInput struct {
	// ModuleKind is the kind of the module that will be reset.
	ModuleKind ModuleKind
}

// ResetOutput output from the reset operation.
type ResetOutput struct {
}

// EthereumTransaction represents an Ethereum transaction.
type EthereumTransaction struct {
	// From address.
	From address.Address
	// To address.
	To *address.Address
	// Gas amount to use for transaction execution.
	Gas entities.HexUInt64
	// GasPrice to use for each paid gas.
	GasPrice entities.HexInt256
	// Value amount sent with this transaction.
	Value *entities.HexInt256
	// Data arguments packed according to json rpc standard.
	Data entities.HexBytes
	// Nonce integer to identify request.
	Nonce entities.HexUInt64
	// ChainID id of the blockchain network where the transaction is sent to.
	ChainID entities.HexInt256
	// Signature Ethereum transaction signature.
	Signature *EthereumSignature
}

// EthereumSignature represents an Ethereum transaction signature.
type EthereumSignature struct {
	V entities.Int256
	R entities.Int256
	S entities.Int256
}

// RLPEncode RLP encodes the Ethereum transaction (including its signature) according to EIP-155. This function fails if the transaction doesn't have a signature yet.
// As a summary, the result is rlp(nonce, gasPrice, gas, to, value, data, V, R, S)
func (tx EthereumTransaction) RLPEncode() (*entities.HexBytes, error) {
	if tx.Signature == nil {
		return nil, errors.Internal().WithMessage("tx doesn't have a signature so it can't be RLP encoded")
	}
	nonce, err := entities.NewHexBytesFromString(hexStringEvenLength(tx.Nonce.String()))
	if err != nil {
		return nil, errors.Internal().WithMessage("could not convert 'nonce' to hex bytes")
	}
	nonceBytes := nonce.Bytes()
	if tx.Nonce.Uint64() == 0 {
		nonceBytes = []byte{}
	}

	gasPrice := nonZeroOrNil(tx.GasPrice)

	gas, err := entities.NewHexBytesFromString(hexStringEvenLength(tx.Gas.String()))
	if err != nil {
		return nil, errors.Internal().WithMessage("could not convert 'gas' to hex bytes")
	}

	var toBytes []byte
	if tx.To != nil {
		hexBytes, newErr := entities.NewHexBytesFromString(tx.To.String())
		if newErr != nil {
			return nil, errors.Internal().WithMessage("could not convert 'to' to hex bytes")
		}
		toBytes = hexBytes.Bytes()
	} else {
		toBytes = []byte{}
	}

	var value *big.Int
	if tx.Value != nil && tx.Value.BigInt().Sign() != 0 {
		value = tx.Value.BigInt()
	}

	var data []byte
	if len(tx.Data.Bytes()) > 0 {
		hexBytes, newErr := entities.NewHexBytesFromString(tx.Data.String())
		if newErr != nil {
			return nil, errors.Internal().WithMessage("could not convert 'data' to hex bytes")
		}
		data = hexBytes.Bytes()
	} else {
		data = []byte{}
	}
	dataToEncode := []interface{}{
		&nonceBytes,
		gasPrice,
		gas.Bytes(),
		toBytes,
		value,
		data,
		tx.Signature.V.BigInt(),
		tx.Signature.R.BigInt(),
		tx.Signature.S.BigInt(),
	}

	// Debug: identify which element fails RLP encoding
	for _, elem := range dataToEncode {
		var encodeErr error
		_, encodeErr = rlp.Encode(elem)
		if encodeErr != nil {
			return nil, encodeErr
		}
	}

	rlpEncode, err := rlp.Encode(dataToEncode)
	if err != nil {
		return nil, errors.InternalFromErr(err).WithMessage("failed to RLP encode the payload to sign")
	}

	return entities.NewHexBytes(rlpEncode), nil
}

// Hash calculates the Ethereum transaction hash.
func (tx EthereumTransaction) Hash() (*entities.HexBytes, error) {
	nonce, err := entities.NewHexBytesFromString(hexStringEvenLength(tx.Nonce.String()))
	if err != nil {
		return nil, errors.Internal().WithMessage("could not convert 'nonce' to hex bytes")
	}
	nonceBytes := nonce.Bytes()
	if tx.Nonce.Uint64() == 0 {
		nonceBytes = []byte{}
	}

	gasPrice := nonZeroOrNil(tx.GasPrice)

	gas, err := entities.NewHexBytesFromString(hexStringEvenLength(tx.Gas.String()))
	if err != nil {
		return nil, errors.Internal().WithMessage("could not convert 'gas' to hex bytes")
	}

	var toBytes []byte
	if tx.To != nil {
		hexBytes, newErr := entities.NewHexBytesFromString(tx.To.String())
		if newErr != nil {
			return nil, errors.Internal().WithMessage("could not convert 'to' to hex bytes")
		}
		toBytes = hexBytes.Bytes()
	} else {
		toBytes = []byte{}
	}

	var value *big.Int
	if tx.Value != nil && tx.Value.BigInt().Sign() != 0 {
		value = tx.Value.BigInt()
	}

	var data []byte
	if len(tx.Data.Bytes()) > 0 {
		hexBytes, newErr := entities.NewHexBytesFromString(tx.Data.String())
		if newErr != nil {
			return nil, errors.Internal().WithMessage("could not convert 'data' to hex bytes")
		}
		data = hexBytes.Bytes()
	} else {
		data = []byte{}
	}
	chainID, err := chainIDToRLPBytes(tx.ChainID)
	if err != nil {
		return nil, err
	}

	dataToEncode := []interface{}{
		&nonceBytes,
		gasPrice,
		gas.Bytes(),
		toBytes,
		value,
		data,
		chainID,
		uint(0),
		uint(0),
	}
	// 1. RLP encode of the data
	rlpEncode, err := rlp.Encode(dataToEncode)
	if err != nil {
		return nil, errors.InternalFromErr(err).WithMessage("failed to RLP encode the payload to sign")
	}

	// 2. Keccak256 of the RLP encoded data
	hash, err := hashKeccak256(rlpEncode)
	if err != nil {
		return nil, errors.InternalFromErr(err).WithMessage("failed to calculate the Keccak256 of the payload to sign")
	}

	return entities.NewHexBytes(hash), nil
}

// AccessListEntry represents a single entry in an EIP-2930 or EIP-1559 access list.
type AccessListEntry struct {
	// Address is the account address being accessed.
	Address address.Address
	// StorageKeys is a list of storage keys being accessed at this address.
	StorageKeys []entities.HexBytes32
}

// AccessList is a list of access list entries for EIP-2930 and EIP-1559 transactions.
type AccessList []AccessListEntry

// AuthorizationListEntry represents a single entry in an EIP-7702 authorization list.
type AuthorizationListEntry struct {
	// Address is the account address being authorized.
	Address address.Address
	// StorageKeys is a list of storage keys being authorized at this address.
	StorageKeys []entities.HexBytes32
}

// AuthorizationList is a list of authorization list entries for EIP-7702 transactions.
type AuthorizationList []AuthorizationListEntry

// YParityTransactionSignature represents a transaction signature with YParity.
// YParity is 0 or 1 (not the EIP-155 formula).
type YParityTransactionSignature struct {
	YParity entities.Int256
	R       entities.Int256
	S       entities.Int256
}

// EIP2930Transaction represents an EIP-2930 (Type 1) Ethereum transaction.
type EIP2930Transaction struct {
	// From address.
	From address.Address
	// To address.
	To *address.Address
	// Gas amount to use for transaction execution.
	Gas entities.HexUInt64
	// GasPrice to use for each paid gas.
	GasPrice entities.HexInt256
	// Value amount sent with this transaction.
	Value *entities.HexInt256
	// Data arguments packed according to JSON RPC standard.
	Data entities.HexBytes
	// Nonce integer to identify request.
	Nonce entities.HexUInt64
	// ChainID id of the blockchain network where the transaction is sent to.
	ChainID entities.HexInt256
	// AccessList is a list of addresses and storage keys the transaction accesses.
	AccessList AccessList
	// Signature transaction signature with Y parity.
	Signature *YParityTransactionSignature
}

// eip2930TypePrefix is the transaction type byte for EIP-2930.
const eip2930TypePrefix = 0x01

// EIP1559Transaction represents an EIP-1559 (Type 2) Ethereum transaction.
type EIP1559Transaction struct {
	// From address.
	From address.Address
	// To address.
	To *address.Address
	// Gas amount to use for transaction execution.
	Gas entities.HexUInt64
	// MaxFeePerGas is the maximum total fee per gas.
	MaxFeePerGas entities.HexInt256
	// MaxPriorityFeePerGas is the maximum priority fee per gas (tip).
	MaxPriorityFeePerGas entities.HexInt256
	// Value amount sent with this transaction.
	Value *entities.HexInt256
	// Data arguments packed according to JSON RPC standard.
	Data entities.HexBytes
	// Nonce integer to identify request.
	Nonce entities.HexUInt64
	// ChainID id of the blockchain network where the transaction is sent to.
	ChainID entities.HexInt256
	// AccessList is a list of addresses and storage keys the transaction accesses.
	AccessList AccessList
	// Signature transaction signature with Y parity.
	Signature *YParityTransactionSignature
}

// eip1559TypePrefix is the transaction type byte for EIP-1559.
const eip1559TypePrefix = 0x02

// typedTxEnvelope is the EIP-2718 envelope of a typed transaction: the transaction type prefix byte and
// the list of fields the signature commits to, in the order the relevant EIP defines.
type typedTxEnvelope struct {
	prefix byte
	fields []interface{}
}

func hashTypedTx(envelope typedTxEnvelope) (*entities.HexBytes, error) {
	rlpEncoded, err := rlp.Encode(envelope.fields)
	if err != nil {
		return nil, errors.InternalFromErr(err).WithMessage("failed to RLP encode the type %d payload to sign", envelope.prefix)
	}

	hash, err := hashKeccak256(append([]byte{envelope.prefix}, rlpEncoded...))
	if err != nil {
		return nil, errors.InternalFromErr(err).WithMessage("failed to calculate the Keccak256 of the type %d payload", envelope.prefix)
	}

	return entities.NewHexBytes(hash), nil
}

// encodeTypedTx RLP encodes a typed transaction for the wire:
// prefix || rlp(fields ++ [yParity, r, s]).
func encodeTypedTx(envelope typedTxEnvelope, signature *YParityTransactionSignature) (*entities.HexBytes, error) {
	if signature == nil {
		return nil, errors.Internal().WithMessage("tx doesn't have a signature so it can't be RLP encoded")
	}

	signed := make([]interface{}, 0, len(envelope.fields)+3)
	signed = append(signed, envelope.fields...)
	signed = append(signed, signature.YParity.BigInt(), signature.R.BigInt(), signature.S.BigInt())

	rlpEncoded, err := rlp.Encode(signed)
	if err != nil {
		return nil, errors.InternalFromErr(err).WithMessage("failed to RLP encode the type %d transaction", envelope.prefix)
	}

	return entities.NewHexBytes(append([]byte{envelope.prefix}, rlpEncoded...)), nil
}

// chainIDToRLPBytes converts a chain ID to its big-endian byte representation for RLP encoding.
func chainIDToRLPBytes(chainID entities.HexInt256) ([]byte, error) {
	hexBytes, err := entities.NewHexBytesFromString(hexStringEvenLength(chainID.String()))
	if err != nil {
		return nil, errors.InternalFromErr(err).WithMessage("failed to calculate the HexBytes from chain ID")
	}
	return hexBytes.Bytes(), nil
}

func nonZeroOrNil(amount entities.HexInt256) *big.Int {
	if amount.BigInt().Sign() == 0 {
		return nil
	}
	return amount.BigInt()
}

// accessListToRLPInterface converts an AccessList to the nested []interface{} structure for RLP encoding.
// An Address is a fixed 20-byte array and a storage key a fixed 32-byte array, so both are taken as bytes
// directly: there is no encoding step here that can fail.
func accessListToRLPInterface(accessList AccessList) []interface{} {
	result := make([]interface{}, len(accessList))
	for i, entry := range accessList {
		storageKeys := make([]interface{}, len(entry.StorageKeys))
		for j, key := range entry.StorageKeys {
			storageKeys[j] = key.Bytes()
		}
		result[i] = []interface{}{
			entry.Address[:],
			storageKeys,
		}
	}
	return result
}

// prepareCommonFields converts common transaction fields to their RLP-ready representations.
func prepareCommonFields(nonce entities.HexUInt64, gas entities.HexUInt64, to *address.Address, value *entities.HexInt256, txData entities.HexBytes) (nonceBytes []byte, gasBytes []byte, toBytes []byte, valueBigInt *big.Int, data []byte, err error) {
	nonceHex, err := entities.NewHexBytesFromString(hexStringEvenLength(nonce.String()))
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Internal().WithMessage("could not convert 'nonce' to hex bytes")
	}
	nonceBytes = nonceHex.Bytes()
	if nonce.Uint64() == 0 {
		nonceBytes = []byte{}
	}

	gasHex, err := entities.NewHexBytesFromString(hexStringEvenLength(gas.String()))
	if err != nil {
		return nil, nil, nil, nil, nil, errors.Internal().WithMessage("could not convert 'gas' to hex bytes")
	}
	gasBytes = gasHex.Bytes()

	if to != nil {
		hexBytes, newErr := entities.NewHexBytesFromString(to.String())
		if newErr != nil {
			return nil, nil, nil, nil, nil, errors.Internal().WithMessage("could not convert 'to' to hex bytes")
		}
		toBytes = hexBytes.Bytes()
	} else {
		toBytes = []byte{}
	}

	if value != nil && value.BigInt().Sign() != 0 {
		valueBigInt = value.BigInt()
	}

	if len(txData.Bytes()) > 0 {
		hexBytes, newErr := entities.NewHexBytesFromString(txData.String())
		if newErr != nil {
			return nil, nil, nil, nil, nil, errors.Internal().WithMessage("could not convert 'data' to hex bytes")
		}
		data = hexBytes.Bytes()
	} else {
		data = []byte{}
	}

	return nonceBytes, gasBytes, toBytes, valueBigInt, data, nil
}

// RLPEncode RLP encodes the EIP-2930 transaction (including its signature).
// The result is 0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, signatureYParity, signatureR, signatureS])
func (tx EIP2930Transaction) RLPEncode() (*entities.HexBytes, error) {
	envelope, err := tx.envelope()
	if err != nil {
		return nil, err
	}
	return encodeTypedTx(*envelope, tx.Signature)
}

// Hash calculates the EIP-2930 transaction hash for signing.
// The hash is keccak256(0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList]))
func (tx EIP2930Transaction) Hash() (*entities.HexBytes, error) {
	envelope, err := tx.envelope()
	if err != nil {
		return nil, err
	}
	return hashTypedTx(*envelope)
}

// envelope returns the EIP-2930 type prefix and the field list its signature commits to:
// [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList]
func (tx EIP2930Transaction) envelope() (*typedTxEnvelope, error) {
	nonceBytes, gasBytes, toBytes, value, data, err := prepareCommonFields(tx.Nonce, tx.Gas, tx.To, tx.Value, tx.Data)
	if err != nil {
		return nil, err
	}

	chainID, err := chainIDToRLPBytes(tx.ChainID)
	if err != nil {
		return nil, err
	}

	accessListRLP := accessListToRLPInterface(tx.AccessList)

	return &typedTxEnvelope{
		prefix: eip2930TypePrefix,
		fields: []interface{}{
			chainID,
			&nonceBytes,
			nonZeroOrNil(tx.GasPrice),
			gasBytes,
			toBytes,
			value,
			data,
			accessListRLP,
		},
	}, nil
}

// RLPEncode RLP encodes the EIP-1559 transaction (including its signature).
// The result is 0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, signatureYParity, signatureR, signatureS])
func (tx EIP1559Transaction) RLPEncode() (*entities.HexBytes, error) {
	envelope, err := tx.envelope()
	if err != nil {
		return nil, err
	}
	return encodeTypedTx(*envelope, tx.Signature)
}

// Hash calculates the EIP-1559 transaction hash for signing.
// The hash is keccak256(0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList]))
func (tx EIP1559Transaction) Hash() (*entities.HexBytes, error) {
	envelope, err := tx.envelope()
	if err != nil {
		return nil, err
	}
	return hashTypedTx(*envelope)
}

// envelope returns the EIP-1559 type prefix and the field list its signature commits to:
// [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList]
func (tx EIP1559Transaction) envelope() (*typedTxEnvelope, error) {
	nonceBytes, gasBytes, toBytes, value, data, err := prepareCommonFields(tx.Nonce, tx.Gas, tx.To, tx.Value, tx.Data)
	if err != nil {
		return nil, err
	}

	chainID, err := chainIDToRLPBytes(tx.ChainID)
	if err != nil {
		return nil, err
	}

	accessListRLP := accessListToRLPInterface(tx.AccessList)

	return &typedTxEnvelope{
		prefix: eip1559TypePrefix,
		fields: []interface{}{
			chainID,
			&nonceBytes,
			nonZeroOrNil(tx.MaxPriorityFeePerGas),
			nonZeroOrNil(tx.MaxFeePerGas),
			gasBytes,
			toBytes,
			value,
			data,
			accessListRLP,
		},
	}, nil
}

func hexStringEvenLength(input string) string {
	result := input
	if len(input)%2 != 0 {
		result = "0x0" + input[2:]
	}
	return result
}
