package signaturemanager

import (
	"github.com/lfdt-smoot/signare/app/pkg/commons/logger"
	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
)

// GenerateKeyInput for account generation requests.
type GenerateKeyInput struct {
	// Slot the slot to look for the keys
	Slot string
	// Pin the pin to authorize the user
	Pin string
	// Tracer to log what is needed
	Tracer logger.Tracer
}

// GenerateKeyOutput for account generation responses.
type GenerateKeyOutput struct {
	// Address derived from the generated public key.
	Address address.Address `json:"address"`
}

// DeriveAddressFromPrivateKeyInput for account import requests.
type DeriveAddressFromPrivateKeyInput struct {
	// PrivateKey
	PrivateKey entities.HexBytes
	// Tracer to log what is needed
	Tracer logger.Tracer
}

// DeriveAddressFromPrivateKeyOutput for account import responses.
type DeriveAddressFromPrivateKeyOutput struct {
	// Address derived from the private key's public key.
	Address address.Address `json:"address"`
}

// RemoveKeyInput for account removal requests.
type RemoveKeyInput struct {
	// Slot the slot to look for the keys
	Slot string
	// Pin the pin to authorize the user
	Pin string
	// Tracer to log what is needed
	Tracer logger.Tracer
	// Address identifies the key pair to remove.
	Address address.Address `json:"address"`
}

// RemoveKeyOutput for account removal responses.
type RemoveKeyOutput struct{}

// ListKeysInput for account listing requests.
type ListKeysInput struct {
	// Slot the slot to look for the keys
	Slot string
	// Pin the pin to authorize the user
	Pin string
	// Tracer to log what is needed
	Tracer logger.Tracer
}

// ListKeysOutput for account listing responses.
type ListKeysOutput struct {
	Items []address.Address `json:"items"`
}

// SignInput for transaction signing requests.
type SignInput struct {
	// Slot the slot to look for the keys
	Slot string
	// Pin the pin to authorize the user
	Pin string
	// Config of the slot.
	Config SlotConfig
	// Tracer to log what is needed
	Tracer logger.Tracer
	// From address identifying the private key to use.
	From address.Address
	// Data to sign.
	Data entities.HexBytes
}

// SlotConfig defines the configuration for a particular slot.
type SlotConfig struct {
	AKV           []AKVConfig
	LocalKeyVault *LocalKeyVaultConfig
}

// AKVConfig defines possible configurations for Azure Key Vault.
type AKVConfig struct {
	// KeyName is the name for the key to use in AKV
	KeyName string
	// KeyVersion is the version for the key to use in AKV
	KeyVersion string
	// KeyPublicAddress is the public address for the key to use in AKV
	KeyPublicAddress string
}

// LocalKeyVaultConfig defines possible configurations for Local Key Vault.
type LocalKeyVaultConfig struct {
	// KeyStore holds the stored addresses and its private keys
	KeyStore map[address.Address]string
}

// SignOutput for transaction signing responses.
type SignOutput struct {
	// Signature signed bytes
	Signature []byte
}

// CloseInput input to close connection and clean up resources.
type CloseInput struct {
	// Tracer to log what is needed
	Tracer logger.Tracer
}

// CloseOutput output closing the connection and cleaning up all the resources.
type CloseOutput struct{}

// OpenInput input to open connection
type OpenInput struct {
	// Tracer to log what is needed
	Tracer logger.Tracer
}

// OpenOutput output opening the connection.
type OpenOutput struct{}

// IsAliveInput input to check the healthiness of a slot
type IsAliveInput struct {
	// Slot the slot to look for the keys
	Slot string
	// Pin the pin to authorize the user
	Pin string
	// Tracer to log what is needed
	Tracer logger.Tracer
}

// IsAliveOutput response of the healthiness of a slot
type IsAliveOutput struct {
	// IsAlive is true if the slot is ready to be used
	IsAlive bool
}
