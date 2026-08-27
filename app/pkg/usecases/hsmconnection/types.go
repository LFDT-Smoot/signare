package hsmconnection

import (
	"log/slog"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmslot"
)

// ByApplicationInput input to get an HSMConnector given an application.
type ByApplicationInput struct {
	// ApplicationID identifier of the application.
	ApplicationID string
}

// HSMConnection HSM connection details.
type HSMConnection struct {
	Slot hsmslot.HSMSlot
	// ModuleKind type of the HSM module.
	ModuleKind hsmconnector.ModuleKind
	// ApplicationDefaultChainID application's chain ID.
	ApplicationDefaultChainID entities.Int256
}

// LogValue implements slog.LogValuer so that logging an HSMConnection does not print the slot it
// carries. HSMSlot redacts itself when logged directly, but slog does not resolve LogValuer on a
// struct field, so without this the whole slot, including its PIN, would be marshalled.
func (c HSMConnection) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("slot", c.Slot),
		slog.String("moduleKind", string(c.ModuleKind)),
	)
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
