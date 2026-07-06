package hsmslot

import (
	"github.com/hyperledger-labs/signare/app/pkg/entities"
	"github.com/hyperledger-labs/signare/app/pkg/entities/address"
)

// HSMSlot defines the HSMSlot resource.
type HSMSlot struct {
	entities.StandardResourceMeta
	// InternalResourceID uniquely identifies an HSMSlot by a single ID.
	entities.InternalResourceID
	// ApplicationID defines the identifier of the Application of the HSMSlot.
	ApplicationID string `valid:"required"`
	// HSMModuleID defines the identifier of the module of the HSMSlot.
	HSMModuleID string `valid:"required"`
	// Slot defines the logical container on the HSM.
	Slot string `valid:"required"`
	// Pin defines the alphanumeric code used for authentication in the HSM.
	Pin string `valid:"required"`
	// Config defines the configuration for the HSM
	Config SlotConfig `valid:"required"`
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

// CreateHSMSlotInput configures the creation of an HSMSlot.
type CreateHSMSlotInput struct {
	// ID defines the identifier of the User resource.
	ID *string `valid:"optional"`
	// ApplicationID defines the identifier of the Application of the HSMSlot.
	ApplicationID string `valid:"required"`
	// HSMModuleID defines the identifier of the module of the HSMSlot.
	HSMModuleID string `valid:"required"`
	// Slot defines the logical container on the HSM.
	Slot string `valid:"optional"`
	// Pin defines the alphanumeric code used for authentication in the HSM.
	Pin string `valid:"optional"`
	// Config defines the configuration for the HSM
	Config SlotConfig `valid:"optional"`
}

// CreateHSMSlotOutput defines the output of creating an HSMSlot.
type CreateHSMSlotOutput struct {
	HSMSlot
}

// GetHSMSlotInput defines the input for getting an HSMSlot.
type GetHSMSlotInput struct {
	entities.StandardID
}

// GetHSMSlotOutput defines the output of getting an HSMSlot.
type GetHSMSlotOutput struct {
	HSMSlot
}

// GetHSMSlotByApplicationInput defines the input for getting an application's HSMSlot.
type GetHSMSlotByApplicationInput struct {
	ApplicationID entities.StandardID `valid:"required"`
}

// GetHSMSlotByApplicationOutput defines the output of getting an application's HSMSlot.
type GetHSMSlotByApplicationOutput struct {
	HSMSlot
}

// EditPinInput configures the update of an HSMSlot's Pin.
type EditPinInput struct {
	entities.StandardID
	// ResourceVersion resource version for resource locking.
	ResourceVersion string `valid:"required"`
	// Pin defines the alphanumeric code used for authentication in the HSM.
	Pin string `valid:"required"`
	// HSMModuleID represents the unique identifier of the slot's HSM.
	HSMModuleID string `valid:"required"`
}

// EditPinOutput defines the output of editing an HSMSlot's Pin.
type EditPinOutput struct {
	HSMSlot
}

// EditConfigInput configures the update of an HSMSlot's Config.
type EditConfigInput struct {
	entities.StandardID
	// ResourceVersion resource version for resource locking.
	ResourceVersion string `valid:"required"`
	// Config defines the configuration for the HSM
	Config SlotConfig `valid:"required"`
	// HSMModuleID represents the unique identifier of the slot's HSM.
	HSMModuleID string `valid:"required"`
}

// EditConfigOutput defines the output of editing an HSMSlot's Pin.
type EditConfigOutput struct {
	HSMSlot
}

// DeleteHSMSlotInput configures the deletion of an HSMSlot.
type DeleteHSMSlotInput struct {
	entities.StandardID
}

// DeleteHSMSlotOutput defines the output of deleting an HSMSlot.
type DeleteHSMSlotOutput struct {
	HSMSlot
}

// ListHSMSlotsByApplicationInput defines all possible options to list HSMSlot resources for a specific Application.
type ListHSMSlotsByApplicationInput struct {
	// ApplicationID defines the identifier of the Application of the HSMSlot resource.
	ApplicationID entities.StandardID
	// PageLimit maximum amount of HSMSlot in list output.
	PageLimit int `valid:"natural"`
	// PageOffset amount of HSMSlot elapsed in list output.
	PageOffset int `valid:"natural"`
	// OrderBy whether to order by last update date.
	OrderBy string `valid:"optional"`
	// OrderDirection the direction in which the list will be ordered base on the attribute selected in OrderBy.
	OrderDirection string `valid:"optional"`
}

// ListHSMSlotsByApplicationOutput defines the output of listing HSMSlots for a specific Application.
type ListHSMSlotsByApplicationOutput struct {
	HSMSlotCollection
}

// ListHSMSlotsByHSMModuleInput defines all possible options to list HSMSlot resources for a specific HSMModuleID.
type ListHSMSlotsByHSMModuleInput struct {
	// HSMModuleID defines the identifier of the HSMModuleID of the HSMSlot resource.
	HSMModuleID entities.StandardID
	// PageLimit maximum amount of HSMSlot in list output.
	PageLimit int `valid:"natural"`
	// PageOffset amount of HSMSlot elapsed in list output.
	PageOffset int `valid:"natural"`
	// OrderBy whether to order by last update date.
	OrderBy string `valid:"optional"`
	// OrderDirection the direction in which the list will be ordered base on the attribute selected in OrderBy.
	OrderDirection string `valid:"optional"`
	// ApplicationID the application that will be used to filter the slots of the list
	ApplicationID *string `valid:"optional"`
}

// AddLocalKeyInput configures the addition of a local key to a LKV HSMSlot's config.
type AddLocalKeyInput struct {
	entities.StandardID
	// PrivateKey to store.
	PrivateKey entities.HexBytes `valid:"hexBytes"`
	// Addresses derived from the private key.
	Address address.Address `valid:"address"`
}

// RemoveLocalKeyInput configures the removal of a local key from a LKV HSMSlot's config.
type RemoveLocalKeyInput struct {
	entities.StandardID
	// Addresses to remove from the local key vault.
	Address address.Address `valid:"address"`
}

// ListLocalKeysInput defines from which HSMSlot's config to list local keys from.
type ListLocalKeysInput struct {
	entities.StandardID
}

// ListLocalKeysOutput defines the output of listing local keys for a specific HSMSlot.
type ListLocalKeysOutput struct {
	Addresses []address.Address
}

// ListHSMSlotsByHSMModuleOutput defines the output of listing HSMSlots for a specific HSMModuleID.
type ListHSMSlotsByHSMModuleOutput struct {
	HSMSlotCollection
}

// HSMSlotCollection defines a collection of HSMSlot resources.
type HSMSlotCollection struct {
	// Items HSMSlot in collection.
	Items []HSMSlot
	// StandardCollectionPage is the page data of the collection.
	entities.StandardCollectionPage
}
