package hsmslot

import (
	"log/slog"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
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
	// PinSource names the secret holding the PIN. A reference, not a value: the PIN is resolved at login
	// time and never enters this struct.
	PinSource string `valid:"optional"`
	// Config defines the configuration for the HSM
	Config SlotConfig `valid:"required"`
}

// LogValue implements slog.LogValuer so that logging an HSMSlot emits only its identifying fields.
//
// Config may hold Local Key Vault private key material, so it is not emitted. This is a guard on the
// type rather than a fix at one call site: a tracer property or a wrapped error anywhere can otherwise
// put the whole struct in front of a handler, and the JSON handler would marshal every field.
//
// PinSource is emitted: it names a secret rather than holding one, the API returns it on SlotDetail,
// and it is what an operator needs to act on a slot that cannot open its token.
//
// It protects the value and pointer forms, which is what log call sites use. It does NOT extend to an
// HSMSlot reached inside a bare slice or map: slog resolves LogValuer on the attribute value itself,
// not on values nested inside it, so a handler marshals the raw struct in those cases.
// TestHSMSlot_LogValueDoesNotExtendIntoABareSlice pins that boundary. Log a slot directly, and give any
// type that carries one its own LogValue, as HSMConnection and HSMSlotCollection do.
func (s HSMSlot) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", s.ID),
		slog.String("applicationId", s.ApplicationID),
		slog.String("hsmModuleId", s.HSMModuleID),
		slog.String("slot", s.Slot),
		slog.String("pinSource", s.PinSource),
	)
}

// SlotConfig defines the configuration for a particular slot.
type SlotConfig struct {
	AKV           []AKVConfig          `valid:"optional"`
	LocalKeyVault *LocalKeyVaultConfig `valid:"optional"`
}

// LogValue implements slog.LogValuer so slot configuration cannot leak key material into a log
// record. Only the shape is reported, never the Local Key Vault key store.
func (c SlotConfig) LogValue() slog.Value {
	localKeys := 0
	if c.LocalKeyVault != nil {
		localKeys = len(c.LocalKeyVault.KeyStore)
	}
	return slog.GroupValue(
		slog.Int("akvEntries", len(c.AKV)),
		slog.Int("localKeyVaultEntries", localKeys),
	)
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

// LogValue implements slog.LogValuer so the key store cannot reach a log record. Only the entry count
// is reported, never an address or its private key.
//
// SlotConfig holds this as a pointer, and slog does not resolve LogValuer on a struct field, so the
// guard has to live here as well for it to hold when the config is logged on its own.
func (c LocalKeyVaultConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("entries", len(c.KeyStore)),
	)
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
	// PinSource names the secret holding the PIN. Mandatory for a PKCS#11 module and rejected for the
	// others, checked once the module kind is known.
	PinSource string `valid:"optional"`
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

// EditPinSourceInput configures the update of an HSMSlot's PinSource.
type EditPinSourceInput struct {
	entities.StandardID
	// ResourceVersion resource version for resource locking.
	ResourceVersion string `valid:"required"`
	// PinSource names the secret holding the PIN.
	PinSource string `valid:"required"`
	// HSMModuleID represents the unique identifier of the slot's HSM.
	HSMModuleID string `valid:"required"`
}

// EditPinSourceOutput defines the output of editing an HSMSlot's PinSource.
type EditPinSourceOutput struct {
	HSMSlot
}

// VerifyPinSourceInput configures the verification of an HSMSlot's current PinSource.
type VerifyPinSourceInput struct {
	entities.StandardID
	// HSMModuleID represents the unique identifier of the slot's HSM.
	HSMModuleID string `valid:"required"`
}

// VerifyPinSourceOutput defines the output of verifying an HSMSlot's PinSource.
type VerifyPinSourceOutput struct {
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

// EditConfigOutput defines the output of editing an HSMSlot's Config.
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

// LogValue implements slog.LogValuer so that logging a collection does not print the slots it carries.
// HSMSlot redacts itself when logged directly, but slog does not resolve LogValuer on slice elements,
// so without this every slot in the page, including its key material, would be marshalled.
func (c HSMSlotCollection) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("items", len(c.Items)),
		slog.Int("limit", c.Limit),
		slog.Int("offset", c.Offset),
		slog.Bool("moreItems", c.MoreItems),
	)
}
