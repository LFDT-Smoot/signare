package hsmslot

import (
	"context"
	"fmt"
	"strings"

	"github.com/lfdt-smoot/signare/app/pkg/commons/persistence"
	"github.com/lfdt-smoot/signare/app/pkg/commons/time"
	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/application"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmmodule"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/referentialintegrity"
	"github.com/lfdt-smoot/signare/app/pkg/utils"

	"github.com/asaskevich/govalidator"
	"github.com/google/uuid"
)

const (
	defaultOrderDirection = entities.OrderDesc
)

// HSMSlotUseCase defines the management of HSMSlot in storage.
type HSMSlotUseCase interface {
	// CreateHSMSlot creates a HSMSlot in storage and returns an error if it fails.
	CreateHSMSlot(ctx context.Context, input CreateHSMSlotInput) (*CreateHSMSlotOutput, error)
	// GetHSMSlot gets an HSMSlot by its ID in storage and returns an error if it fails.
	GetHSMSlot(ctx context.Context, input GetHSMSlotInput) (*GetHSMSlotOutput, error)
	// GetHSMSlotByApplication gets the HSMSlot for the specified application in storage and returns an error if it fails.
	GetHSMSlotByApplication(ctx context.Context, input GetHSMSlotByApplicationInput) (*GetHSMSlotByApplicationOutput, error)
	// EditPinSource edits the PinSource of an HSMSlot in storage and returns an error if it fails.
	EditPinSource(ctx context.Context, input EditPinSourceInput) (*EditPinSourceOutput, error)
	// VerifyPinSource checks that an HSMSlot's current PinSource opens the slot and returns an error if it fails.
	VerifyPinSource(ctx context.Context, input VerifyPinSourceInput) (*VerifyPinSourceOutput, error)
	// EditConfig edits the config of an HSMSlot in storage and returns an error if it fails.
	EditConfig(ctx context.Context, input EditConfigInput) (*EditConfigOutput, error)
	// DeleteHSMSlot deletes a HSMSlot in storage and returns an error if it fails.
	DeleteHSMSlot(ctx context.Context, input DeleteHSMSlotInput) (*DeleteHSMSlotOutput, error)
	// ListHSMSlotsByApplication lists HSMSlot for a specific application in storage and returns an error if it fails.
	ListHSMSlotsByApplication(ctx context.Context, input ListHSMSlotsByApplicationInput) (*ListHSMSlotsByApplicationOutput, error)
	// ListHSMSlotsByHSMModule lists HSMSlot for a specific HSM in storage and returns an error if it fails.
	ListHSMSlotsByHSMModule(ctx context.Context, input ListHSMSlotsByHSMModuleInput) (*ListHSMSlotsByHSMModuleOutput, error)
	// AddLocalKey adds a local key to the slot's configuration (only compatible with modules of kind LKV)
	AddLocalKey(ctx context.Context, input AddLocalKeyInput) error
	// RemoveLocalKey removes a local key from the slot's configuration (only compatible with modules of kind LKV)
	RemoveLocalKey(ctx context.Context, input RemoveLocalKeyInput) error
	// ListLocalKeys list all local keys from the slot's configuration (only compatible with modules of kind LKV)
	ListLocalKeys(ctx context.Context, input ListLocalKeysInput) (*ListLocalKeysOutput, error)
}

func (u *DefaultUseCase) CreateHSMSlot(ctx context.Context, input CreateHSMSlotInput) (*CreateHSMSlotOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	getHSMModuleInput := hsmmodule.GetHSMModuleInput{
		StandardID: entities.StandardID{ID: input.HSMModuleID},
	}
	getHSMOutput, getHSMErr := u.hsmModuleUseCase.GetHSMModule(ctx, getHSMModuleInput)
	if getHSMErr != nil {
		if errors.IsNotFound(getHSMErr) {
			msg := fmt.Sprintf("slot '%s' in HSM '%s' is not reachable", input.Slot, input.HSMModuleID)
			return nil, errors.PreconditionFailedFromErr(getHSMErr).WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
		}
		return nil, errors.InternalFromErr(getHSMErr)
	}

	// A PIN only means anything to a PKCS#11 module, so a source is mandatory for one and refused for the
	// others rather than stored and never read.
	if getHSMOutput.Kind == hsmmodule.SoftHSMModuleKind {
		if len(input.PinSource) == 0 {
			msg := fmt.Sprintf("a 'pinSource' is required for a slot in the HSM module '%s'", input.HSMModuleID)
			return nil, errors.InvalidArgument().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
		}
		if validateErr := hsmconnector.ValidatePinSource(input.PinSource); validateErr != nil {
			return nil, validateErr
		}
	} else if len(input.PinSource) > 0 {
		msg := fmt.Sprintf("a 'pinSource' cannot be set for a slot in the HSM module '%s', which is of kind %s", input.HSMModuleID, getHSMOutput.Kind)
		return nil, errors.InvalidArgument().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
	}

	if getHSMOutput.Kind == hsmmodule.SoftHSMModuleKind {
		resetInput := hsmconnector.ResetInput{
			ModuleKind: hsmconnector.ModuleKind(getHSMOutput.Kind),
		}
		_, resetErr := u.hsmConnector.Reset(ctx, resetInput)
		if resetErr != nil {
			return nil, resetErr
		}

		findSlotInput := hsmconnector.IsAliveInput{
			Slot:       input.Slot,
			PinSource:  input.PinSource,
			ModuleKind: hsmconnector.ModuleKind(getHSMOutput.Kind),
		}
		isAliveOutput, isAliveErr := u.hsmConnector.IsAlive(ctx, findSlotInput)
		if isAliveErr != nil {
			if errors.IsPreconditionFailed(isAliveErr) {
				return nil, isAliveErr
			}
			return nil, errors.InternalFromErr(isAliveErr)
		}
		if !isAliveOutput.IsAlive {
			msg := fmt.Sprintf("slot %s is not reachable in the HSM module '%s'", input.Slot, input.HSMModuleID)
			return nil, errors.PreconditionFailed().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
		}
	}

	hsmSlot, createSlotErr := u.createSlot(ctx, input)
	if createSlotErr != nil {
		if errors.IsAlreadyExists(createSlotErr) {
			return nil, errors.AlreadyExistsFromErr(createSlotErr)
		}
		if errors.IsPreconditionFailed(createSlotErr) {
			return nil, createSlotErr
		}
		return nil, errors.InternalFromErr(createSlotErr)
	}

	return &CreateHSMSlotOutput{
		HSMSlot: *hsmSlot,
	}, nil
}

func (u *DefaultUseCase) GetHSMSlot(ctx context.Context, input GetHSMSlotInput) (*GetHSMSlotOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	slot, err := u.hsmSlotStorage.Get(ctx, input.StandardID)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.NotFoundFromErr(err).WithMessage("hsm slot [%s] not found", input.ID)
		}
		return nil, errors.InternalFromErr(err)
	}

	return &GetHSMSlotOutput{
		HSMSlot: *slot,
	}, nil
}

func (u *DefaultUseCase) GetHSMSlotByApplication(ctx context.Context, input GetHSMSlotByApplicationInput) (*GetHSMSlotByApplicationOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	slot, err := u.hsmSlotStorage.GetByApplication(ctx, input.ApplicationID)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.NotFoundFromErr(err).WithMessage("hsm slot not found for application [%s] not found", input.ApplicationID)
		}
		return nil, errors.InternalFromErr(err)
	}

	return &GetHSMSlotByApplicationOutput{
		HSMSlot: *slot,
	}, nil
}

func (u *DefaultUseCase) EditPinSource(ctx context.Context, input EditPinSourceInput) (*EditPinSourceOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}
	if validateErr := hsmconnector.ValidatePinSource(input.PinSource); validateErr != nil {
		return nil, validateErr
	}

	slot, moduleKind, err := u.pkcs11SlotOf(ctx, input.StandardID, input.HSMModuleID)
	if err != nil {
		return nil, err
	}

	// Proven to open the slot before it is stored, so a wrong secret is rejected here rather than on the
	// next signature.
	if err = u.assertSlotAlive(ctx, slot.Slot, input.PinSource, moduleKind); err != nil {
		return nil, err
	}

	edited, err := u.hsmSlotStorage.EditPinSource(ctx, HSMSlot{
		StandardResourceMeta: entities.StandardResourceMeta{
			StandardResource: entities.StandardResource{
				StandardID: input.StandardID,
				Timestamps: entities.Timestamps{
					LastUpdate: time.Now(),
				},
			},
			ResourceVersion: input.ResourceVersion,
		},
		PinSource: input.PinSource,
	})
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.NotFoundFromErr(err).WithMessage("hsm slot [%s] not found", input.ID)
		}
		return nil, errors.InternalFromErr(err)
	}

	return &EditPinSourceOutput{
		HSMSlot: *edited,
	}, nil
}

// VerifyPinSource checks the slot's stored source against the HSM without changing anything. Run after
// rotating a secret out of band; a success also closes a breaker opened by an earlier refused PIN.
func (u *DefaultUseCase) VerifyPinSource(ctx context.Context, input VerifyPinSourceInput) (*VerifyPinSourceOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	slot, moduleKind, err := u.pkcs11SlotOf(ctx, input.StandardID, input.HSMModuleID)
	if err != nil {
		return nil, err
	}

	if len(slot.PinSource) == 0 {
		msg := fmt.Sprintf("slot %s has no 'pinSource' to verify", slot.ID)
		return nil, errors.PreconditionFailed().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
	}

	if err = u.assertSlotAlive(ctx, slot.Slot, slot.PinSource, moduleKind); err != nil {
		return nil, err
	}

	return &VerifyPinSourceOutput{
		HSMSlot: slot.HSMSlot,
	}, nil
}

// pkcs11SlotOf loads a slot and confirms it belongs to the named module and that the module
// authenticates with a PIN.
func (u *DefaultUseCase) pkcs11SlotOf(ctx context.Context, id entities.StandardID, hsmModuleID string) (*GetHSMSlotOutput, hsmconnector.ModuleKind, error) {
	slot, err := u.GetHSMSlot(ctx, GetHSMSlotInput{StandardID: id})
	if err != nil {
		return nil, "", err
	}

	if slot.HSMModuleID != hsmModuleID {
		msg := fmt.Sprintf("slot doesn't exist in the HSM module '%s'", hsmModuleID)
		return nil, "", errors.NotFound().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
	}

	module, getHSMErr := u.hsmModuleUseCase.GetHSMModule(ctx, hsmmodule.GetHSMModuleInput{
		StandardID: entities.StandardID{ID: slot.HSMModuleID},
	})
	if getHSMErr != nil {
		if errors.IsNotFound(getHSMErr) {
			msg := fmt.Sprintf("HSM '%s' assigned to this slot does not exist", slot.HSMModuleID)
			return nil, "", errors.PreconditionFailedFromErr(getHSMErr).WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
		}
		return nil, "", errors.InternalFromErr(getHSMErr)
	}

	if module.Kind != hsmmodule.SoftHSMModuleKind {
		msg := fmt.Sprintf("cannot operate on a pin source: configured HSM '%s' is not of kind %s", module.ID, hsmmodule.SoftHSMModuleKind)
		return nil, "", errors.PreconditionFailed().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
	}

	return slot, hsmconnector.ModuleKind(module.Kind), nil
}

// assertSlotAlive fails unless the PIN named by source opens the slot.
func (u *DefaultUseCase) assertSlotAlive(ctx context.Context, slot string, source string, moduleKind hsmconnector.ModuleKind) error {
	isAliveOutput, isAliveErr := u.hsmConnector.IsAlive(ctx, hsmconnector.IsAliveInput{
		Slot:       slot,
		PinSource:  source,
		ModuleKind: moduleKind,
	})
	if isAliveErr != nil {
		if errors.IsPreconditionFailed(isAliveErr) || errors.IsInvalidArgument(isAliveErr) {
			return isAliveErr
		}
		return errors.InternalFromErr(isAliveErr)
	}
	if !isAliveOutput.IsAlive {
		msg := fmt.Sprintf("slot %s is not reachable, the pin named by '%s' might be incorrect", slot, source)
		return errors.PreconditionFailed().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
	}
	return nil
}

func (u *DefaultUseCase) EditConfig(ctx context.Context, input EditConfigInput) (*EditConfigOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}
	getHSMSlotInput := GetHSMSlotInput{
		StandardID: input.StandardID,
	}
	getHSMSlotOutput, getHSMSlotErr := u.GetHSMSlot(ctx, getHSMSlotInput)
	if getHSMSlotErr != nil {
		return nil, getHSMSlotErr
	}

	if getHSMSlotOutput.HSMModuleID != input.HSMModuleID {
		msg := fmt.Sprintf("slot doesn't exist in the HSM module '%s'", input.HSMModuleID)
		return nil, errors.NotFound().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
	}

	getHSMModuleInput := hsmmodule.GetHSMModuleInput{
		StandardID: entities.StandardID{ID: getHSMSlotOutput.HSMModuleID},
	}
	getHSMOutput, getHSMErr := u.hsmModuleUseCase.GetHSMModule(ctx, getHSMModuleInput)
	if getHSMErr != nil {
		if errors.IsNotFound(getHSMErr) {
			msg := fmt.Sprintf("HSM '%s' assigned to this slot does not exist", getHSMSlotOutput.HSMModuleID)
			return nil, errors.PreconditionFailedFromErr(getHSMErr).WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
		}
		return nil, errors.InternalFromErr(getHSMErr)
	}

	if getHSMOutput.Kind != hsmmodule.AKVModuleKind {
		msg := fmt.Sprintf("cannot update config: configured HSM '%s' is not of kind %s", getHSMOutput.ID, hsmmodule.AKVModuleKind)
		return nil, errors.PreconditionFailed().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
	}

	slot := HSMSlot{
		StandardResourceMeta: entities.StandardResourceMeta{
			StandardResource: entities.StandardResource{
				StandardID: input.StandardID,
				Timestamps: entities.Timestamps{
					LastUpdate: time.Now(),
				},
			},
			ResourceVersion: input.ResourceVersion,
		},
		HSMModuleID: getHSMOutput.ID,
		Config:      input.Config,
	}
	editedSlot, err := u.hsmSlotStorage.EditConfig(ctx, slot)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.NotFoundFromErr(err).WithMessage("hsm slot [%s] not found", input.ID)
		}
		return nil, errors.InternalFromErr(err)
	}

	return &EditConfigOutput{
		HSMSlot: *editedSlot,
	}, nil
}

func (u *DefaultUseCase) DeleteHSMSlot(ctx context.Context, input DeleteHSMSlotInput) (*DeleteHSMSlotOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}
	removeAllDependenciesErr := u.removeAllDependencies(ctx, input.StandardID)
	if removeAllDependenciesErr != nil {
		return nil, removeAllDependenciesErr
	}

	removedSlot, err := u.hsmSlotStorage.Remove(ctx, input.StandardID)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.NotFoundFromErr(err).WithMessage("hsm slot [%s] not found", input.ID)
		}
		return nil, errors.InternalFromErr(err)
	}

	return &DeleteHSMSlotOutput{
		HSMSlot: *removedSlot,
	}, nil
}

func (u *DefaultUseCase) ListHSMSlotsByApplication(ctx context.Context, input ListHSMSlotsByApplicationInput) (*ListHSMSlotsByApplicationOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	filters := u.hsmSlotStorage.Filter()
	filters.FilterByApplicationID(input.ApplicationID)

	direction := utils.DefaultString(input.OrderDirection, defaultOrderDirection)
	direction, validDirection := entities.NormalizeOrderDirection(direction)
	if !validDirection {
		return nil, errors.InvalidArgument().SetHumanReadableMessage("invalid order direction %q, expected one of [asc, desc]", input.OrderDirection)
	}
	filters.OrderByCreationDate(persistence.OrderDirection(direction))
	if input.OrderBy == entities.OrderByLastUpdate {
		filters.OrderByLastUpdateDate(persistence.OrderDirection(direction))
	}

	filters.Paged(persistence.ClampPageLimit(input.PageLimit), input.PageOffset)

	slotCollection, err := u.hsmSlotStorage.All(ctx, filters)
	if err != nil {
		return nil, errors.InternalFromErr(err)
	}

	return &ListHSMSlotsByApplicationOutput{
		HSMSlotCollection: *slotCollection,
	}, nil
}

func (u *DefaultUseCase) ListHSMSlotsByHSMModule(ctx context.Context, input ListHSMSlotsByHSMModuleInput) (*ListHSMSlotsByHSMModuleOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	filters := u.hsmSlotStorage.Filter()
	filters.FilterByHSMModuleID(input.HSMModuleID)

	if input.ApplicationID != nil {
		filters.FilterByApplicationID(entities.StandardID{ID: *input.ApplicationID})
	}

	direction := utils.DefaultString(input.OrderDirection, defaultOrderDirection)
	direction, validDirection := entities.NormalizeOrderDirection(direction)
	if !validDirection {
		return nil, errors.InvalidArgument().SetHumanReadableMessage("invalid order direction %q, expected one of [asc, desc]", input.OrderDirection)
	}
	filters.OrderByCreationDate(persistence.OrderDirection(direction))
	if input.OrderBy == entities.OrderByLastUpdate {
		filters.OrderByLastUpdateDate(persistence.OrderDirection(direction))
	}

	filters.Paged(persistence.ClampPageLimit(input.PageLimit), input.PageOffset)

	slotCollection, err := u.hsmSlotStorage.All(ctx, filters)
	if err != nil {
		return nil, errors.InternalFromErr(err)
	}

	return &ListHSMSlotsByHSMModuleOutput{
		HSMSlotCollection: *slotCollection,
	}, nil
}

func (u *DefaultUseCase) AddLocalKey(ctx context.Context, input AddLocalKeyInput) error {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}
	getHSMSlotInput := GetHSMSlotInput{
		StandardID: input.StandardID,
	}
	storedSlot, getHSMSlotErr := u.GetHSMSlot(ctx, getHSMSlotInput)
	if getHSMSlotErr != nil {
		return getHSMSlotErr
	}

	getHSMModuleInput := hsmmodule.GetHSMModuleInput{
		StandardID: entities.StandardID{ID: storedSlot.HSMModuleID},
	}
	storedHSM, getHSMErr := u.hsmModuleUseCase.GetHSMModule(ctx, getHSMModuleInput)
	if getHSMErr != nil {
		if errors.IsNotFound(getHSMErr) {
			msg := fmt.Sprintf("HSM '%s' assigned to this slot does not exist", storedSlot.HSMModuleID)
			return errors.PreconditionFailedFromErr(getHSMErr).WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
		}
		return errors.InternalFromErr(getHSMErr)
	}

	if storedHSM.Kind != hsmmodule.LKVModuleKind {
		msg := fmt.Sprintf("cannot add local key: configured HSM '%s' is not of kind %s", storedHSM.ID, hsmmodule.LKVModuleKind)
		return errors.PreconditionFailed().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
	}

	if storedSlot.Config.LocalKeyVault == nil {
		storedSlot.Config.LocalKeyVault = &LocalKeyVaultConfig{
			KeyStore: make(map[address.Address]string),
		}
	}

	if _, exists := storedSlot.Config.LocalKeyVault.KeyStore[input.Address]; exists {
		return errors.AlreadyExists().WithMessage("address [%s] already exists in local key vault for slot [%s]", input.Address.String(), storedSlot.ID)
	}

	storedSlot.Config.LocalKeyVault.KeyStore[input.Address] = strings.TrimPrefix(input.PrivateKey.String(), "0x")
	storedSlot.LastUpdate = time.Now()

	_, err = u.hsmSlotStorage.EditConfig(ctx, storedSlot.HSMSlot)
	if err != nil {
		if errors.IsNotFound(err) {
			return errors.NotFoundFromErr(err).WithMessage("hsm slot [%s] not found", input.ID)
		}
		return errors.InternalFromErr(err)
	}
	return nil
}

func (u *DefaultUseCase) RemoveLocalKey(ctx context.Context, input RemoveLocalKeyInput) error {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}
	getHSMSlotInput := GetHSMSlotInput{
		StandardID: input.StandardID,
	}
	storedSlot, getHSMSlotErr := u.GetHSMSlot(ctx, getHSMSlotInput)
	if getHSMSlotErr != nil {
		return getHSMSlotErr
	}

	getHSMModuleInput := hsmmodule.GetHSMModuleInput{
		StandardID: entities.StandardID{ID: storedSlot.HSMModuleID},
	}
	storedHSM, getHSMErr := u.hsmModuleUseCase.GetHSMModule(ctx, getHSMModuleInput)
	if getHSMErr != nil {
		if errors.IsNotFound(getHSMErr) {
			msg := fmt.Sprintf("HSM '%s' assigned to this slot does not exist", storedSlot.HSMModuleID)
			return errors.PreconditionFailedFromErr(getHSMErr).WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
		}
		return errors.InternalFromErr(getHSMErr)
	}

	if storedHSM.Kind != hsmmodule.LKVModuleKind {
		msg := fmt.Sprintf("cannot remove local key: configured HSM '%s' is not of kind %s", storedHSM.ID, hsmmodule.LKVModuleKind)
		return errors.PreconditionFailed().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
	}

	if storedSlot.Config.LocalKeyVault == nil || storedSlot.Config.LocalKeyVault.KeyStore == nil {
		return errors.NotFound().WithMessage("address [%s] not found in local key vault for slot [%s]", input.Address.String(), storedSlot.ID)
	}

	if _, exists := storedSlot.Config.LocalKeyVault.KeyStore[input.Address]; !exists {
		return errors.NotFound().WithMessage("address [%s] not found in local key vault for slot [%s]", input.Address.String(), storedSlot.ID)
	}

	delete(storedSlot.Config.LocalKeyVault.KeyStore, input.Address)
	storedSlot.LastUpdate = time.Now()
	_, err = u.hsmSlotStorage.EditConfig(ctx, storedSlot.HSMSlot)
	if err != nil {
		if errors.IsNotFound(err) {
			return errors.NotFoundFromErr(err).WithMessage("hsm slot [%s] not found", input.ID)
		}
		return errors.InternalFromErr(err)
	}
	return nil
}

func (u *DefaultUseCase) ListLocalKeys(ctx context.Context, input ListLocalKeysInput) (*ListLocalKeysOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}
	getHSMSlotInput := GetHSMSlotInput(input)
	storedSlot, getHSMSlotErr := u.GetHSMSlot(ctx, getHSMSlotInput)
	if getHSMSlotErr != nil {
		return nil, getHSMSlotErr
	}

	getHSMModuleInput := hsmmodule.GetHSMModuleInput{
		StandardID: entities.StandardID{ID: storedSlot.HSMModuleID},
	}
	storedHSM, getHSMErr := u.hsmModuleUseCase.GetHSMModule(ctx, getHSMModuleInput)
	if getHSMErr != nil {
		if errors.IsNotFound(getHSMErr) {
			msg := fmt.Sprintf("HSM '%s' assigned to this slot does not exist", storedSlot.HSMModuleID)
			return nil, errors.PreconditionFailedFromErr(getHSMErr).WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
		}
		return nil, errors.InternalFromErr(getHSMErr)
	}

	if storedHSM.Kind != hsmmodule.LKVModuleKind {
		msg := fmt.Sprintf("cannot list local keys: configured HSM '%s' is not of kind %s", storedHSM.ID, hsmmodule.LKVModuleKind)
		return nil, errors.PreconditionFailed().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
	}

	storedAddresses := make([]address.Address, 0)
	if storedSlot.Config.LocalKeyVault != nil && storedSlot.Config.LocalKeyVault.KeyStore != nil {
		for addr := range storedSlot.Config.LocalKeyVault.KeyStore {
			storedAddresses = append(storedAddresses, addr)
		}
	}
	return &ListLocalKeysOutput{
		Addresses: storedAddresses,
	}, nil
}

func (u *DefaultUseCase) createSlot(ctx context.Context, input CreateHSMSlotInput) (*HSMSlot, error) {
	now := time.Now()
	if input.ID == nil {
		randomID := uuid.NewString()
		input.ID = &randomID
	}

	hsmSlot := HSMSlot{
		StandardResourceMeta: entities.StandardResourceMeta{
			StandardResource: entities.StandardResource{
				StandardID: entities.StandardID{
					ID: *input.ID,
				},
				Timestamps: entities.Timestamps{
					CreationDate: now,
					LastUpdate:   now,
				},
			},
		},
		ApplicationID: input.ApplicationID,
		HSMModuleID:   input.HSMModuleID,
		Slot:          input.Slot,
		PinSource:     input.PinSource,
		Config:        input.Config,
	}
	hsmSlot.InternalResourceID = entities.NewInternalResourceID()

	addApplicationDependencyErr := u.addApplicationDependency(ctx, hsmSlot)
	if addApplicationDependencyErr != nil {
		return nil, addApplicationDependencyErr
	}

	addHSMModuleDependencyErr := u.addHSMModuleDependency(ctx, hsmSlot)
	if addHSMModuleDependencyErr != nil {
		return nil, addHSMModuleDependencyErr
	}

	addedSlot, err := u.hsmSlotStorage.Add(ctx, hsmSlot)
	if err != nil {
		if errors.IsAlreadyExists(err) {
			return nil, errors.AlreadyExistsFromErr(err).SetHumanReadableMessage("hsm slot [%s] already exists", hsmSlot.ID)
		}
		return nil, errors.InternalFromErr(err)
	}

	return addedSlot, nil
}

var _ HSMSlotUseCase = new(DefaultUseCase)

// DefaultUseCaseOptions configures a DefaultUseCase.
type DefaultUseCaseOptions struct {
	// HSMSlotStorage is the persistence adapter of the HSMSlot.
	HSMSlotStorage HSMSlotStorage

	// ApplicationUseCase defines how to interact with Application resources.
	ApplicationUseCase application.ApplicationUseCase
	// HSMModuleUseCase defines how to interact with HSMModule resources.
	HSMModuleUseCase hsmmodule.HSMModuleUseCase
	// HSMConnector connects with the HSM and operates with it.
	HSMConnector hsmconnector.HSMConnector
	// ReferentialIntegrityUseCase to manage dependencies between resources.
	ReferentialIntegrityUseCase referentialintegrity.ReferentialIntegrityUseCase
}

// DefaultUseCase default management of User in configuration implementation.
type DefaultUseCase struct {
	// hsmSlotStorage is the persistence adapter of the HSMSlot.
	hsmSlotStorage HSMSlotStorage

	// applicationUseCase defines how to interact with Application resources.
	applicationUseCase application.ApplicationUseCase
	// hsmModuleUseCase defines how to interact with HSMModule resources.
	hsmModuleUseCase hsmmodule.HSMModuleUseCase
	// hsmConnector connects with the HSM and operates with it.
	hsmConnector hsmconnector.HSMConnector
	// referentialIntegrityUseCase to manage dependencies between resources.
	referentialIntegrityUseCase referentialintegrity.ReferentialIntegrityUseCase
}

// ProvideDefaultUseCase creates a DefaultUseCase with the given options.
func ProvideDefaultUseCase(options DefaultUseCaseOptions) (*DefaultUseCase, error) {
	if options.ApplicationUseCase == nil {
		return nil, errors.Internal().WithMessage("mandatory 'ApplicationUseCase' was not provided")
	}
	if options.HSMConnector == nil {
		return nil, errors.Internal().WithMessage("mandatory 'HSMConnector' was not provided")
	}
	if options.HSMModuleUseCase == nil {
		return nil, errors.Internal().WithMessage("mandatory 'HSMModuleUseCase' was not provided")
	}
	if options.HSMSlotStorage == nil {
		return nil, errors.Internal().WithMessage("mandatory 'HSMSlotStorage' was not provided")
	}
	if options.ReferentialIntegrityUseCase == nil {
		return nil, errors.Internal().WithMessage("mandatory 'ReferentialIntegrityUseCase' was not provided")
	}

	return &DefaultUseCase{
		hsmConnector:                options.HSMConnector,
		hsmModuleUseCase:            options.HSMModuleUseCase,
		hsmSlotStorage:              options.HSMSlotStorage,
		applicationUseCase:          options.ApplicationUseCase,
		referentialIntegrityUseCase: options.ReferentialIntegrityUseCase,
	}, nil
}
