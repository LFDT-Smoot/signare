package hsmslotdbout

import (
	"encoding/json"

	"github.com/lfdt-smoot/signare/app/pkg/commons/persistence"
	"github.com/lfdt-smoot/signare/app/pkg/commons/time"
	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/infra/storage/hsmslotdb"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmslot"
)

type slotConfigDB struct {
	AKV           []akvConfigDB          `json:"akv,omitempty"`
	LocalKeyVault *localKeyVaultConfigDB `json:"localKeyVault,omitempty"`
}

type akvConfigDB struct {
	KeyName          string `json:"keyName"`
	KeyVersion       string `json:"keyVersion"`
	KeyPublicAddress string `json:"keyPublicAddress"`
}

type localKeyVaultConfigDB struct {
	KeyStore map[string]string `json:"keyStore"`
}

func mapToSlotConfigDB(slotConfig hsmslot.SlotConfig) slotConfigDB {
	configDB := slotConfigDB{}

	configDB.AKV = make([]akvConfigDB, len(slotConfig.AKV))
	for i, akvConfig := range slotConfig.AKV {
		configDB.AKV[i] = akvConfigDB{
			KeyName:          akvConfig.KeyName,
			KeyVersion:       akvConfig.KeyVersion,
			KeyPublicAddress: akvConfig.KeyPublicAddress,
		}
	}
	if slotConfig.LocalKeyVault != nil {
		configDB.LocalKeyVault = &localKeyVaultConfigDB{
			KeyStore: make(map[string]string),
		}
		for k, v := range slotConfig.LocalKeyVault.KeyStore {
			configDB.LocalKeyVault.KeyStore[k.String()] = v
		}
	}
	return configDB
}

func mapFromSlotConfigDB(slotConfigDB slotConfigDB) (*hsmslot.SlotConfig, error) {
	slotConfig := &hsmslot.SlotConfig{}

	slotConfig.AKV = make([]hsmslot.AKVConfig, len(slotConfigDB.AKV))
	for i, akvConfig := range slotConfigDB.AKV {
		slotConfig.AKV[i] = hsmslot.AKVConfig{
			KeyName:          akvConfig.KeyName,
			KeyVersion:       akvConfig.KeyVersion,
			KeyPublicAddress: akvConfig.KeyPublicAddress,
		}
	}
	if slotConfigDB.LocalKeyVault != nil {
		slotConfig.LocalKeyVault = &hsmslot.LocalKeyVaultConfig{
			KeyStore: make(map[address.Address]string),
		}
		for k, v := range slotConfigDB.LocalKeyVault.KeyStore {
			addr, err := address.NewFromHexString(k)
			if err != nil {
				return nil, err
			}
			slotConfig.LocalKeyVault.KeyStore[addr] = v
		}
	}
	return slotConfig, nil
}

func mapToCreateDB(slot hsmslot.HSMSlot) (*hsmslotdb.HSMSlotCreateDB, error) {
	if len(slot.ID) == 0 {
		return nil, errors.Internal().WithMessage("'ID' cannot be empty")
	}
	if len(slot.InternalResourceID) == 0 {
		return nil, errors.Internal().WithMessage("'InternalResourceID' cannot be empty")
	}
	if len(slot.ApplicationID) == 0 {
		return nil, errors.Internal().WithMessage("'ApplicationID' cannot be empty")
	}
	if len(slot.HSMModuleID) == 0 {
		return nil, errors.Internal().WithMessage("'HSMModuleID' cannot be empty")
	}
	configSerialized, err := json.Marshal(mapToSlotConfigDB(slot.Config))
	if err != nil {
		return nil, err
	}
	return &hsmslotdb.HSMSlotCreateDB{
		HSMSlotDB: hsmslotdb.HSMSlotDB{
			StandardID:         slot.StandardID,
			InternalResourceID: slot.String(),
			ApplicationID:      slot.ApplicationID,
			HSMModuleID:        slot.HSMModuleID,
			Slot:               slot.Slot,
			Pin:                slot.Pin,
			Config:             string(configSerialized),
			CreationDate:       slot.CreationDate.ToInt64(),
			LastUpdate:         slot.LastUpdate.ToInt64(),
		},
	}, nil
}

func mapToUpdatePinDB(slot hsmslot.HSMSlot) (*hsmslotdb.HSMSlotUpdatePinDB, error) {
	if len(slot.ID) == 0 {
		return nil, errors.Internal().WithMessage("'ID' cannot be empty")
	}
	if len(slot.Pin) == 0 {
		return nil, errors.Internal().WithMessage("'Pin' cannot be empty")
	}
	return &hsmslotdb.HSMSlotUpdatePinDB{
		StandardID:      slot.StandardID,
		ResourceVersion: slot.ResourceVersion,
		Pin:             slot.Pin,
		LastUpdate:      slot.LastUpdate.ToInt64(),
	}, nil
}

func mapToUpdateConfigDB(slot hsmslot.HSMSlot) (*hsmslotdb.HSMSlotUpdateConfigDB, error) {
	if len(slot.ID) == 0 {
		return nil, errors.Internal().WithMessage("'ID' cannot be empty")
	}
	configSerialized, err := json.Marshal(mapToSlotConfigDB(slot.Config))
	if err != nil {
		return nil, err
	}
	return &hsmslotdb.HSMSlotUpdateConfigDB{
		StandardID:      slot.StandardID,
		ResourceVersion: slot.ResourceVersion,
		Config:          string(configSerialized),
		LastUpdate:      slot.LastUpdate.ToInt64(),
	}, nil
}

func mapFromDB(db hsmslotdb.HSMSlotDB) (*hsmslot.HSMSlot, error) {
	if len(db.InternalResourceID) == 0 {
		return nil, errors.Internal().WithMessage("'InternalResourceID' cannot be empty")
	}
	var configDB slotConfigDB
	err := json.Unmarshal([]byte(db.Config), &configDB)
	if err != nil {
		return nil, err
	}
	dbConfigData, err := mapFromSlotConfigDB(configDB)
	if err != nil {
		return nil, err
	}
	return &hsmslot.HSMSlot{
		StandardResourceMeta: entities.StandardResourceMeta{
			StandardResource: entities.StandardResource{
				StandardID: db.StandardID,
				Timestamps: entities.Timestamps{
					CreationDate: time.TimestampFromInt64(db.CreationDate),
					LastUpdate:   time.TimestampFromInt64(db.LastUpdate),
				},
			},
			ResourceVersion: db.ResourceVersion,
		},
		ApplicationID:      db.ApplicationID,
		HSMModuleID:        db.HSMModuleID,
		Slot:               db.Slot,
		Pin:                db.Pin,
		Config:             *dbConfigData,
		InternalResourceID: entities.InternalResourceID(db.InternalResourceID),
	}, nil
}

func mapSliceFromDB(dbSlice []hsmslotdb.HSMSlotDB) ([]hsmslot.HSMSlot, error) {
	userSlice := make([]hsmslot.HSMSlot, len(dbSlice))
	for index := range dbSlice {
		item, err := mapFromDB(dbSlice[index])
		if err != nil {
			return nil, err
		}
		userSlice[index] = *item
	}
	return userSlice, nil
}

func mapPersistenceErrorToSignerError(err error) error {
	if persistence.IsAlreadyExists(err) {
		return errors.AlreadyExistsFromErr(err)
	}
	if persistence.IsNotFound(err) {
		return errors.NotFoundFromErr(err)
	}
	if persistence.IsEntryNotAdded(err) {
		return errors.InternalFromErr(err)
	}
	return errors.InternalFromErr(err)
}
