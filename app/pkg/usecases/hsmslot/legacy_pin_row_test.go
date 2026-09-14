package hsmslot_test

import (
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/application"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmslot"
	"github.com/lfdt-smoot/signare/app/test/dbtesthelper"
	"github.com/lfdt-smoot/signare/app/test/signaturemanagertesthelper"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestLegacyPinRowKeepsWorking covers the one thing that lets an existing deployment upgrade the binary
// before moving its secrets: a row written before pin_source existed still opens its slot.
//
// The row has to be written with raw SQL, because creation no longer persists a pin, and the assertions
// have to tell the three read statements apart. Dropping pin from getByApplication, or removing its
// COALESCE, leaves the rest of the suite green and breaks every pre-upgrade slot. The statement uses
// '?' placeholders because the suite runs on SQLite.
func TestLegacyPinRowKeepsWorking(t *testing.T) {
	applicationID := uuid.NewString()
	createApplicationOutput, err := app.ApplicationUseCase.CreateApplication(ctx, application.CreateApplicationInput{
		ID:      &applicationID,
		ChainID: *chainID,
	})
	require.NoError(t, err)

	addedModule := createOrGetModule(t, "7e61fd30-299a-4282-9cf7-4582505ecbc5")
	createdSlot := createOrGetSlot(t, createApplicationOutput.ID, slotIDOne, addedModule.ID)

	byApplication := hsmslot.GetHSMSlotByApplicationInput{
		ApplicationID: entities.StandardID{ID: createApplicationOutput.ID},
	}
	byID := hsmslot.GetHSMSlotInput{StandardID: createdSlot.StandardID}

	// Rewrite the row into its pre-upgrade shape: a cleartext pin and no source.
	_, err = dbtesthelper.Connection().GetDB().Exec(
		"UPDATE cfg_hardware_security_module_slot SET pin = ?, pin_source = '' WHERE id = ?",
		signaturemanagertesthelper.SlotPin, createdSlot.ID,
	)
	require.NoError(t, err)

	t.Run("the slot-open read still loads the stored pin", func(t *testing.T) {
		out, getErr := app.HSMSlotUseCase.GetHSMSlotByApplication(ctx, byApplication)
		require.NoError(t, getErr)
		require.Equal(t, signaturemanagertesthelper.SlotPin, out.Pin, "a legacy row must still yield its PIN to the signing path")
		require.Empty(t, out.PinSource)
	})

	t.Run("the admin reads do not load it", func(t *testing.T) {
		single, getErr := app.HSMSlotUseCase.GetHSMSlot(ctx, byID)
		require.NoError(t, getErr)
		require.Empty(t, single.Pin, "getById must not select the pin column")

		listed, listErr := app.HSMSlotUseCase.ListHSMSlotsByApplication(ctx, hsmslot.ListHSMSlotsByApplicationInput{
			ApplicationID: entities.StandardID{ID: createApplicationOutput.ID},
		})
		require.NoError(t, listErr)
		require.NotEmpty(t, listed.Items)
		for _, item := range listed.Items {
			require.Empty(t, item.Pin, "list must not select the pin column")
		}
	})

	// The end the whole fallback exists for: the slot still opens against the token.
	t.Run("the slot still opens against the HSM", func(t *testing.T) {
		out, getErr := app.HSMSlotUseCase.GetHSMSlotByApplication(ctx, byApplication)
		require.NoError(t, getErr)

		connectionData := hsmconnector.SlotConnectionData{
			Slot:       out.Slot,
			LegacyPin:  out.Pin,
			ModuleKind: hsmconnector.SoftHSMModuleKind,
		}
		generated, generateErr := app.HSMConnector.GenerateAddress(ctx, hsmconnector.GenerateAddressInput{
			SlotConnectionData: connectionData,
		})
		require.NoError(t, generateErr, "a legacy row must still be able to log in to the token")
		require.NotNil(t, generated)

		_, removeErr := app.HSMConnector.RemoveAddress(ctx, hsmconnector.RemoveAddressInput{
			SlotConnectionData: connectionData,
			Address:            generated.Address,
		})
		require.NoError(t, removeErr)
	})

	// Moving to a source clears the old value, so the row stops serving it.
	t.Run("naming a source clears the stored pin", func(t *testing.T) {
		current, getErr := app.HSMSlotUseCase.GetHSMSlot(ctx, byID)
		require.NoError(t, getErr)

		edited, editErr := app.HSMSlotUseCase.EditPinSource(ctx, hsmslot.EditPinSourceInput{
			StandardID:      current.StandardID,
			ResourceVersion: current.ResourceVersion,
			PinSource:       slotPinSource,
			HSMModuleID:     current.HSMModuleID,
		})
		require.NoError(t, editErr)
		require.Equal(t, slotPinSource, edited.PinSource)

		reread, rereadErr := app.HSMSlotUseCase.GetHSMSlotByApplication(ctx, byApplication)
		require.NoError(t, rereadErr)
		require.Empty(t, reread.Pin, "the legacy value must not survive the move to a source")
		require.Equal(t, slotPinSource, reread.PinSource)
	})
}
