package hsmslot_test

import (
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/application"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmslot"
	"github.com/lfdt-smoot/signare/app/test/dbtesthelper"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestSlotWithNoPinSourceFailsClearly covers the state a deployment is left in if it drops the pin
// column while a slot still depended on it: a stored row naming no source.
//
// The row has to be written with raw SQL because that shape is unreachable through the API, which is
// the point. Creation requires a source for a PKCS#11 module, EditPinSourceInput.PinSource is
// valid:"required", and ValidatePinSource rejects the empty string. Only a row predating the pin-source
// migration can look like this, so nothing else in the suite can produce one.
func TestSlotWithNoPinSourceFailsClearly(t *testing.T) {
	applicationID := uuid.NewString()
	createApplicationOutput, err := app.ApplicationUseCase.CreateApplication(ctx, application.CreateApplicationInput{
		ID:      &applicationID,
		ChainID: *chainID,
	})
	require.NoError(t, err)

	addedModule := createOrGetModule(t, "7e61fd30-299a-4282-9cf7-4582505ecbc5")
	createdSlot := createOrGetSlot(t, createApplicationOutput.ID, slotIDOne, addedModule.ID)

	_, err = dbtesthelper.Connection().GetDB().Exec(
		"UPDATE cfg_hardware_security_module_slot SET pin_source = '' WHERE id = ?",
		createdSlot.ID,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, cleanupErr := dbtesthelper.Connection().GetDB().Exec(
			"UPDATE cfg_hardware_security_module_slot SET pin_source = ? WHERE id = ?",
			slotPinSource, createdSlot.ID,
		)
		require.NoError(t, cleanupErr)
	})

	t.Run("the slot still reads back, with no source", func(t *testing.T) {
		out, getErr := app.HSMSlotUseCase.GetHSMSlotByApplication(ctx, hsmslot.GetHSMSlotByApplicationInput{
			ApplicationID: entities.StandardID{ID: createApplicationOutput.ID},
		})
		require.NoError(t, getErr, "the row is readable, it just cannot open its token")
		require.Empty(t, out.PinSource)
	})

	// The operator-facing half: the failure has to name the cause, because the slot exists, the HSM is
	// reachable and nothing in the admin API shows the slot as broken.
	t.Run("verifying it reports the missing source rather than an HSM failure", func(t *testing.T) {
		out, verifyErr := app.HSMSlotUseCase.VerifyPinSource(ctx, hsmslot.VerifyPinSourceInput{
			StandardID:  createdSlot.StandardID,
			HSMModuleID: createdSlot.HSMModuleID,
		})
		require.Error(t, verifyErr)
		require.True(t, errors.IsPreconditionFailed(verifyErr))
		require.Contains(t, verifyErr.Error(), "no 'pinSource' to verify")
		require.Nil(t, out)
	})

	t.Run("naming a source recovers the slot", func(t *testing.T) {
		current, getErr := app.HSMSlotUseCase.GetHSMSlot(ctx, hsmslot.GetHSMSlotInput{StandardID: createdSlot.StandardID})
		require.NoError(t, getErr)

		edited, editErr := app.HSMSlotUseCase.EditPinSource(ctx, hsmslot.EditPinSourceInput{
			StandardID:      current.StandardID,
			ResourceVersion: current.ResourceVersion,
			PinSource:       slotPinSource,
			HSMModuleID:     current.HSMModuleID,
		})
		require.NoError(t, editErr, "setting a source is the documented recovery")
		require.Equal(t, slotPinSource, edited.PinSource)

		verified, verifyErr := app.HSMSlotUseCase.VerifyPinSource(ctx, hsmslot.VerifyPinSourceInput{
			StandardID:  createdSlot.StandardID,
			HSMModuleID: createdSlot.HSMModuleID,
		})
		require.NoError(t, verifyErr)
		require.Equal(t, slotPinSource, verified.PinSource)
	})
}
