package hsmslot_test

import (
	"context"
	"os"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/adapters/storage/postgres/hsmslotdbout"
	"github.com/lfdt-smoot/signare/app/pkg/commons/time"
	"github.com/lfdt-smoot/signare/app/pkg/commons/validators"
	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/graph"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/application"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmmodule"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmslot"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/referentialintegrity"
	"github.com/lfdt-smoot/signare/app/test/dbtesthelper"
	"github.com/lfdt-smoot/signare/app/test/signaturemanagertesthelper"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

var (
	app       graph.GraphShared
	slotIDOne string
	slotIDTwo string

	chainID        = entities.NewInt256FromInt(5050)
	slotPinSource  = signaturemanagertesthelper.SlotPinSource
	wrongPinSource = signaturemanagertesthelper.WrongSlotPinSource
)

var (
	ctx                 = context.Background()
	resourceDescription = "resource description"

	moduleWithoutID = hsmmodule.HSMModule{
		StandardResourceMeta: entities.StandardResourceMeta{
			StandardResource: entities.StandardResource{
				StandardID: entities.StandardID{
					ID: "",
				},
				Timestamps: entities.Timestamps{
					CreationDate: time.Now(),
					LastUpdate:   time.Now(),
				},
			},
			ResourceVersion: uuid.NewString(),
		},
		Description: &resourceDescription,
		Configuration: hsmmodule.HSMModuleConfiguration{
			SoftHSMConfiguration: &hsmmodule.SoftHSMConfiguration{},
		},
		Kind: hsmmodule.SoftHSMModuleKind,
	}
)

func TestMain(m *testing.M) {
	slotOne, slotTwo, err := signaturemanagertesthelper.InitializeSoftHSMSlot()
	if err != nil {
		panic(err)
	}
	slotIDOne = *slotOne
	slotIDTwo = *slotTwo

	a, err := dbtesthelper.InitializeApp()
	if err != nil {
		panic(err)
	}
	app = *a

	validators.SetValidators()
	os.Exit(m.Run())
}

func TestProvideDefaultUseCase(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		userUseCase, err := hsmslot.ProvideDefaultUseCase(hsmslot.DefaultUseCaseOptions{
			HSMSlotStorage:              &hsmslotdbout.Repository{},
			ApplicationUseCase:          &application.DefaultUseCase{},
			HSMModuleUseCase:            &hsmmodule.DefaultUseCase{},
			HSMConnector:                &hsmconnector.DefaultUseCase{},
			ReferentialIntegrityUseCase: &referentialintegrity.DefaultUseCase{},
		})
		require.NoError(t, err)
		require.NotNil(t, userUseCase)
	})

	t.Run("nil slot storage", func(t *testing.T) {
		userUseCase, err := hsmslot.ProvideDefaultUseCase(hsmslot.DefaultUseCaseOptions{
			HSMSlotStorage:              nil,
			ApplicationUseCase:          &application.DefaultUseCase{},
			HSMModuleUseCase:            &hsmmodule.DefaultUseCase{},
			HSMConnector:                &hsmconnector.DefaultUseCase{},
			ReferentialIntegrityUseCase: &referentialintegrity.DefaultUseCase{},
		})
		require.Error(t, err)
		require.Nil(t, userUseCase)
	})

	t.Run("nil application use case", func(t *testing.T) {
		userUseCase, err := hsmslot.ProvideDefaultUseCase(hsmslot.DefaultUseCaseOptions{
			HSMSlotStorage:              &hsmslotdbout.Repository{},
			ApplicationUseCase:          nil,
			HSMModuleUseCase:            &hsmmodule.DefaultUseCase{},
			HSMConnector:                &hsmconnector.DefaultUseCase{},
			ReferentialIntegrityUseCase: &referentialintegrity.DefaultUseCase{},
		})
		require.Error(t, err)
		require.Nil(t, userUseCase)
	})

	t.Run("nil hsm module use case", func(t *testing.T) {
		userUseCase, err := hsmslot.ProvideDefaultUseCase(hsmslot.DefaultUseCaseOptions{
			HSMSlotStorage:              &hsmslotdbout.Repository{},
			ApplicationUseCase:          &application.DefaultUseCase{},
			HSMModuleUseCase:            nil,
			HSMConnector:                &hsmconnector.DefaultUseCase{},
			ReferentialIntegrityUseCase: &referentialintegrity.DefaultUseCase{},
		})
		require.Error(t, err)
		require.Nil(t, userUseCase)
	})

	t.Run("nil hsm connector use case", func(t *testing.T) {
		userUseCase, err := hsmslot.ProvideDefaultUseCase(hsmslot.DefaultUseCaseOptions{
			HSMSlotStorage:              &hsmslotdbout.Repository{},
			ApplicationUseCase:          &application.DefaultUseCase{},
			HSMModuleUseCase:            &hsmmodule.DefaultUseCase{},
			HSMConnector:                nil,
			ReferentialIntegrityUseCase: &referentialintegrity.DefaultUseCase{},
		})
		require.Error(t, err)
		require.Nil(t, userUseCase)
	})

	t.Run("nil referential integrity use case", func(t *testing.T) {
		userUseCase, err := hsmslot.ProvideDefaultUseCase(hsmslot.DefaultUseCaseOptions{
			HSMSlotStorage:              &hsmslotdbout.Repository{},
			ApplicationUseCase:          &application.DefaultUseCase{},
			HSMModuleUseCase:            &hsmmodule.DefaultUseCase{},
			HSMConnector:                &hsmconnector.DefaultUseCase{},
			ReferentialIntegrityUseCase: nil,
		})
		require.Error(t, err)
		require.Nil(t, userUseCase)
	})
}

func TestDefaultUseCase_CreateHSMSlot(t *testing.T) {
	// Create Module
	addedModule := createOrGetModule(t, "7e61fd30-299a-4282-9cf7-4582505ecbc5")

	applicationID := uuid.NewString()
	createApplicationInput := application.CreateApplicationInput{
		ID:      &applicationID,
		ChainID: *chainID,
	}
	createApplicationOutput, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, createApplicationInput)
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createApplicationOutput)

	t.Run("failure: invalid input arguments", func(t *testing.T) {
		input := hsmslot.CreateHSMSlotInput{
			ApplicationID: "",
			HSMModuleID:   addedModule.ID,
			Slot:          "my-slot-id",
			PinSource:     slotPinSource,
		}
		output, err := app.HSMSlotUseCase.CreateHSMSlot(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)

		input = hsmslot.CreateHSMSlotInput{
			ApplicationID: createApplicationOutput.ID,
			HSMModuleID:   "",
			Slot:          "my-slot-id",
			PinSource:     slotPinSource,
		}
		output, err = app.HSMSlotUseCase.CreateHSMSlot(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("failure: slot already exists", func(t *testing.T) {
		input := hsmslot.CreateHSMSlotInput{
			ApplicationID: createApplicationOutput.ID,
			HSMModuleID:   addedModule.ID,
			Slot:          slotIDOne,
			PinSource:     slotPinSource,
		}
		_, err := app.HSMSlotUseCase.CreateHSMSlot(ctx, input)
		require.NoError(t, err)

		// Duplicated Slot
		output, err := app.HSMSlotUseCase.CreateHSMSlot(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsAlreadyExists(err))
		require.Nil(t, output)
	})

	t.Run("success", func(t *testing.T) {
		// Create Slot
		createdSlot := createOrGetSlot(t, createApplicationOutput.ID, slotIDOne, addedModule.ID)

		require.NotEmpty(t, createdSlot.InternalResourceID)
		require.Equal(t, applicationID, createdSlot.ApplicationID)
		require.Equal(t, addedModule.ID, createdSlot.HSMModuleID)
		require.Equal(t, slotIDOne, createdSlot.Slot)
		require.Equal(t, slotPinSource, createdSlot.PinSource)
		require.Empty(t, createdSlot.Pin, "creation must not persist a PIN value")
	})
}

func TestDefaultUseCase_GetHSMSlot(t *testing.T) {
	applicationID := uuid.NewString()
	createApplicationInput := application.CreateApplicationInput{
		ID:      &applicationID,
		ChainID: *chainID,
	}
	createApplicationOutput, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, createApplicationInput)
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createApplicationOutput)

	t.Run("failure: invalid input arguments", func(t *testing.T) {
		input := hsmslot.GetHSMSlotInput{
			StandardID: entities.StandardID{
				ID: "",
			},
		}
		output, err := app.HSMSlotUseCase.GetHSMSlot(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("failure: slot not found", func(t *testing.T) {
		input := hsmslot.GetHSMSlotInput{
			StandardID: entities.StandardID{
				ID: "123",
			},
		}
		output, err := app.HSMSlotUseCase.GetHSMSlot(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Nil(t, output)
	})

	t.Run("success", func(t *testing.T) {
		// Create Module
		addedModule := createOrGetModule(t, "7e61fd30-299a-4282-9cf7-4582505ecbc5")

		// Create Slot
		createdSlot := createOrGetSlot(t, createApplicationOutput.ID, slotIDOne, addedModule.ID)

		// Get Slot
		expectedSlotID := createdSlot.ID
		getSlotInput := hsmslot.GetHSMSlotInput{
			StandardID: entities.StandardID{ID: createdSlot.ID},
		}
		output, err := app.HSMSlotUseCase.GetHSMSlot(ctx, getSlotInput)
		require.NoError(t, err)
		require.NotNil(t, output)
		require.Equal(t, expectedSlotID, output.ID)
		require.Equal(t, createApplicationOutput.ID, output.ApplicationID)
		require.Equal(t, addedModule.ID, output.HSMModuleID)
		require.Equal(t, slotIDOne, output.Slot)
		require.Equal(t, slotPinSource, output.PinSource)
		require.NotEmpty(t, output.InternalResourceID)
	})
}

func TestDefaultUseCase_GetHSMSlotByApplication(t *testing.T) {
	applicationID := uuid.NewString()
	createApplicationInput := application.CreateApplicationInput{
		ID:      &applicationID,
		ChainID: *chainID,
	}
	createApplicationOutput, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, createApplicationInput)
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createApplicationOutput)

	t.Run("failure: invalid input arguments", func(t *testing.T) {
		input := hsmslot.GetHSMSlotByApplicationInput{
			ApplicationID: entities.StandardID{
				ID: "",
			},
		}
		output, err := app.HSMSlotUseCase.GetHSMSlotByApplication(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("failure: slot not found", func(t *testing.T) {
		input := hsmslot.GetHSMSlotByApplicationInput{
			ApplicationID: entities.StandardID{
				ID: "123",
			},
		}
		output, err := app.HSMSlotUseCase.GetHSMSlotByApplication(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Nil(t, output)
	})

	t.Run("success", func(t *testing.T) {
		// Create Module
		addedModule := createOrGetModule(t, "7e61fd30-299a-4282-9cf7-4582505ecbc5")

		// Create Slot
		createdSlot := createOrGetSlot(t, createApplicationOutput.ID, slotIDOne, addedModule.ID)

		// Get Slot
		expectedSlotID := createdSlot.ID
		getSlotInput := hsmslot.GetHSMSlotByApplicationInput{
			ApplicationID: entities.StandardID{
				ID: createdSlot.ApplicationID,
			},
		}
		output, err := app.HSMSlotUseCase.GetHSMSlotByApplication(ctx, getSlotInput)
		require.NoError(t, err)
		require.NotNil(t, output)
		require.Equal(t, expectedSlotID, output.ID)
		require.Equal(t, createApplicationOutput.ID, output.ApplicationID)
		require.Equal(t, addedModule.ID, output.HSMModuleID)
		require.Equal(t, slotIDOne, output.Slot)
		require.Equal(t, slotPinSource, output.PinSource)
		require.NotEmpty(t, output.InternalResourceID)
	})
}

func TestDefaultUseCase_EditPinSource(t *testing.T) {
	applicationID := uuid.NewString()
	createApplicationInput := application.CreateApplicationInput{
		ID:      &applicationID,
		ChainID: *chainID,
	}
	createApplicationOutput, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, createApplicationInput)
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createApplicationOutput)

	t.Run("failure: invalid input arguments", func(t *testing.T) {
		input := hsmslot.EditPinSourceInput{
			StandardID: entities.StandardID{
				ID: "",
			},
			ResourceVersion: "my-resource-version",
			PinSource:       slotPinSource,
			HSMModuleID:     "hsm-module",
		}
		output, err := app.HSMSlotUseCase.EditPinSource(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)

		input = hsmslot.EditPinSourceInput{
			StandardID: entities.StandardID{
				ID: "my-id",
			},
			ResourceVersion: "",
			PinSource:       slotPinSource,
			HSMModuleID:     "hsm-module",
		}
		output, err = app.HSMSlotUseCase.EditPinSource(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)

		input = hsmslot.EditPinSourceInput{
			StandardID: entities.StandardID{
				ID: "my-id",
			},
			ResourceVersion: "my-resource-version",
			PinSource:       "",
			HSMModuleID:     "hsm-module",
		}
		output, err = app.HSMSlotUseCase.EditPinSource(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	// A source is a name resolved under a configured directory, so anything that could address a file
	// outside it has to be refused before it is stored.
	t.Run("failure: pin source is not a single name", func(t *testing.T) {
		addedModule := createOrGetModule(t, "7e61fd30-299a-4282-9cf7-4582505ecbc5")
		createdSlot := createOrGetSlot(t, createApplicationOutput.ID, slotIDOne, addedModule.ID)

		for _, source := range []string{
			"../escape",
			"sub/dir",
			`sub\dir`,
			"..",
			"..data",
			".",
			"/etc/passwd",
			"has space",
			"semi;colon",
		} {
			input := hsmslot.EditPinSourceInput{
				StandardID:      createdSlot.StandardID,
				HSMModuleID:     createdSlot.HSMModuleID,
				ResourceVersion: createdSlot.ResourceVersion,
				PinSource:       source,
			}
			output, err := app.HSMSlotUseCase.EditPinSource(ctx, input)
			require.Error(t, err, "pin source %q must be rejected", source)
			require.True(t, errors.IsInvalidArgument(err), "pin source %q must be rejected as invalid argument", source)
			require.Nil(t, output)
		}
	})

	t.Run("failure: slot not found", func(t *testing.T) {
		input := hsmslot.EditPinSourceInput{
			StandardID: entities.StandardID{
				ID: "my-id",
			},
			ResourceVersion: "my-resource-version",
			PinSource:       slotPinSource,
			HSMModuleID:     "hsm-module",
		}
		output, err := app.HSMSlotUseCase.EditPinSource(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Nil(t, output)
	})

	t.Run("failure: invalid resource version", func(t *testing.T) {
		addedModule := createOrGetModule(t, "7e61fd30-299a-4282-9cf7-4582505ecbc5")
		createdSlot := createOrGetSlot(t, createApplicationOutput.ID, slotIDOne, addedModule.ID)

		input := hsmslot.EditPinSourceInput{
			StandardID:      createdSlot.StandardID,
			ResourceVersion: "invalid-resource-version",
			PinSource:       slotPinSource,
			HSMModuleID:     createdSlot.HSMModuleID,
		}
		editedSlot, err := app.HSMSlotUseCase.EditPinSource(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Nil(t, editedSlot)
	})

	t.Run("failure: pin source names a secret the HSM refuses", func(t *testing.T) {
		addedModule := createOrGetModule(t, "7e61fd30-299a-4282-9cf7-4582505ecbc5")
		createdSlot := createOrGetSlot(t, createApplicationOutput.ID, slotIDOne, addedModule.ID)

		input := hsmslot.EditPinSourceInput{
			StandardID:      createdSlot.StandardID,
			HSMModuleID:     createdSlot.HSMModuleID,
			ResourceVersion: createdSlot.ResourceVersion,
			PinSource:       wrongPinSource,
		}
		editedSlot, err := app.HSMSlotUseCase.EditPinSource(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsPreconditionFailed(err))
		require.Nil(t, editedSlot)

		// The wrong value must not have been stored: the slot still resolves through its old source.
		stored, getErr := app.HSMSlotUseCase.GetHSMSlot(ctx, hsmslot.GetHSMSlotInput{StandardID: createdSlot.StandardID})
		require.NoError(t, getErr)
		require.Equal(t, slotPinSource, stored.PinSource)

		// Clear the breaker the refused login just opened, so later subtests are not short-circuited.
		_, verifyErr := app.HSMSlotUseCase.VerifyPinSource(ctx, hsmslot.VerifyPinSourceInput{
			StandardID:  createdSlot.StandardID,
			HSMModuleID: createdSlot.HSMModuleID,
		})
		require.NoError(t, verifyErr)
	})

	t.Run("failure: unreadable pin source", func(t *testing.T) {
		addedModule := createOrGetModule(t, "7e61fd30-299a-4282-9cf7-4582505ecbc5")
		createdSlot := createOrGetSlot(t, createApplicationOutput.ID, slotIDOne, addedModule.ID)

		input := hsmslot.EditPinSourceInput{
			StandardID:      createdSlot.StandardID,
			HSMModuleID:     createdSlot.HSMModuleID,
			ResourceVersion: createdSlot.ResourceVersion,
			PinSource:       "no-such-source",
		}
		editedSlot, err := app.HSMSlotUseCase.EditPinSource(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsPreconditionFailed(err))
		require.Nil(t, editedSlot)
	})

	t.Run("failure: slot does not exist in HSM module", func(t *testing.T) {
		addedModule := createOrGetModule(t, "7e61fd30-299a-4282-9cf7-4582505ecbc5")
		createdSlot := createOrGetSlot(t, createApplicationOutput.ID, slotIDOne, addedModule.ID)

		input := hsmslot.EditPinSourceInput{
			StandardID:      createdSlot.StandardID,
			HSMModuleID:     "other-hsm-module",
			ResourceVersion: createdSlot.ResourceVersion,
			PinSource:       slotPinSource,
		}
		editedSlot, err := app.HSMSlotUseCase.EditPinSource(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Nil(t, editedSlot)
	})

	t.Run("success", func(t *testing.T) {
		addedModule := createOrGetModule(t, "7e61fd30-299a-4282-9cf7-4582505ecbc5")
		createdSlot := createOrGetSlot(t, createApplicationOutput.ID, slotIDOne, addedModule.ID)

		input := hsmslot.EditPinSourceInput{
			StandardID:      createdSlot.StandardID,
			HSMModuleID:     createdSlot.HSMModuleID,
			ResourceVersion: createdSlot.ResourceVersion,
			PinSource:       slotPinSource,
		}
		editedSlot, err := app.HSMSlotUseCase.EditPinSource(ctx, input)
		require.NoError(t, err)
		require.NotNil(t, editedSlot)
		require.Equal(t, createdSlot.ID, editedSlot.ID)
		require.Equal(t, createdSlot.ApplicationID, editedSlot.ApplicationID)
		require.Equal(t, createdSlot.CreationDate, editedSlot.CreationDate)
		require.NotEqual(t, createdSlot.LastUpdate, editedSlot.LastUpdate)
		require.Equal(t, createdSlot.HSMModuleID, editedSlot.HSMModuleID)
		require.NotEqual(t, createdSlot.ResourceVersion, editedSlot.ResourceVersion)
		require.Equal(t, slotPinSource, editedSlot.PinSource)
		require.Empty(t, editedSlot.Pin, "naming a source must clear any stored PIN")
	})
}

func TestDefaultUseCase_VerifyPinSource(t *testing.T) {
	applicationID := uuid.NewString()
	createApplicationInput := application.CreateApplicationInput{
		ID:      &applicationID,
		ChainID: *chainID,
	}
	createApplicationOutput, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, createApplicationInput)
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createApplicationOutput)

	t.Run("failure: invalid input arguments", func(t *testing.T) {
		output, err := app.HSMSlotUseCase.VerifyPinSource(ctx, hsmslot.VerifyPinSourceInput{
			StandardID:  entities.StandardID{ID: "my-id"},
			HSMModuleID: "",
		})
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("failure: slot not found", func(t *testing.T) {
		output, err := app.HSMSlotUseCase.VerifyPinSource(ctx, hsmslot.VerifyPinSourceInput{
			StandardID:  entities.StandardID{ID: "my-id"},
			HSMModuleID: "hsm-module",
		})
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Nil(t, output)
	})

	t.Run("success", func(t *testing.T) {
		addedModule := createOrGetModule(t, "7e61fd30-299a-4282-9cf7-4582505ecbc5")
		createdSlot := createOrGetSlot(t, createApplicationOutput.ID, slotIDOne, addedModule.ID)

		output, err := app.HSMSlotUseCase.VerifyPinSource(ctx, hsmslot.VerifyPinSourceInput{
			StandardID:  createdSlot.StandardID,
			HSMModuleID: createdSlot.HSMModuleID,
		})
		require.NoError(t, err)
		require.NotNil(t, output)
		require.Equal(t, createdSlot.ID, output.ID)
		require.Equal(t, slotPinSource, output.PinSource)
		// Verification must not mutate the resource.
		require.Equal(t, createdSlot.ResourceVersion, output.ResourceVersion)
	})
}

func TestDefaultUseCase_DeleteHSMSlot(t *testing.T) {
	applicationID := uuid.NewString()
	createApplicationInput := application.CreateApplicationInput{
		ID:      &applicationID,
		ChainID: *chainID,
	}
	createApplicationOutput, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, createApplicationInput)
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createApplicationOutput)

	t.Run("failure: invalid input arguments", func(t *testing.T) {
		input := hsmslot.DeleteHSMSlotInput{
			StandardID: entities.StandardID{
				ID: "",
			},
		}
		output, err := app.HSMSlotUseCase.DeleteHSMSlot(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("failure: slot not found", func(t *testing.T) {
		input := hsmslot.DeleteHSMSlotInput{
			StandardID: entities.StandardID{
				ID: uuid.NewString(),
			},
		}
		output, err := app.HSMSlotUseCase.DeleteHSMSlot(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Nil(t, output)
	})

	t.Run("success", func(t *testing.T) {
		// Create module
		addedModule := createOrGetModule(t, "7e61fd30-299a-4282-9cf7-4582505ecbc5")

		// Create Slot
		createdSlot := createOrGetSlot(t, createApplicationOutput.ID, slotIDOne, addedModule.ID)

		// Delete Slot
		input := hsmslot.DeleteHSMSlotInput{
			StandardID: entities.StandardID{
				ID: createdSlot.ID,
			},
		}
		deletedSlot, err := app.HSMSlotUseCase.DeleteHSMSlot(ctx, input)
		require.NoError(t, err)
		require.NotNil(t, deletedSlot)
		require.Equal(t, createdSlot.ID, deletedSlot.ID)
	})
}

func TestDefaultUseCase_ListHSMSlotsByApplication(t *testing.T) {
	// Create Application 1
	applicationOneID := uuid.NewString()
	createApplicationInput := application.CreateApplicationInput{
		ID:      &applicationOneID,
		ChainID: *chainID,
	}
	createApplicationOneOutput, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, createApplicationInput)
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createApplicationOneOutput)

	// Create Application 2
	applicationTwoID := uuid.NewString()
	createApplicationInput = application.CreateApplicationInput{
		ID:      &applicationTwoID,
		ChainID: *chainID,
	}
	createApplicationTwoOutput, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, createApplicationInput)
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createApplicationTwoOutput)

	// Create Module
	moduleID := uuid.NewString()
	hsmModule := createOrGetModule(t, moduleID)

	// Create Slot for Application 1
	hsmSlotOne := createOrGetSlot(t, createApplicationOneOutput.ID, slotIDOne, hsmModule.ID)

	// Create Slot for Application 2
	createOrGetSlot(t, createApplicationTwoOutput.ID, slotIDTwo, hsmModule.ID)

	t.Run("failure: invalid argument", func(t *testing.T) {
		input := hsmslot.ListHSMSlotsByApplicationInput{
			ApplicationID: entities.StandardID{
				ID: "",
			},
		}
		output, err := app.HSMSlotUseCase.ListHSMSlotsByApplication(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("success: list all slots without limit", func(t *testing.T) {
		input := hsmslot.ListHSMSlotsByApplicationInput{
			ApplicationID: createApplicationOneOutput.StandardID,
		}
		output, err := app.HSMSlotUseCase.ListHSMSlotsByApplication(ctx, input)
		require.NoError(t, err)
		require.Len(t, output.Items, 1)
		require.Equal(t, *hsmSlotOne, output.Items[0])
	})
}

func TestDefaultUseCase_ListHSMSlotsByHSMModule(t *testing.T) {
	// Create Application 1
	applicationOneID := uuid.NewString()
	createApplicationInput := application.CreateApplicationInput{
		ID:      &applicationOneID,
		ChainID: *chainID,
	}
	createApplicationOneOutput, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, createApplicationInput)
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createApplicationOneOutput)

	// Create Application 2
	applicationTwoID := uuid.NewString()
	createApplicationInput = application.CreateApplicationInput{
		ID:      &applicationTwoID,
		ChainID: *chainID,
	}
	createApplicationTwoOutput, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, createApplicationInput)
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createApplicationTwoOutput)

	// Create Module
	moduleID := uuid.NewString()
	hsmModule := createOrGetModule(t, moduleID)

	// Create Slot for Application 1
	hsmSlotOne := createOrGetSlot(t, createApplicationOneOutput.ID, slotIDOne, hsmModule.ID)

	// Create Slot for Application 2
	hsmSlotTwo := createOrGetSlot(t, createApplicationTwoOutput.ID, slotIDTwo, hsmModule.ID)

	t.Run("failure: invalid argument", func(t *testing.T) {
		input := hsmslot.ListHSMSlotsByHSMModuleInput{
			HSMModuleID: entities.StandardID{
				ID: "",
			},
		}
		output, err := app.HSMSlotUseCase.ListHSMSlotsByHSMModule(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("success: list ASC all slots without limit", func(t *testing.T) {
		input := hsmslot.ListHSMSlotsByHSMModuleInput{
			HSMModuleID: entities.StandardID{
				ID: moduleID,
			},
			OrderDirection: "asc",
		}
		expectedSlots := 2
		output, err := app.HSMSlotUseCase.ListHSMSlotsByHSMModule(ctx, input)
		require.NoError(t, err)
		require.Len(t, output.Items, expectedSlots)
		require.Equal(t, *hsmSlotOne, output.Items[0])
		require.Equal(t, *hsmSlotTwo, output.Items[1])
	})

	t.Run("success: list DESC all slots without limit", func(t *testing.T) {
		input := hsmslot.ListHSMSlotsByHSMModuleInput{
			HSMModuleID: entities.StandardID{
				ID: moduleID,
			},
			OrderDirection: "desc",
		}
		expectedSlots := 2
		output, err := app.HSMSlotUseCase.ListHSMSlotsByHSMModule(ctx, input)
		require.NoError(t, err)
		require.Len(t, output.Items, expectedSlots)
		require.Equal(t, *hsmSlotOne, output.Items[1])
		require.Equal(t, *hsmSlotTwo, output.Items[0])
	})

	t.Run("success: list ASC all slots with limit", func(t *testing.T) {
		limit := 1
		input := hsmslot.ListHSMSlotsByHSMModuleInput{
			HSMModuleID: entities.StandardID{
				ID: moduleID,
			},
			PageLimit:      limit,
			OrderDirection: "asc",
		}
		output, err := app.HSMSlotUseCase.ListHSMSlotsByHSMModule(ctx, input)
		require.NoError(t, err)
		require.Len(t, output.Items, limit)
		require.Equal(t, *hsmSlotOne, output.Items[0])
	})
}

func createOrGetModule(t *testing.T, moduleID string) *hsmmodule.HSMModule {
	t.Helper()
	createHSMModuleInput := hsmmodule.CreateHSMModuleInput{
		ID:            &moduleID,
		Description:   moduleWithoutID.Description,
		Configuration: moduleWithoutID.Configuration,
		ModuleKind:    moduleWithoutID.Kind,
	}
	addedModule, err := app.HSMModuleUseCase.CreateHSMModule(ctx, createHSMModuleInput)
	if err != nil {
		require.True(t, errors.IsAlreadyExists(err))
		getHSMModuleInput := hsmmodule.GetHSMModuleInput{
			StandardID: entities.StandardID{
				ID: moduleID,
			},
		}
		module, errGet := app.HSMModuleUseCase.GetHSMModule(ctx, getHSMModuleInput)
		require.NoError(t, errGet)
		require.NotNil(t, module)
		return &module.HSMModule
	}
	require.NotNil(t, addedModule)
	return &addedModule.HSMModule
}

func createOrGetSlot(t *testing.T, applicationID, slotID, hsmID string) *hsmslot.HSMSlot {
	t.Helper()
	createSlotInput := hsmslot.CreateHSMSlotInput{
		ApplicationID: applicationID,
		HSMModuleID:   hsmID,
		Slot:          slotID,
		PinSource:     slotPinSource,
	}

	createdSlot, err := app.HSMSlotUseCase.CreateHSMSlot(ctx, createSlotInput)
	if err != nil {
		require.True(t, errors.IsAlreadyExists(err))

		// Search for existing slot as it may be assigned to another application and the ID is unknown
		listInput := hsmslot.ListHSMSlotsByHSMModuleInput{
			HSMModuleID: entities.StandardID{
				ID: hsmID,
			},
		}
		slotList, listErr := app.HSMSlotUseCase.ListHSMSlotsByHSMModule(ctx, listInput)
		require.NoError(t, listErr)
		existingSlotID := ""
		slotFound := false
		for _, slot := range slotList.Items {
			if slot.Slot == slotID {
				slotFound = true
				existingSlotID = slot.ID
			}
		}
		require.True(t, slotFound)

		// Delete the configured slot
		deleteSlotInput := hsmslot.DeleteHSMSlotInput{
			StandardID: entities.StandardID{
				ID: existingSlotID,
			},
		}
		_, deleteErr := app.HSMSlotUseCase.DeleteHSMSlot(ctx, deleteSlotInput)
		require.NoError(t, deleteErr)

		// Create the slot for the specified application
		createdSlot, err = app.HSMSlotUseCase.CreateHSMSlot(ctx, createSlotInput)
		require.NoError(t, err)
		require.NotNil(t, createdSlot)
		return &createdSlot.HSMSlot
	}
	require.NotNil(t, createdSlot)
	return &createdSlot.HSMSlot
}
