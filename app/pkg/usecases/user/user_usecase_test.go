package user_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	gotime "time"

	"github.com/lfdt-smoot/signare/app/pkg/adapters/storage/postgres/userdbout"
	"github.com/lfdt-smoot/signare/app/pkg/commons/time"
	"github.com/lfdt-smoot/signare/app/pkg/commons/validators"
	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/graph"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/application"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnection"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmmodule"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmslot"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/user"
	"github.com/lfdt-smoot/signare/app/test/dbtesthelper"
	"github.com/lfdt-smoot/signare/app/test/signaturemanagertesthelper"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

var (
	slotID string

	// testAdminCaller stands in for a signer-admin: an authenticated principal acting without an
	// application header, for whom the self-service guard does not apply. Tests that are not about
	// the guard use it so the mandatory caller is stated without repeating the intent.
	testAdminCaller = entities.Caller{ID: "test-signer-admin"}

	chainID          = entities.NewInt256FromInt(44844)
	slotPin          = signaturemanagertesthelper.SlotPin
	hsmLoadedAddress = signaturemanagertesthelper.ImportedKeyAddress

	app graph.GraphShared
)

func TestMain(m *testing.M) {
	initializedSlotID, _, err := signaturemanagertesthelper.InitializeSoftHSMSlot()
	if err != nil {
		panic(err)
	}
	slotID = *initializedSlotID

	testApp, err := dbtesthelper.InitializeApp()
	if err != nil {
		panic(err)
	}
	app = *testApp

	validators.SetValidators()
	os.Exit(m.Run())
}

func TestProvideDefaultUseCase(t *testing.T) {
	t.Run("nil storage", func(t *testing.T) {
		userUseCase, err := user.ProvideDefaultUseCase(user.DefaultUserUseCaseOptions{
			Storage:            nil,
			ApplicationUseCase: &application.DefaultUseCase{},
		})
		require.Error(t, err)
		require.Nil(t, userUseCase)
	})

	t.Run("nil application use case", func(t *testing.T) {
		userUseCase, err := user.ProvideDefaultUseCase(user.DefaultUserUseCaseOptions{
			Storage:            &userdbout.Repository{},
			ApplicationUseCase: nil,
		})
		require.Error(t, err)
		require.Nil(t, userUseCase)
	})
}

func TestDefaultUseCase_CreateUser(t *testing.T) {
	ctx := context.Background()

	applicationID := uuid.NewString()
	description := "application for CreateUser test"
	createApplicationInput := application.CreateApplicationInput{
		ID:          &applicationID,
		ChainID:     *chainID,
		Description: &description,
	}
	createdApplication, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, createApplicationInput)
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createdApplication)

	t.Run("failure: invalid input arguments", func(t *testing.T) {
		input := user.CreateUserInput{
			Caller:        testAdminCaller,
			ApplicationID: "",
			Roles: []string{
				"application-admin",
			},
		}
		output, err := app.UserUseCase.CreateUser(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)

		input = user.CreateUserInput{
			Caller:        testAdminCaller,
			ApplicationID: createdApplication.ID,
			Roles:         []string{},
		}
		output, err = app.UserUseCase.CreateUser(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("success: if ID is not provided a random one is generated", func(t *testing.T) {
		input := user.CreateUserInput{
			Caller:        testAdminCaller,
			ApplicationID: createdApplication.ID,
			Roles: []string{
				"application-admin",
			},
		}
		output, err := app.UserUseCase.CreateUser(ctx, input)
		require.NoError(t, err)
		require.NotNil(t, output)
		require.NotEmpty(t, output.ID)
	})

	t.Run("success", func(t *testing.T) {
		userID := uuid.New().String()
		input := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: createdApplication.ID,
			Roles: []string{
				"application-admin",
			},
		}
		output, err := app.UserUseCase.CreateUser(ctx, input)
		require.NoError(t, err)
		require.NotNil(t, output)
		require.NotEmpty(t, output.InternalResourceID)
		require.Equal(t, userID, output.ID)
	})

	t.Run("success: transaction-signer is assignable", func(t *testing.T) {
		// Pins that the application-scope gate does not over-block the other application-scoped role.
		userID := uuid.New().String()
		input := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: createdApplication.ID,
			Roles: []string{
				"transaction-signer",
			},
		}
		output, err := app.UserUseCase.CreateUser(ctx, input)
		require.NoError(t, err)
		require.NotNil(t, output)
		require.Equal(t, []string{"transaction-signer"}, output.Roles)
	})

	t.Run("success: message-signer is assignable alongside transaction-signer", func(t *testing.T) {
		// message-signer grants personal_sign on its own, so an identity that only authenticates never
		// needs transaction signing. Pins that it is application-scoped, and that a user needing both
		// can hold both rather than the two roles being mutually exclusive.
		userID := uuid.New().String()
		input := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: createdApplication.ID,
			Roles: []string{
				"message-signer",
				"transaction-signer",
			},
		}
		output, err := app.UserUseCase.CreateUser(ctx, input)
		require.NoError(t, err)
		require.NotNil(t, output)
		require.ElementsMatch(t, []string{"message-signer", "transaction-signer"}, output.Roles)
	})

	t.Run("failure: invalid role", func(t *testing.T) {
		userID := uuid.New().String()
		input := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: createdApplication.ID,
			Roles: []string{
				"invalid-role",
			},
		}
		output, err := app.UserUseCase.CreateUser(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("failure: signer-admin not assignable", func(t *testing.T) {
		userID := uuid.New().String()
		input := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: createdApplication.ID,
			Roles: []string{
				"signer-admin",
			},
		}
		output, err := app.UserUseCase.CreateUser(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("failure: signer-admin not assignable alongside an application role", func(t *testing.T) {
		userID := uuid.New().String()
		input := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: createdApplication.ID,
			Roles: []string{
				"application-admin",
				"signer-admin",
			},
		}
		output, err := app.UserUseCase.CreateUser(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("failure: already exists", func(t *testing.T) {
		userID := uuid.New().String()
		input := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: createdApplication.ID,
			Roles: []string{
				"application-admin",
			},
		}
		_, err := app.UserUseCase.CreateUser(ctx, input)
		require.NoError(t, err)

		// Duplicated entry
		output, err := app.UserUseCase.CreateUser(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsAlreadyExists(err))
		require.Nil(t, output)
	})
}

func TestDefaultUseCase_ListUsers(t *testing.T) {
	ctx := context.Background()

	application1ID := uuid.NewString()
	description := "application for CreateUser test"
	createApplication1Input := application.CreateApplicationInput{
		ID:          &application1ID,
		ChainID:     *chainID,
		Description: &description,
	}
	createdApplication1, createApplication1Err := app.ApplicationUseCase.CreateApplication(ctx, createApplication1Input)
	require.NoError(t, createApplication1Err)
	require.NotNil(t, createdApplication1)

	usersToCreate := 20
	// Users for application-1
	for i := 1; i <= usersToCreate; i++ {
		userID := fmt.Sprint("user-", i)
		testDesc := "my-description"
		input := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: createdApplication1.ID,
			Description:   &testDesc,
			Roles: []string{
				"application-admin",
			},
		}
		_, err := app.UserUseCase.CreateUser(ctx, input)
		require.NoError(t, err)
	}

	application2ID := uuid.NewString()
	createApplication2Input := application.CreateApplicationInput{
		ID:          &application2ID,
		ChainID:     *chainID,
		Description: &description,
	}
	createdApplication2, createApplication2Err := app.ApplicationUseCase.CreateApplication(ctx, createApplication2Input)
	require.NoError(t, createApplication2Err)
	require.NotNil(t, createdApplication2)

	// Users for application-2
	for i := 1; i <= usersToCreate; i++ {
		userID := fmt.Sprint("user-", i)
		testDesc := "my-description"
		input := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: createdApplication2.ID,
			Description:   &testDesc,
			Roles: []string{
				"application-admin",
			},
		}
		_, err := app.UserUseCase.CreateUser(ctx, input)
		require.NoError(t, err)
		gotime.Sleep(gotime.Millisecond)
	}

	t.Run("failure: invalid arguments", func(t *testing.T) {
		input := user.ListUsersInput{
			ApplicationID: "",
		}
		output, err := app.UserUseCase.ListUsers(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)

		input = user.ListUsersInput{
			ApplicationID: "test-app",
			PageLimit:     -50,
			PageOffset:    -30,
		}
		output, err = app.UserUseCase.ListUsers(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("failure: invalid order direction", func(t *testing.T) {
		input := user.ListUsersInput{
			ApplicationID:  createdApplication1.ID,
			OrderDirection: "sideways",
		}
		output, err := app.UserUseCase.ListUsers(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("success: order direction is case-insensitive", func(t *testing.T) {
		input := user.ListUsersInput{
			ApplicationID:  createdApplication1.ID,
			OrderDirection: "ASC",
		}
		output, err := app.UserUseCase.ListUsers(ctx, input)
		require.NoError(t, err)
		require.Len(t, output.Items, usersToCreate)
	})

	t.Run("success: list all users without limit", func(t *testing.T) {
		input := user.ListUsersInput{
			ApplicationID: createdApplication1.ID,
		}
		output, err := app.UserUseCase.ListUsers(ctx, input)
		require.NoError(t, err)
		require.Len(t, output.Items, usersToCreate)
	})

	t.Run("success: list DESC with limit", func(t *testing.T) {
		desiredLimit := 5
		input := user.ListUsersInput{
			ApplicationID:  createdApplication2.ID,
			OrderBy:        "creationDate",
			OrderDirection: "desc",
			PageLimit:      desiredLimit,
		}
		output, err := app.UserUseCase.ListUsers(ctx, input)
		require.NoError(t, err)
		require.Len(t, output.Items, desiredLimit)
		require.True(t, output.MoreItems)
		require.Equal(t, "user-20", output.Items[0].ID)
		require.Equal(t, "user-19", output.Items[1].ID)
		require.Equal(t, "user-18", output.Items[2].ID)
		require.Equal(t, "user-17", output.Items[3].ID)
		require.Equal(t, "user-16", output.Items[4].ID)
		// Assert order
		for i := 1; i < len(output.Items); i++ {
			require.GreaterOrEqual(t, output.Items[i-1].CreationDate.ToInt64(), output.Items[i].CreationDate.ToInt64())
		}
	})

	t.Run("success: list ASC with limit", func(t *testing.T) {
		desiredLimit := 5
		input := user.ListUsersInput{
			ApplicationID:  createdApplication2.ID,
			OrderBy:        "lastUpdate",
			OrderDirection: "asc",
			PageLimit:      desiredLimit,
		}
		output, err := app.UserUseCase.ListUsers(ctx, input)
		require.NoError(t, err)
		require.Len(t, output.Items, desiredLimit)
		require.True(t, output.MoreItems)
		require.Equal(t, "user-1", output.Items[0].ID)
		require.Equal(t, "user-2", output.Items[1].ID)
		require.Equal(t, "user-3", output.Items[2].ID)
		require.Equal(t, "user-4", output.Items[3].ID)
		require.Equal(t, "user-5", output.Items[4].ID)
		// Assert order
		for i := 1; i < len(output.Items); i++ {
			require.LessOrEqual(t, output.Items[i-1].LastUpdate.ToInt64(), output.Items[i].LastUpdate.ToInt64())
		}
	})
}

func TestDefaultUseCase_GetUser(t *testing.T) {
	ctx := context.Background()

	applicationID := uuid.NewString()
	description := "application for CreateUser test"
	createApplicationInput := application.CreateApplicationInput{
		ID:          &applicationID,
		ChainID:     *chainID,
		Description: &description,
	}
	createdApplication, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, createApplicationInput)
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createdApplication)

	t.Run("failure: invalid arguments", func(t *testing.T) {
		input := user.GetUserInput{
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            "",
				ApplicationID: createdApplication.ID,
			},
		}
		output, err := app.UserUseCase.GetUser(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)

		input = user.GetUserInput{
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            "my-user",
				ApplicationID: "",
			},
		}
		output, err = app.UserUseCase.GetUser(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("failure: user not found", func(t *testing.T) {
		input := user.GetUserInput{
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            "my-id",
				ApplicationID: createdApplication.ID,
			},
		}
		output, err := app.UserUseCase.GetUser(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Nil(t, output)
	})

	t.Run("success", func(t *testing.T) {
		// Create user before retrieving it
		userID := uuid.New().String()
		testDesc := "my-description"
		createInput := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: createdApplication.ID,
			Description:   &testDesc,
			Roles: []string{
				"application-admin",
			},
		}
		_, err := app.UserUseCase.CreateUser(ctx, createInput)
		require.NoError(t, err)

		getInput := user.GetUserInput{
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            userID,
				ApplicationID: createdApplication.ID,
			},
		}
		output, err := app.UserUseCase.GetUser(ctx, getInput)
		require.NoError(t, err)
		require.NotNil(t, output)
		require.Equal(t, createInput.ApplicationID, output.ApplicationID)
		require.Equal(t, createInput.Description, output.Description)
		require.Len(t, output.Roles, 1)
		require.Equal(t, createInput.Roles[0], output.Roles[0])
		require.Empty(t, output.Accounts)
		require.NotEmpty(t, output.InternalResourceID)
	})
}

func TestDefaultUseCase_EditUser(t *testing.T) {
	ctx := context.Background()

	applicationID := uuid.NewString()
	description := "application for CreateUser test"
	createApplicationInput := application.CreateApplicationInput{
		ID:          &applicationID,
		ChainID:     *chainID,
		Description: &description,
	}
	createdApplication, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, createApplicationInput)
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createdApplication)

	t.Run("failure: invalid arguments", func(t *testing.T) {
		input := user.EditUserInput{
			Caller: testAdminCaller,
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            "my-id",
				ApplicationID: "",
			},
			ResourceVersion: "",
			Roles:           []string{"application-admin"},
		}
		output, err := app.UserUseCase.EditUser(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)

		input = user.EditUserInput{
			Caller: testAdminCaller,
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            "",
				ApplicationID: createdApplication.ID,
			},
			ResourceVersion: "",
		}
		output, err = app.UserUseCase.EditUser(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)

		input = user.EditUserInput{
			Caller: testAdminCaller,
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            "",
				ApplicationID: "",
			},
			ResourceVersion: "the-resource-version",
			Roles:           []string{"application-admin"},
		}
		output, err = app.UserUseCase.EditUser(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("failure: user not found", func(t *testing.T) {
		input := user.EditUserInput{
			Caller: testAdminCaller,
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            uuid.New().String(),
				ApplicationID: createdApplication.ID,
			},
			ResourceVersion: "the-resource-version",
			Roles:           []string{"application-admin"},
		}
		output, err := app.UserUseCase.EditUser(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Nil(t, output)
	})

	t.Run("failure: invalid resource version", func(t *testing.T) {
		// Create the User first
		userID := uuid.New().String()
		testDesc := "my-description"
		createInput := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: createdApplication.ID,
			Description:   &testDesc,
			Roles: []string{
				"application-admin",
			},
		}
		_, err := app.UserUseCase.CreateUser(ctx, createInput)
		require.NoError(t, err)

		input := user.EditUserInput{
			Caller: testAdminCaller,
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            *createInput.ID,
				ApplicationID: createInput.ApplicationID,
			},
			ResourceVersion: "invalid-resource-version",
			Roles:           []string{"application-admin"},
		}
		output, err := app.UserUseCase.EditUser(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Nil(t, output)
	})

	t.Run("failure: role is mandatory", func(t *testing.T) {
		// Create the User first
		userID := uuid.New().String()
		testDesc := "my-description"
		createInput := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: createdApplication.ID,
			Description:   &testDesc,
			Roles: []string{
				"application-admin",
			},
		}
		_, err := app.UserUseCase.CreateUser(ctx, createInput)
		require.NoError(t, err)

		input := user.EditUserInput{
			Caller: testAdminCaller,
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            *createInput.ID,
				ApplicationID: createInput.ApplicationID,
			},
			ResourceVersion: "invalid-resource-version",
		}
		output, err := app.UserUseCase.EditUser(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("failure: invalid role", func(t *testing.T) {
		// Create the User first
		userID := uuid.New().String()
		testDesc := "my-description"
		createInput := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: createdApplication.ID,
			Description:   &testDesc,
			Roles: []string{
				"application-admin",
			},
		}
		_, err := app.UserUseCase.CreateUser(ctx, createInput)
		require.NoError(t, err)

		input := user.EditUserInput{
			Caller: testAdminCaller,
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            *createInput.ID,
				ApplicationID: createInput.ApplicationID,
			},
			ResourceVersion: "invalid-resource-version",
			Roles:           []string{"not-supported-role"},
		}
		output, err := app.UserUseCase.EditUser(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("failure: signer-admin not assignable", func(t *testing.T) {
		// Create the User first
		userID := uuid.New().String()
		testDesc := "my-description"
		createInput := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: createdApplication.ID,
			Description:   &testDesc,
			Roles: []string{
				"application-admin",
			},
		}
		_, err := app.UserUseCase.CreateUser(ctx, createInput)
		require.NoError(t, err)

		// An application-admin must not be able to escalate an application user to signer-admin.
		input := user.EditUserInput{
			Caller: testAdminCaller,
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            *createInput.ID,
				ApplicationID: createInput.ApplicationID,
			},
			ResourceVersion: "invalid-resource-version",
			Roles:           []string{"application-admin", "signer-admin"},
		}
		output, err := app.UserUseCase.EditUser(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("success", func(t *testing.T) {
		// Create the User first
		userID := uuid.New().String()
		testDesc := "my-description"
		createInput := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: createdApplication.ID,
			Description:   &testDesc,
			Roles: []string{
				"application-admin",
			},
		}
		createdUser, err := app.UserUseCase.CreateUser(ctx, createInput)
		require.NoError(t, err)

		// Edit the created user
		gotime.Sleep(gotime.Millisecond)
		newDescription := "this is the new description"
		newRoles := []string{
			"application-admin",
			"transaction-signer",
		}
		input := user.EditUserInput{
			Caller: testAdminCaller,
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            createdUser.ID,
				ApplicationID: createdUser.ApplicationID,
			},
			ResourceVersion: createdUser.ResourceVersion,
			Description:     &newDescription,
			Roles:           newRoles,
		}
		editedUser, err := app.UserUseCase.EditUser(ctx, input)
		require.NoError(t, err)
		require.NotNil(t, editedUser)
		require.Equal(t, newDescription, *editedUser.Description)
		require.Equal(t, newRoles, editedUser.Roles)
		require.NotEqual(t, createdUser.ResourceVersion, editedUser.ResourceVersion)
		require.Equal(t, createdUser.CreationDate, editedUser.CreationDate)
		require.NotEqual(t, createdUser.LastUpdate, editedUser.LastUpdate)
	})
}

func TestDefaultUseCase_DeleteUser(t *testing.T) {
	ctx := context.Background()

	applicationID := uuid.NewString()
	description := "application for CreateUser test"
	createApplicationInput := application.CreateApplicationInput{
		ID:          &applicationID,
		ChainID:     *chainID,
		Description: &description,
	}
	createdApplication, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, createApplicationInput)
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createdApplication)

	t.Run("failure: invalid input arguments", func(t *testing.T) {
		deleteInput := user.DeleteUserInput{
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            "my-id",
				ApplicationID: "",
			},
		}
		output, err := app.UserUseCase.DeleteUser(ctx, deleteInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)

		deleteInput = user.DeleteUserInput{
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            "",
				ApplicationID: createdApplication.ID,
			},
		}
		output, err = app.UserUseCase.DeleteUser(ctx, deleteInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("failure: nonexistent user", func(t *testing.T) {
		deleteInput := user.DeleteUserInput{
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            uuid.New().String(),
				ApplicationID: createdApplication.ID,
			},
		}
		output, err := app.UserUseCase.DeleteUser(ctx, deleteInput)
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Nil(t, output)
	})

	t.Run("success", func(t *testing.T) {
		// Create a valid user
		userID := uuid.New().String()
		createInput := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: createdApplication.ID,
			Roles: []string{
				"application-admin",
			},
		}
		createdUser, err := app.UserUseCase.CreateUser(ctx, createInput)
		require.NoError(t, err)

		// Delete the user
		deleteInput := user.DeleteUserInput{
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            userID,
				ApplicationID: createdApplication.ID,
			},
		}
		deletedUser, err := app.UserUseCase.DeleteUser(ctx, deleteInput)
		require.NoError(t, err)
		require.NotNil(t, deletedUser)
		require.Equal(t, createdUser.ID, deletedUser.ID)
		require.Equal(t, createdUser.InternalResourceID, deletedUser.InternalResourceID)
		require.Equal(t, createdUser.ApplicationID, deletedUser.ApplicationID)
		require.Equal(t, createdUser.ResourceVersion, deletedUser.ResourceVersion)
		require.Equal(t, createdUser.Roles, deletedUser.Roles)
		require.Equal(t, createdUser.Description, deletedUser.Description)
		require.Empty(t, deletedUser.Accounts)

		// Retrieve deleted user
		getOutput, err := app.UserUseCase.GetUser(ctx, user.GetUserInput{
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            userID,
				ApplicationID: createdApplication.ID,
			},
		})
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Nil(t, getOutput)
	})
}

func TestDefaultUseCase_AddUserAccounts(t *testing.T) {
	ctx := context.Background()

	applicationID := uuid.NewString()
	description := "application for CreateUser test"
	createApplicationInput := application.CreateApplicationInput{
		ID:          &applicationID,
		ChainID:     *chainID,
		Description: &description,
	}
	createApplicationOutput, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, createApplicationInput)
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createApplicationOutput)
	currentTestApplication := createApplicationOutput

	hsm := createHSM(ctx, t)
	// Create a slot within the HSM
	createHSMSlotInput := hsmslot.CreateHSMSlotInput{
		ApplicationID: currentTestApplication.ID,
		HSMModuleID:   hsm.ID,
		Slot:          slotID,
		Pin:           slotPin,
	}
	createHSMSlotOutput, createHSMSlotErr := app.HSMSlotUseCase.CreateHSMSlot(ctx, createHSMSlotInput)
	require.NoError(t, createHSMSlotErr)
	require.NotNil(t, createHSMSlotOutput)

	t.Run("failure: invalid input arguments", func(t *testing.T) {
		input := user.EnableAccountsInput{
			UserID:        "",
			ApplicationID: currentTestApplication.ID,
			Addresses: []address.Address{
				address.MustNewFromHexString("0xDc611d30c81e723D0A78BE33f5aF3974c108f5cf"),
			},
		}
		output, err := app.UserUseCase.EnableAccounts(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)

		input = user.EnableAccountsInput{
			UserID:        "my-user-id",
			ApplicationID: "",
			Addresses: []address.Address{
				address.MustNewFromHexString("0xDc611d30c81e723D0A78BE33f5aF3974c108f5cf"),
			},
		}
		output, err = app.UserUseCase.EnableAccounts(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)

		input = user.EnableAccountsInput{
			UserID:        "my-user-id",
			ApplicationID: currentTestApplication.ID,
			Addresses: []address.Address{
				address.MustNewFromHexString("invalid address"),
			},
		}
		output, err = app.UserUseCase.EnableAccounts(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)

		// An empty address list must be rejected rather than silently succeeding.
		input = user.EnableAccountsInput{
			UserID:        "my-user-id",
			ApplicationID: currentTestApplication.ID,
			Addresses:     []address.Address{},
		}
		output, err = app.UserUseCase.EnableAccounts(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("failure: user not found", func(t *testing.T) {
		input := user.EnableAccountsInput{
			UserID:        uuid.New().String(),
			ApplicationID: currentTestApplication.ID,
			Addresses: []address.Address{
				address.MustNewFromHexString("0xDc611d30c81e723D0A78BE33f5aF3974c108f5cf"),
			},
		}
		output, err := app.UserUseCase.EnableAccounts(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Nil(t, output)
	})

	t.Run("failure: user's application not found", func(t *testing.T) {
		// Create a valid User
		userID := uuid.New().String()
		createUserInput := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: currentTestApplication.ID,
			Roles: []string{
				"application-admin",
			},
		}
		_, err := app.UserUseCase.CreateUser(ctx, createUserInput)
		require.NoError(t, err)

		// Add user account
		input := user.EnableAccountsInput{
			UserID:        userID,
			ApplicationID: "non-existent-application",
			Addresses: []address.Address{
				address.MustNewFromHexString("0xDc611d30c81e723D0A78BE33f5aF3974c108f5cf"),
			},
		}
		output, err := app.UserUseCase.EnableAccounts(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Nil(t, output)
	})

	t.Run("success: adding duplicated accounts results in no error but no accounts persisted", func(t *testing.T) {
		// Create a valid User
		userID := uuid.New().String()
		createUserInput := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: currentTestApplication.ID,
			Roles: []string{
				"application-admin",
			},
		}
		_, err := app.UserUseCase.CreateUser(ctx, createUserInput)
		require.NoError(t, err)

		// Add invalid (duplicated) accounts
		byApplicationInput := hsmconnection.ByApplicationInput{
			ApplicationID: currentTestApplication.ID,
		}
		hsmConnection, byApplicationErr := app.HSMConnectionResolver.ByApplication(ctx, byApplicationInput)
		require.NoError(t, byApplicationErr)
		require.NotNil(t, hsmConnection)

		generateAddressInput := hsmconnector.GenerateAddressInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       hsmConnection.Slot.Slot,
				Pin:        hsmConnection.Slot.Pin,
				ModuleKind: hsmconnector.ModuleKind(hsmConnection.ModuleKind),
			},
		}
		generateAddressOneOutput, generateAddressOneErr := app.HSMConnector.GenerateAddress(ctx, generateAddressInput)
		require.NoError(t, generateAddressOneErr)
		require.NotNil(t, generateAddressOneOutput)

		input := user.EnableAccountsInput{
			UserID:        userID,
			ApplicationID: applicationID,
			Addresses: []address.Address{
				generateAddressOneOutput.Address,
				generateAddressOneOutput.Address,
				generateAddressOneOutput.Address,
			},
		}
		output, err := app.UserUseCase.EnableAccounts(ctx, input)
		require.NoError(t, err)
		require.NotNil(t, output)
		require.Len(t, output.Accounts, 1)
	})

	t.Run("success", func(t *testing.T) {
		// Create a valid User
		userID := uuid.New().String()
		createUserInput := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: currentTestApplication.ID,
			Roles: []string{
				"application-admin",
			},
		}
		_, err := app.UserUseCase.CreateUser(ctx, createUserInput)
		require.NoError(t, err)

		// Add user accounts
		byApplicationInput := hsmconnection.ByApplicationInput{
			ApplicationID: currentTestApplication.ID,
		}
		hsmConnection, byApplicationErr := app.HSMConnectionResolver.ByApplication(ctx, byApplicationInput)
		require.NoError(t, byApplicationErr)
		require.NotNil(t, hsmConnection)

		generateAddressInput := hsmconnector.GenerateAddressInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       hsmConnection.Slot.Slot,
				Pin:        hsmConnection.Slot.Pin,
				ModuleKind: hsmconnector.ModuleKind(hsmConnection.ModuleKind),
			},
		}
		generateAddressOneOutput, generateAddressOneErr := app.HSMConnector.GenerateAddress(ctx, generateAddressInput)
		require.NoError(t, generateAddressOneErr)
		require.NotNil(t, generateAddressOneOutput)
		input := user.EnableAccountsInput{
			UserID:        userID,
			ApplicationID: currentTestApplication.ID,
			Addresses: []address.Address{
				generateAddressOneOutput.Address,
			},
		}
		output, err := app.UserUseCase.EnableAccounts(ctx, input)
		require.NoError(t, err)
		require.NotNil(t, output)
		require.Equal(t, userID, output.ID)
		require.Equal(t, applicationID, output.ApplicationID)
		require.Len(t, output.Accounts, 1)
		require.Equal(t, input.Addresses[0].String(), output.Accounts[0].Address.String())
	})
}

func TestDefaultUseCase_RemoveUserAccount(t *testing.T) {
	ctx := context.Background()

	applicationID := uuid.NewString()
	description := "application for CreateUser test"
	createApplicationInput := application.CreateApplicationInput{
		ID:          &applicationID,
		ChainID:     *chainID,
		Description: &description,
	}
	createdApplication, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, createApplicationInput)
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createdApplication)

	t.Run("failure: invalid input arguments", func(t *testing.T) {
		input := user.DisableAccountInput{
			UserID:        "",
			ApplicationID: createdApplication.ID,
			Address:       address.MustNewFromHexString("0xDc611d30c81e723D0A78BE33f5aF3974c108f5cf"),
		}
		output, err := app.UserUseCase.DisableAccount(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)

		input = user.DisableAccountInput{
			UserID:        "my-user-id",
			ApplicationID: "",
			Address:       address.MustNewFromHexString("0xDc611d30c81e723D0A78BE33f5aF3974c108f5cf"),
		}
		output, err = app.UserUseCase.DisableAccount(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)

		input = user.DisableAccountInput{
			UserID:        "my-user-id",
			ApplicationID: createdApplication.ID,
			Address:       address.MustNewFromHexString("invalid address"),
		}
		output, err = app.UserUseCase.DisableAccount(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, output)
	})

	t.Run("failure: account not found", func(t *testing.T) {
		input := user.DisableAccountInput{
			UserID:        "my-user-id",
			ApplicationID: createdApplication.ID,
			Address:       address.MustNewFromHexString("0xDc611d30c81e723D0A78BE33f5aF3974c108f5cf"),
		}
		output, err := app.UserUseCase.DisableAccount(ctx, input)
		require.Error(t, err)
		require.True(t, errors.IsNotFound(err))
		require.Nil(t, output)
	})

	t.Run("success", func(t *testing.T) {
		// Create an HSM to create accounts
		hsm := createHSM(ctx, t)
		require.NotNil(t, hsm)

		// Create a slot within the HSM
		createHSMSlotInput := hsmslot.CreateHSMSlotInput{
			ApplicationID: createdApplication.ID,
			HSMModuleID:   hsm.ID,
			Slot:          slotID,
			Pin:           slotPin,
		}
		createHSMSlotOutput, createHSMSlotErr := app.HSMSlotUseCase.CreateHSMSlot(ctx, createHSMSlotInput)
		require.NoError(t, createHSMSlotErr)
		require.NotNil(t, createHSMSlotOutput)

		// Create a valid User
		userID := uuid.New().String()
		createUserInput := user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &userID,
			ApplicationID: createdApplication.ID,
			Roles: []string{
				"application-admin",
			},
		}
		_, err := app.UserUseCase.CreateUser(ctx, createUserInput)
		require.NoError(t, err)

		// Add user account
		byApplicationInput := hsmconnection.ByApplicationInput{
			ApplicationID: createdApplication.ID,
		}
		hsmConnection, byApplicationErr := app.HSMConnectionResolver.ByApplication(ctx, byApplicationInput)
		require.NoError(t, byApplicationErr)
		require.NotNil(t, hsmConnection)

		generateAddressInput := hsmconnector.GenerateAddressInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       hsmConnection.Slot.Slot,
				Pin:        hsmConnection.Slot.Pin,
				ModuleKind: hsmconnector.ModuleKind(hsmConnection.ModuleKind),
			},
		}
		generateAddressOneOutput, generateAddressOneErr := app.HSMConnector.GenerateAddress(ctx, generateAddressInput)
		require.NoError(t, generateAddressOneErr)
		require.NotNil(t, generateAddressOneOutput)
		input := user.EnableAccountsInput{
			UserID:        userID,
			ApplicationID: applicationID,
			Addresses: []address.Address{
				generateAddressOneOutput.Address,
			},
		}
		_, err = app.UserUseCase.EnableAccounts(ctx, input)
		require.NoError(t, err)

		removeAccountInput := user.DisableAccountInput{
			UserID:        userID,
			ApplicationID: applicationID,
			Address:       generateAddressOneOutput.Address,
		}
		output, err := app.UserUseCase.DisableAccount(ctx, removeAccountInput)
		require.NoError(t, err)
		require.NotNil(t, output)
		require.Empty(t, output.Accounts)
	})
}
func createHSM(ctx context.Context, t *testing.T) *hsmmodule.HSMModule {
	description := "HSM module for testing"
	hsmModule := hsmmodule.HSMModule{
		StandardResourceMeta: entities.StandardResourceMeta{
			StandardResource: entities.StandardResource{
				StandardID: entities.StandardID{
					ID: uuid.NewString(),
				},
				Timestamps: entities.Timestamps{
					CreationDate: time.Now(),
					LastUpdate:   time.Now(),
				},
			},
			ResourceVersion: uuid.NewString(),
		},
		Description: &description,
		Configuration: hsmmodule.HSMModuleConfiguration{
			SoftHSMConfiguration: &hsmmodule.SoftHSMConfiguration{},
		},
		Kind: hsmmodule.SoftHSMModuleKind,
	}
	createHSMModuleInput := hsmmodule.CreateHSMModuleInput{
		ID:            &hsmModule.ID,
		Description:   hsmModule.Description,
		Configuration: hsmModule.Configuration,
		ModuleKind:    hsmModule.Kind,
	}
	addedModule, err := app.HSMModuleUseCase.CreateHSMModule(ctx, createHSMModuleInput)
	if err != nil {
		require.True(t, errors.IsAlreadyExists(err))
		getHSMModuleInput := hsmmodule.GetHSMModuleInput{
			StandardID: entities.StandardID{
				ID: hsmModule.ID,
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

func createAKVHSM(ctx context.Context, t *testing.T) *hsmmodule.HSMModule {
	description := "AKV HSM module for testing"
	createHSMModuleInput := hsmmodule.CreateHSMModuleInput{
		Description: &description,
		Configuration: hsmmodule.HSMModuleConfiguration{
			AKVConfiguration: &hsmmodule.AKVConfiguration{},
		},
		ModuleKind: hsmmodule.AKVModuleKind,
	}
	addedModule, err := app.HSMModuleUseCase.CreateHSMModule(ctx, createHSMModuleInput)
	require.NoError(t, err)
	require.NotNil(t, addedModule)
	return &addedModule.HSMModule
}

func TestDefaultUseCase_AddUserAccounts_AKVValidation(t *testing.T) {
	ctx := context.Background()

	applicationID := uuid.NewString()
	description := "application for AKV EnableAccounts test"
	createApplicationOutput, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, application.CreateApplicationInput{
		ID:          &applicationID,
		ChainID:     *chainID,
		Description: &description,
	})
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createApplicationOutput)

	configuredAddress := address.MustNewFromHexString("0xDc611d30c81e723D0A78BE33f5aF3974c108f5cf")
	unconfiguredAddress := address.MustNewFromHexString("0x970E8128AB834E8EAC17Ab8E3812F010678CF791")
	// zeroByteAddress contains 0x00 bytes but is not the zero address. It guards against a validation
	// mechanism that rejects addresses with a zero byte (regression for the required-tag bug).
	zeroByteAddress := address.MustNewFromHexString("0x0011223344556677889900aabbccddeeff001122")

	akvHSM := createAKVHSM(ctx, t)
	createHSMSlotOutput, createHSMSlotErr := app.HSMSlotUseCase.CreateHSMSlot(ctx, hsmslot.CreateHSMSlotInput{
		ApplicationID: applicationID,
		HSMModuleID:   akvHSM.ID,
		Config: hsmslot.SlotConfig{
			AKV: []hsmslot.AKVConfig{
				{
					KeyName:          "test-key",
					KeyVersion:       "1",
					KeyPublicAddress: configuredAddress.String(),
				},
				{
					KeyName:          "test-key-zero-byte",
					KeyVersion:       "1",
					KeyPublicAddress: zeroByteAddress.String(),
				},
			},
		},
	})
	require.NoError(t, createHSMSlotErr)
	require.NotNil(t, createHSMSlotOutput)

	userID := uuid.NewString()
	_, createUserErr := app.UserUseCase.CreateUser(ctx, user.CreateUserInput{
		Caller:        testAdminCaller,
		ID:            &userID,
		ApplicationID: applicationID,
		Roles:         []string{"application-admin"},
	})
	require.NoError(t, createUserErr)

	t.Run("success: address configured in the AKV slot is accepted", func(t *testing.T) {
		output, err := app.UserUseCase.EnableAccounts(ctx, user.EnableAccountsInput{
			UserID:        userID,
			ApplicationID: applicationID,
			Addresses:     []address.Address{configuredAddress},
		})
		require.NoError(t, err)
		require.NotNil(t, output)
		require.Len(t, output.Accounts, 1)
	})

	t.Run("failure: address not configured in the AKV slot is rejected", func(t *testing.T) {
		output, err := app.UserUseCase.EnableAccounts(ctx, user.EnableAccountsInput{
			UserID:        userID,
			ApplicationID: applicationID,
			Addresses:     []address.Address{unconfiguredAddress},
		})
		require.Error(t, err)
		require.True(t, errors.IsPreconditionFailed(err))
		require.Nil(t, output)
	})

	t.Run("success: address containing a zero byte is accepted", func(t *testing.T) {
		// Regression for the required-tag bug: a valid address with a 0x00 byte must not be rejected
		// at validation time. A fresh user keeps the asserted account count deterministic.
		zeroByteUserID := uuid.NewString()
		_, createErr := app.UserUseCase.CreateUser(ctx, user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &zeroByteUserID,
			ApplicationID: applicationID,
			Roles:         []string{"application-admin"},
		})
		require.NoError(t, createErr)

		output, err := app.UserUseCase.EnableAccounts(ctx, user.EnableAccountsInput{
			UserID:        zeroByteUserID,
			ApplicationID: applicationID,
			Addresses:     []address.Address{zeroByteAddress},
		})
		require.NoError(t, err)
		require.NotNil(t, output)
		require.Len(t, output.Accounts, 1)
	})
}

func TestDefaultUseCase_AddUserAccounts_AKVEmptyConfig(t *testing.T) {
	ctx := context.Background()

	applicationID := uuid.NewString()
	description := "application for AKV empty-config EnableAccounts test"
	createApplicationOutput, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, application.CreateApplicationInput{
		ID:          &applicationID,
		ChainID:     *chainID,
		Description: &description,
	})
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createApplicationOutput)

	// AKV slot with no configured keys: the set of addresses backed by the module is empty.
	akvHSM := createAKVHSM(ctx, t)
	createHSMSlotOutput, createHSMSlotErr := app.HSMSlotUseCase.CreateHSMSlot(ctx, hsmslot.CreateHSMSlotInput{
		ApplicationID: applicationID,
		HSMModuleID:   akvHSM.ID,
		Config:        hsmslot.SlotConfig{},
	})
	require.NoError(t, createHSMSlotErr)
	require.NotNil(t, createHSMSlotOutput)

	userID := uuid.NewString()
	_, createUserErr := app.UserUseCase.CreateUser(ctx, user.CreateUserInput{
		Caller:        testAdminCaller,
		ID:            &userID,
		ApplicationID: applicationID,
		Roles:         []string{"application-admin"},
	})
	require.NoError(t, createUserErr)

	t.Run("failure: enabling against an empty AKV config is rejected", func(t *testing.T) {
		// addressesBackedByModule returns an empty set; the caller must reject (not vacuously accept).
		output, err := app.UserUseCase.EnableAccounts(ctx, user.EnableAccountsInput{
			UserID:        userID,
			ApplicationID: applicationID,
			Addresses:     []address.Address{address.MustNewFromHexString("0xDc611d30c81e723D0A78BE33f5aF3974c108f5cf")},
		})
		require.Error(t, err)
		require.True(t, errors.IsPreconditionFailed(err))
		require.Nil(t, output)
	})
}

// TestDefaultUseCase_SelfServiceGuard covers the separation of duties between application-admin, who
// hands out signing rights, and transaction-signer, who uses them. Both roles are application-scoped,
// so validateApplicationScopedRoles cannot tell them apart; the caller-relative guard is what stops an
// application-admin granting themselves the signing role and then binding the application's keys to
// their own user.
func TestDefaultUseCase_SelfServiceGuard(t *testing.T) {
	ctx := context.Background()

	applicationID := uuid.NewString()
	description := "application for self-service guard test"
	createdApplication, createApplicationErr := app.ApplicationUseCase.CreateApplication(ctx, application.CreateApplicationInput{
		ID:          &applicationID,
		ChainID:     *chainID,
		Description: &description,
	})
	require.NoError(t, createApplicationErr)
	require.NotNil(t, createdApplication)

	// adminUser stands in for the application-admin doing the escalating.
	adminUserID := uuid.NewString()
	createdAdmin, createErr := app.UserUseCase.CreateUser(ctx, user.CreateUserInput{
		Caller:        testAdminCaller,
		ID:            &adminUserID,
		ApplicationID: createdApplication.ID,
		Roles:         []string{"application-admin"},
	})
	require.NoError(t, createErr)
	require.NotNil(t, createdAdmin)

	selfCaller := entities.Caller{ID: adminUserID, ApplicationID: createdApplication.ID}

	t.Run("failure: application-admin cannot grant themselves transaction-signer", func(t *testing.T) {
		output, err := app.UserUseCase.EditUser(ctx, user.EditUserInput{
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            adminUserID,
				ApplicationID: createdApplication.ID,
			},
			ResourceVersion: createdAdmin.ResourceVersion,
			Roles:           []string{"application-admin", "transaction-signer"},
			Caller:          selfCaller,
		})
		require.Error(t, err)
		require.True(t, errors.IsPermissionDenied(err))
		require.Nil(t, output)
	})

	t.Run("failure: the guard is on the record, not just on the roles", func(t *testing.T) {
		// Editing your own record with the roles you already hold is refused too. The guard covers the
		// whole self-directed write so it never has to read the stored roles back to compare them.
		newDescription := "self-service description change"
		output, err := app.UserUseCase.EditUser(ctx, user.EditUserInput{
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            adminUserID,
				ApplicationID: createdApplication.ID,
			},
			ResourceVersion: createdAdmin.ResourceVersion,
			Roles:           []string{"application-admin"},
			Description:     &newDescription,
			Caller:          selfCaller,
		})
		require.Error(t, err)
		require.True(t, errors.IsPermissionDenied(err))
		require.Nil(t, output)
	})

	t.Run("failure: application-admin cannot create a user under their own id", func(t *testing.T) {
		// Defence in depth rather than the load-bearing half of the fix. To be authorized for
		// application.users.create inside an application the caller must already have a user record,
		// since the policy decision point resolves an application caller's roles by reading it, so a
		// real caller creating under their own id would collide on the (application_id, id) primary
		// key anyway. Asserting PermissionDenied and not merely an error is what keeps this honest:
		// without the guard the call still fails, but with AlreadyExists. The two Edit cases above are
		// the ones that close the exploit.
		output, err := app.UserUseCase.CreateUser(ctx, user.CreateUserInput{
			ID:            &adminUserID,
			ApplicationID: createdApplication.ID,
			Roles:         []string{"transaction-signer"},
			Caller:        selfCaller,
		})
		require.Error(t, err)
		require.True(t, errors.IsPermissionDenied(err))
		require.Nil(t, output)
	})

	t.Run("failure: an omitted caller is refused rather than read as not-self", func(t *testing.T) {
		// The guard is opt-in per call site, so the failure mode that matters is a call site that never
		// passes a caller. The zero caller must not fall through as "not application-scoped, therefore
		// allowed": it is a wiring error and both paths say so.
		editOutput, editErr := app.UserUseCase.EditUser(ctx, user.EditUserInput{
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            adminUserID,
				ApplicationID: createdApplication.ID,
			},
			ResourceVersion: createdAdmin.ResourceVersion,
			Roles:           []string{"application-admin", "transaction-signer"},
		})
		require.Error(t, editErr)
		require.True(t, errors.IsInternal(editErr))
		require.Nil(t, editOutput)

		uncalledForID := uuid.NewString()
		createOutput, createErr := app.UserUseCase.CreateUser(ctx, user.CreateUserInput{
			ID:            &uncalledForID,
			ApplicationID: createdApplication.ID,
			Roles:         []string{"transaction-signer"},
		})
		require.Error(t, createErr)
		require.True(t, errors.IsInternal(createErr))
		require.Nil(t, createOutput)
	})

	t.Run("success: application-admin can still onboard a different signer", func(t *testing.T) {
		// Onboarding signers is the application-admin's job. The guard must not block it, otherwise the
		// fix would be an overcorrection that breaks the documented workflow.
		signerID := uuid.NewString()
		output, err := app.UserUseCase.CreateUser(ctx, user.CreateUserInput{
			ID:            &signerID,
			ApplicationID: createdApplication.ID,
			Roles:         []string{"transaction-signer"},
			Caller:        selfCaller,
		})
		require.NoError(t, err)
		require.NotNil(t, output)
		require.Contains(t, output.Roles, "transaction-signer")

		edited, editErr := app.UserUseCase.EditUser(ctx, user.EditUserInput{
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            signerID,
				ApplicationID: createdApplication.ID,
			},
			ResourceVersion: output.ResourceVersion,
			Roles:           []string{"application-admin", "transaction-signer"},
			Caller:          selfCaller,
		})
		require.NoError(t, editErr)
		require.NotNil(t, edited)
	})

	t.Run("success: an admin caller is unaffected", func(t *testing.T) {
		// A signer-admin reaches application routes without an application header, so the caller is not
		// application-scoped and administration behaves exactly as before, including on their own id.
		current, getErr := app.UserUseCase.GetUser(ctx, user.GetUserInput{
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            adminUserID,
				ApplicationID: createdApplication.ID,
			},
		})
		require.NoError(t, getErr)

		output, err := app.UserUseCase.EditUser(ctx, user.EditUserInput{
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            adminUserID,
				ApplicationID: createdApplication.ID,
			},
			ResourceVersion: current.ResourceVersion,
			Roles:           []string{"application-admin", "transaction-signer"},
			Caller:          entities.Caller{ID: "some-signer-admin"},
		})
		require.NoError(t, err)
		require.NotNil(t, output)
		require.Contains(t, output.Roles, "transaction-signer")
	})

	t.Run("success: same user id in a different application is not self, on edit", func(t *testing.T) {
		// The exploit in the issue uses the Edit path, so pin the per-application comparison there too
		// and not only on Create: a future divergence in how the target is built would go unnoticed.
		otherApplicationID := uuid.NewString()
		otherDescription := "other application for the edit path"
		otherApplication, otherErr := app.ApplicationUseCase.CreateApplication(ctx, application.CreateApplicationInput{
			ID:          &otherApplicationID,
			ChainID:     *chainID,
			Description: &otherDescription,
		})
		require.NoError(t, otherErr)

		targetID := uuid.NewString()
		created, createTargetErr := app.UserUseCase.CreateUser(ctx, user.CreateUserInput{
			Caller:        testAdminCaller,
			ID:            &targetID,
			ApplicationID: otherApplication.ID,
			Roles:         []string{"transaction-signer"},
		})
		require.NoError(t, createTargetErr)

		output, err := app.UserUseCase.EditUser(ctx, user.EditUserInput{
			ApplicationStandardID: entities.ApplicationStandardID{
				ID:            targetID,
				ApplicationID: otherApplication.ID,
			},
			ResourceVersion: created.ResourceVersion,
			Roles:           []string{"application-admin"},
			// Same user id, different application: not the caller's own record.
			Caller: entities.Caller{ID: targetID, ApplicationID: createdApplication.ID},
		})
		require.NoError(t, err)
		require.NotNil(t, output)
	})

	t.Run("success: same user id in a different application is not self, on create", func(t *testing.T) {
		// Identifiers are only unique within an application, so the guard must compare the application
		// too. A caller with a colliding id in another application must not be treated as the target.
		otherApplicationID := uuid.NewString()
		otherDescription := "other application"
		otherApplication, otherErr := app.ApplicationUseCase.CreateApplication(ctx, application.CreateApplicationInput{
			ID:          &otherApplicationID,
			ChainID:     *chainID,
			Description: &otherDescription,
		})
		require.NoError(t, otherErr)

		targetID := uuid.NewString()
		output, err := app.UserUseCase.CreateUser(ctx, user.CreateUserInput{
			ID:            &targetID,
			ApplicationID: otherApplication.ID,
			Roles:         []string{"transaction-signer"},
			Caller:        entities.Caller{ID: targetID, ApplicationID: createdApplication.ID},
		})
		require.NoError(t, err)
		require.NotNil(t, output)
	})
}
