package user

import (
	"context"
	"fmt"
	"strings"

	"github.com/lfdt-smoot/signare/app/pkg/commons/logger"
	"github.com/lfdt-smoot/signare/app/pkg/commons/persistence"
	"github.com/lfdt-smoot/signare/app/pkg/commons/time"
	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/application"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/authorization/role"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnection"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmslot"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/referentialintegrity"
	"github.com/lfdt-smoot/signare/app/pkg/utils"

	"github.com/asaskevich/govalidator"
	"github.com/google/uuid"
)

// UserUseCase defines the management of the User resource.
type UserUseCase interface {
	// CreateUser creates a User. It returns the created User or an error if it fails.
	CreateUser(ctx context.Context, creation CreateUserInput) (*CreateUserOutput, error)
	// ListUsers returns all the Users or an error if it fails.
	ListUsers(ctx context.Context, listOptions ListUsersInput) (*ListUsersOutput, error)
	// GetUser returns the requested User or an error if it fails.
	GetUser(ctx context.Context, input GetUserInput) (*GetUserOutput, error)
	// EditUser edits a User. It returns the edited User or an error if it fails.
	EditUser(ctx context.Context, update EditUserInput) (*EditUserOutput, error)
	// DeleteUser deletes a User. It returns the deleted User or an error if it fails.
	DeleteUser(ctx context.Context, input DeleteUserInput) (*DeleteUserOutput, error)
	// EnableAccounts adds accounts in the User's authorized accounts list. It returns the edited User or an error if it fails.
	EnableAccounts(ctx context.Context, input EnableAccountsInput) (*EnableAccountsOutput, error)
	// DisableAccount removes accounts in the User's authorized accounts list. It returns the edited User or an error if it fails.
	DisableAccount(ctx context.Context, input DisableAccountInput) (*DisableAccountOutput, error)
	AccountUseCase
}

func (u *DefaultUserUseCase) CreateUser(ctx context.Context, input CreateUserInput) (*CreateUserOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input user")
	}

	if input.ID == nil {
		randomID := uuid.New().String()
		input.ID = &randomID
	}

	now := time.Now()
	user := User{
		ApplicationStandardResourceMeta: entities.ApplicationStandardResourceMeta{
			ApplicationStandardResource: entities.ApplicationStandardResource{
				ApplicationStandardID: entities.ApplicationStandardID{
					ID:            *input.ID,
					ApplicationID: input.ApplicationID,
				},
				Timestamps: entities.Timestamps{
					CreationDate: now,
					LastUpdate:   now,
				},
			},
		},
		Roles:       input.Roles,
		Description: input.Description,
	}
	if validateErr := u.validateApplicationScopedRoles(ctx, input.Roles); validateErr != nil {
		return nil, validateErr
	}

	user.InternalResourceID = entities.NewInternalResourceID()
	addUserToApplicationDependencyErr := u.addUserToApplicationDependency(ctx, user)
	if addUserToApplicationDependencyErr != nil {
		return nil, addUserToApplicationDependencyErr
	}

	addedUser, err := u.storage.Add(ctx, user)
	if err != nil {
		if errors.IsAlreadyExists(err) {
			return nil, errors.AlreadyExistsFromErr(err)
		}
		return nil, errors.InternalFromErr(err)
	}

	addedUser.Accounts = make([]Account, 0)
	return &CreateUserOutput{
		User: *addedUser,
	}, nil
}

// validateApplicationScopedRoles ensures every requested role is supported and assignable to an
// application user. Admin-scoped roles (e.g. signer-admin) are rejected so that an application-admin
// cannot escalate an application user to a global administrator.
func (u *DefaultUserUseCase) validateApplicationScopedRoles(ctx context.Context, roles []string) error {
	getSupportedRolesOutput, err := u.roleUseCase.GetSupportedRoles(ctx, role.GetSupportedRolesInput{})
	if err != nil {
		return err
	}

	supportedRoles := make(map[string]role.Role, len(getSupportedRolesOutput.Roles))
	for _, supportedRole := range getSupportedRolesOutput.Roles {
		supportedRoles[supportedRole.ID] = supportedRole
	}

	for _, roleID := range roles {
		supportedRole, ok := supportedRoles[roleID]
		if !ok {
			msg := fmt.Sprintf("the role '%s' is not supported", roleID)
			return errors.InvalidArgument().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
		}
		if !supportedRole.IsApplicationScoped() {
			msg := fmt.Sprintf("the role '%s' cannot be assigned to an application user", roleID)
			return errors.InvalidArgument().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
		}
	}

	return nil
}

func (u *DefaultUserUseCase) ListUsers(ctx context.Context, input ListUsersInput) (*ListUsersOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	filters := u.storage.Filter(input.ApplicationID)
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

	userCollection, err := u.storage.All(ctx, filters)
	if err != nil {
		return nil, errors.InternalFromErr(err)
	}
	for i, userItem := range userCollection.Items {
		user := userItem
		listAccountsInput := ListAccountsInput{
			UserID:        &user.ID,
			ApplicationID: user.ApplicationID,
		}
		userAccounts, errList := u.ListAccounts(ctx, listAccountsInput)
		if errList != nil {
			return nil, errors.InternalFromErr(errList)
		}
		accounts := make([]Account, len(userAccounts.Items))
		copy(accounts, userAccounts.Items)
		userCollection.Items[i].Accounts = accounts
	}
	return &ListUsersOutput{
		UserCollection: *userCollection,
	}, nil
}

func (u *DefaultUserUseCase) GetUser(ctx context.Context, input GetUserInput) (*GetUserOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	getInput := entities.ApplicationStandardID{
		ID:            input.ID,
		ApplicationID: input.ApplicationID,
	}
	user, err := u.storage.Get(ctx, getInput)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.NotFoundFromErr(err).WithMessage("user [%s] not found", input.ID)
		}
		return nil, errors.InternalFromErr(err)
	}

	listAccountsInput := ListAccountsInput{
		ApplicationID: user.ApplicationID,
		UserID:        &user.ID,
	}
	userAccounts, errList := u.ListAccounts(ctx, listAccountsInput)
	if errList != nil {
		return nil, errors.InternalFromErr(errList)
	}

	user.Accounts = userAccounts.Items
	return &GetUserOutput{
		User: *user,
	}, nil
}

func (u *DefaultUserUseCase) EditUser(ctx context.Context, input EditUserInput) (*EditUserOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	if len(input.Roles) < 1 {
		return nil, errors.InvalidArgument().WithMessage("the 'Role' cannot be empty")
	}

	if validateErr := u.validateApplicationScopedRoles(ctx, input.Roles); validateErr != nil {
		return nil, validateErr
	}

	user := User{
		ApplicationStandardResourceMeta: entities.ApplicationStandardResourceMeta{
			ApplicationStandardResource: entities.ApplicationStandardResource{
				ApplicationStandardID: entities.ApplicationStandardID{
					ID:            input.ID,
					ApplicationID: input.ApplicationID,
				},
				Timestamps: entities.Timestamps{
					LastUpdate: time.Now(),
				},
			},
			ResourceVersion: input.ResourceVersion,
		},
		Roles: input.Roles,
	}
	if input.Description != nil {
		user.Description = input.Description
	}

	editedUser, err := u.storage.Edit(ctx, user)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.NotFoundFromErr(err).WithMessage("user [%s] not found", input.ID)
		}
		return nil, errors.InternalFromErr(err)
	}

	listAccountsInput := ListAccountsInput{
		ApplicationID: user.ApplicationID,
		UserID:        &user.ID,
	}
	userAccounts, errList := u.ListAccounts(ctx, listAccountsInput)
	if errList != nil {
		return nil, errors.InternalFromErr(errList)
	}

	editedUser.Accounts = userAccounts.Items

	return &EditUserOutput{
		User: *editedUser,
	}, nil
}

func (u *DefaultUserUseCase) DeleteUser(ctx context.Context, input DeleteUserInput) (*DeleteUserOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}
	removeAllDependenciesErr := u.removeAllUserDependencies(ctx, input.ApplicationStandardID)
	if removeAllDependenciesErr != nil {
		return nil, removeAllDependenciesErr
	}

	removeInput := entities.ApplicationStandardID{
		ID:            input.ID,
		ApplicationID: input.ApplicationID,
	}
	user, err := u.storage.Remove(ctx, removeInput)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.NotFoundFromErr(err).WithMessage("user [%s] not found", input.ID)
		}
		return nil, errors.InternalFromErr(err)
	}

	return &DeleteUserOutput{
		User: *user,
	}, nil
}

func (u *DefaultUserUseCase) EnableAccounts(ctx context.Context, input EnableAccountsInput) (*EnableAccountsOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}
	if len(input.Addresses) == 0 {
		return nil, errors.InvalidArgument().SetHumanReadableMessage("at least one address is required")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("user", input.UserID)
	tracer.AddProperty("application", input.ApplicationID)
	tracer.AddProperty("addresses", input.Addresses)
	tracer.Debug("enabling accounts of user")

	getUserInput := entities.ApplicationStandardID{
		ID:            input.UserID,
		ApplicationID: input.ApplicationID,
	}
	user, err := u.storage.Get(ctx, getUserInput)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.NotFoundFromErr(err).SetHumanReadableMessage("could not find user [%s] on application [%s]", input.UserID, input.ApplicationID)
		}
		return nil, errors.InternalFromErr(err)
	}

	byApplicationInput := hsmconnection.ByApplicationInput{
		ApplicationID: input.ApplicationID,
	}

	hsmConnection, byApplicationErr := u.hsmConnectionResolver.ByApplication(ctx, byApplicationInput)
	if byApplicationErr != nil {
		return nil, byApplicationErr
	}

	// Accounts must be backed by a key in the HSM module; validate the requested addresses against the
	// set of addresses the module actually holds before creating any account.
	knownAddresses, knownAddressesErr := u.addressesBackedByModule(ctx, hsmConnection)
	if knownAddressesErr != nil {
		return nil, knownAddressesErr
	}
	if !areAddressesValid(knownAddresses, input.Addresses) {
		msg := fmt.Sprintf("one or more accounts '%s' do not exist in the HSM", input.Addresses)
		return nil, errors.PreconditionFailed().WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
	}

	accountsToCreate := make([]CreateAccountInput, len(input.Addresses))
	for i, addr := range input.Addresses {
		a := CreateAccountInput{
			AccountID: AccountID{
				Address:       addr,
				UserID:        input.UserID,
				ApplicationID: input.ApplicationID,
			},
		}
		accountsToCreate[i] = a
	}

	var accountsNotAdded = make([]string, 0)
	for _, createAccountInput := range accountsToCreate {
		_, createAccountErr := u.CreateAccount(ctx, createAccountInput)
		if createAccountErr != nil && !errors.IsAlreadyExists(createAccountErr) {
			accountsNotAdded = append(accountsNotAdded, createAccountInput.Address.String())
			continue
		}
	}

	if len(accountsNotAdded) > 0 {
		formattedAddresses := fmt.Sprintf("[%s]", strings.Join(accountsNotAdded, ", "))
		return nil, errors.Internal().WithMessage("error while adding accounts to the user. The following accounts were not added: %s", formattedAddresses)
	}

	listAccountsInput := ListAccountsInput{
		ApplicationID: input.ApplicationID,
		UserID:        &input.UserID,
	}
	userAccounts, err := u.ListAccounts(ctx, listAccountsInput)
	if err != nil {
		return nil, errors.InternalFromErr(err)
	}

	user.Accounts = userAccounts.Items
	return &EnableAccountsOutput{
		User: *user,
	}, nil
}

// addressesBackedByModule returns the addresses that have a backing key in the HSM module of the given
// connection, resolved according to the module kind: SoftHSM does a live query of the manager, while LKV
// and AKV trust the persisted slot configuration as the source of truth (so a KeyPublicAddress mistyped
// at slot creation is taken at face value). EnableAccounts validates requested accounts against this set
// so an account cannot be created for an address with no key behind it.
func (u *DefaultUserUseCase) addressesBackedByModule(ctx context.Context, hsmConnection *hsmconnection.HSMConnection) ([]address.Address, error) {
	switch hsmConnection.ModuleKind {
	case hsmconnector.SoftHSMModuleKind:
		listAddressesInput := hsmconnector.ListAddressesInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       hsmConnection.Slot.Slot,
				Pin:        hsmConnection.Slot.Pin,
				ModuleKind: hsmConnection.ModuleKind,
			},
		}
		listAddressesOutput, err := u.hsmConnector.ListAddresses(ctx, listAddressesInput)
		if err != nil {
			return nil, errors.InternalFromErr(err)
		}
		return listAddressesOutput.Items, nil
	case hsmconnector.LKVModuleKind:
		listLocalKeysInput := hsmslot.ListLocalKeysInput{
			StandardID: entities.StandardID{
				ID: hsmConnection.Slot.ID,
			},
		}
		listAddressesOutput, err := u.slotUseCase.ListLocalKeys(ctx, listLocalKeysInput)
		if err != nil {
			return nil, errors.InternalFromErr(err)
		}
		return listAddressesOutput.Addresses, nil
	case hsmconnector.AKVModuleKind:
		// AKV addresses are the public addresses of the keys configured for the slot.
		akvAddresses := make([]address.Address, 0, len(hsmConnection.Slot.Config.AKV))
		for _, akvConfig := range hsmConnection.Slot.Config.AKV {
			addr, err := address.NewFromHexString(akvConfig.KeyPublicAddress)
			if err != nil {
				return nil, errors.InternalFromErr(err)
			}
			akvAddresses = append(akvAddresses, addr)
		}
		return akvAddresses, nil
	default:
		return nil, errors.Internal().WithMessage("unsupported HSM module kind '%s'", hsmConnection.ModuleKind)
	}
}

func (u *DefaultUserUseCase) DisableAccount(ctx context.Context, input DisableAccountInput) (*DisableAccountOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("user", input.UserID)
	tracer.AddProperty("application", input.ApplicationID)
	tracer.AddProperty("address", input.Address.String())
	tracer.Debug("disabling account of user")

	deleteAccountInput := DeleteAccountInput{
		AccountID: AccountID{
			Address:       input.Address,
			UserID:        input.UserID,
			ApplicationID: input.ApplicationID,
		},
	}
	_, err = u.DeleteAccount(ctx, deleteAccountInput)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.NotFoundFromErr(err).SetHumanReadableMessage("account [%s] not found for user [%s]", input.Address, input.UserID)
		}
		return nil, errors.InternalFromErr(err)
	}

	getUserInput := entities.ApplicationStandardID{
		ID:            input.UserID,
		ApplicationID: input.ApplicationID,
	}
	user, err := u.storage.Get(ctx, getUserInput)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.NotFoundFromErr(err).SetHumanReadableMessage("could not find user [%s] on application [%s]", input.UserID, input.ApplicationID)
		}
		return nil, errors.InternalFromErr(err)
	}

	listAccountsInput := ListAccountsInput{
		ApplicationID: input.ApplicationID,
		UserID:        &input.UserID,
	}
	userAccounts, err := u.ListAccounts(ctx, listAccountsInput)
	if err != nil {
		return nil, errors.InternalFromErr(err)
	}

	user.Accounts = userAccounts.Items
	return &DisableAccountOutput{
		User: *user,
	}, nil
}

func areAddressesValid(items []address.Address, addresses []address.Address) bool {
	for _, addr := range addresses {
		if !containsAddress(items, addr) {
			return false
		}
	}
	return true
}

func containsAddress(items []address.Address, address address.Address) bool {
	for _, item := range items {
		if item == address {
			return true
		}
	}
	return false
}

var _ UserUseCase = new(DefaultUserUseCase)

// DefaultUserUseCase default management of User in configuration implementation.
type DefaultUserUseCase struct {
	// storage is the persistence adapter of the User.
	storage UserStorage
	// accountStorage is the persistence adapter of the Account.
	accountStorage AccountStorage

	// applicationUseCase defines how to interact with Application resources.
	applicationUseCase application.ApplicationUseCase
	// hsmConnectionResolver finds what HSMConnection is required depending on the constraints.
	hsmConnectionResolver hsmconnection.Resolver
	// hsmConnector connects with the HSM and operates with it.
	hsmConnector hsmconnector.HSMConnector
	// referentialIntegrityUseCase to manage dependencies between resources.
	referentialIntegrityUseCase referentialintegrity.ReferentialIntegrityUseCase
	// slotUseCase defines how to interact with Slot resources.
	slotUseCase hsmslot.HSMSlotUseCase
	// roleUseCase defines how to interact with Role resources.
	roleUseCase role.RoleUseCase
}

// DefaultUserUseCaseOptions configures a DefaultUserUseCase.
type DefaultUserUseCaseOptions struct {
	// Storage is the persistence adapter of the User.
	Storage UserStorage
	// AccountStorage is the persistence adapter of the Account.
	AccountStorage AccountStorage

	// ApplicationUseCase defines how to interact with Application resources.
	ApplicationUseCase application.ApplicationUseCase
	// HSMConnectionResolver finds what HSMConnection is required depending on the constraints.
	HSMConnectionResolver hsmconnection.Resolver
	// HSMConnector connects with the HSM and operates with it.
	HSMConnector hsmconnector.HSMConnector
	// ReferentialIntegrityUseCase to manage dependencies between resources.
	ReferentialIntegrityUseCase referentialintegrity.ReferentialIntegrityUseCase
	// SlotUseCase defines how to interact with Slot resources.
	SlotUseCase hsmslot.HSMSlotUseCase
	// RoleUseCase defines how to interact with Role resources.
	RoleUseCase role.RoleUseCase
}

// ProvideDefaultUseCase creates a DefaultUserUseCase with the given options.
func ProvideDefaultUseCase(options DefaultUserUseCaseOptions) (*DefaultUserUseCase, error) {
	if options.Storage == nil {
		return nil, errors.Internal().WithMessage("mandatory 'Storage' was not provided")
	}
	if options.AccountStorage == nil {
		return nil, errors.Internal().WithMessage("mandatory 'AccountStorage' was not provided")
	}
	if options.ApplicationUseCase == nil {
		return nil, errors.Internal().WithMessage("mandatory 'ApplicationUseCase' was not provided")
	}
	if options.HSMConnectionResolver == nil {
		return nil, errors.Internal().WithMessage("mandatory 'Resolver' was not provided")
	}
	if options.HSMConnector == nil {
		return nil, errors.Internal().WithMessage("mandatory 'HSMConnector' was not provided")
	}
	if options.ReferentialIntegrityUseCase == nil {
		return nil, errors.Internal().WithMessage("mandatory 'ReferentialIntegrityUseCase' was not provided")
	}
	if options.SlotUseCase == nil {
		return nil, errors.Internal().WithMessage("mandatory 'SlotUseCase' was not provided")
	}
	if options.RoleUseCase == nil {
		return nil, errors.Internal().WithMessage("mandatory 'RoleUseCase' was not provided")
	}
	return &DefaultUserUseCase{
		storage:                     options.Storage,
		applicationUseCase:          options.ApplicationUseCase,
		accountStorage:              options.AccountStorage,
		slotUseCase:                 options.SlotUseCase,
		roleUseCase:                 options.RoleUseCase,
		hsmConnector:                options.HSMConnector,
		hsmConnectionResolver:       options.HSMConnectionResolver,
		referentialIntegrityUseCase: options.ReferentialIntegrityUseCase,
	}, nil
}
