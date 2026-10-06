package user_test

import (
	"context"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnection"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmslot"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/user"

	"github.com/stretchr/testify/require"
)

type localKeyVaultResolver struct{}

func (localKeyVaultResolver) ByApplication(context.Context, hsmconnection.ByApplicationInput) (*hsmconnection.HSMConnection, error) {
	return &hsmconnection.HSMConnection{ModuleKind: hsmconnector.LKVModuleKind}, nil
}

// failingRemoveSlotUseCase fails RemoveLocalKey with err; anything else panics through the nil interface.
type failingRemoveSlotUseCase struct {
	hsmslot.HSMSlotUseCase
	err error
}

func (f failingRemoveSlotUseCase) RemoveLocalKey(context.Context, hsmslot.RemoveLocalKeyInput) error {
	return f.err
}

// TestDeleteAllAccountsForAddress_KeepsTheRemovalErrorClass checks that a failed key removal keeps the
// class a caller can act on. A precondition failure, such as a refused PIN or a Local Key Vault store
// still changing after its retries, used to be flattened into an internal error.
func TestDeleteAllAccountsForAddress_KeepsTheRemovalErrorClass(t *testing.T) {
	tests := map[string]struct {
		removeErr error
		is        func(error) bool
	}{
		"precondition failed": {errors.PreconditionFailed().WithMessage("slot modified concurrently"), errors.IsPreconditionFailed},
		"not found":           {errors.NotFound().WithMessage("address not in slot"), errors.IsNotFound},
		"anything else":       {errors.Internal().WithMessage("storage down"), errors.IsInternal},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			useCase, err := user.ProvideDefaultUseCase(user.DefaultUserUseCaseOptions{
				Storage:                     struct{ user.UserStorage }{},
				AccountStorage:              struct{ user.AccountStorage }{},
				ApplicationUseCase:          app.ApplicationUseCase,
				HSMConnectionResolver:       localKeyVaultResolver{},
				HSMConnector:                app.HSMConnector,
				ReferentialIntegrityUseCase: app.ReferentialIntegrityUseCase,
				SlotUseCase:                 failingRemoveSlotUseCase{err: tt.removeErr},
				RoleUseCase:                 app.RoleUseCase,
			})
			require.NoError(t, err)

			out, err := useCase.DeleteAllAccountsForAddress(ctx, user.DeleteAllAccountsForAddressInput{
				Address:       address.MustNewFromHexString("0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"),
				ApplicationID: "app",
			})
			require.Nil(t, out)
			require.True(t, tt.is(err), "got %v", err)
		})
	}
}
