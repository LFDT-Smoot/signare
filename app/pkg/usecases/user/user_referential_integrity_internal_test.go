package user

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/referentialintegrity"
)

// stubReferentialIntegrity is a minimal ReferentialIntegrityUseCase used to drive the
// removeAll*Dependencies cleanup paths. ListMyChildrenEntries returns no children so the
// "has dependents" guard is skipped; DeleteMyEntriesIfAny returns the configured error.
type stubReferentialIntegrity struct {
	referentialintegrity.ReferentialIntegrityUseCase
	deleteErr   error
	deleteCalls int
}

func (s *stubReferentialIntegrity) ListMyChildrenEntries(_ context.Context, _ referentialintegrity.ListMyChildrenEntriesInput) (*referentialintegrity.ListMyChildrenEntriesOutput, error) {
	return &referentialintegrity.ListMyChildrenEntriesOutput{}, nil
}

func (s *stubReferentialIntegrity) DeleteMyEntriesIfAny(_ context.Context, _ referentialintegrity.DeleteMyEntriesIfAnyInput) error {
	s.deleteCalls++
	return s.deleteErr
}

// stubUserStorage returns a fixed User from Get; other methods are unused.
type stubUserStorage struct {
	UserStorage
	user *User
}

func (s *stubUserStorage) Get(_ context.Context, _ entities.ApplicationStandardID) (*User, error) {
	return s.user, nil
}

// stubAccountStorage satisfies the account lookups that GetUser performs via ListAccounts.
type stubAccountStorage struct {
	AccountStorage
}

func (s *stubAccountStorage) Filter(_ string) AccountFilters { return stubAccountFilters{} }

func (s *stubAccountStorage) All(_ context.Context, _ AccountFilters) (*AccountCollection, error) {
	return &AccountCollection{}, nil
}

type stubAccountFilters struct{}

func (f stubAccountFilters) FilterByUserID(_ string) AccountFilters  { return f }
func (f stubAccountFilters) FilterByAddress(_ string) AccountFilters { return f }

func newUserUseCaseWithStubs(ri referentialintegrity.ReferentialIntegrityUseCase) *DefaultUserUseCase {
	storedUser := &User{}
	storedUser.ID = "user-1"
	storedUser.ApplicationID = "app-1"
	storedUser.InternalResourceID = "internal-user-1"
	return &DefaultUserUseCase{
		storage:                     &stubUserStorage{user: storedUser},
		accountStorage:              &stubAccountStorage{},
		referentialIntegrityUseCase: ri,
	}
}

// TestRemoveAllUserDependencies_DeleteFailurePropagates is the regression guard for DB-3:
// a DeleteMyEntriesIfAny failure must surface, not be swallowed (which previously let the
// user be deleted while stale referential-integrity rows survived).
func TestRemoveAllUserDependencies_DeleteFailurePropagates(t *testing.T) {
	deleteErr := stderrors.New("referential integrity cleanup failed")
	ri := &stubReferentialIntegrity{deleteErr: deleteErr}
	u := newUserUseCaseWithStubs(ri)

	err := u.removeAllUserDependencies(context.Background(), entities.ApplicationStandardID{ID: "user-1", ApplicationID: "app-1"})

	require.ErrorIs(t, err, deleteErr)
	require.Equal(t, 1, ri.deleteCalls)
}

func TestRemoveAllUserDependencies_DeleteSuccess(t *testing.T) {
	ri := &stubReferentialIntegrity{}
	u := newUserUseCaseWithStubs(ri)

	err := u.removeAllUserDependencies(context.Background(), entities.ApplicationStandardID{ID: "user-1", ApplicationID: "app-1"})

	require.NoError(t, err)
	require.Equal(t, 1, ri.deleteCalls)
}
