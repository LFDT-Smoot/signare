package application

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/referentialintegrity"
)

// stubReferentialIntegrity drives the cleanup path: no children, configurable delete error.
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

type stubApplicationStorage struct {
	ApplicationStorage
	application *Application
}

func (s *stubApplicationStorage) Get(_ context.Context, _ entities.StandardID) (*Application, error) {
	return s.application, nil
}

func newUseCaseWithStubs(ri referentialintegrity.ReferentialIntegrityUseCase) *DefaultUseCase {
	stored := &Application{}
	stored.ID = "application-1"
	stored.InternalResourceID = "internal-application-1"
	return &DefaultUseCase{
		storage:                     &stubApplicationStorage{application: stored},
		referentialIntegrityUseCase: ri,
	}
}

// TestRemoveAllDependencies_DeleteFailurePropagates is the DB-3 regression guard: a
// DeleteMyEntriesIfAny failure must surface rather than be swallowed.
func TestRemoveAllDependencies_DeleteFailurePropagates(t *testing.T) {
	deleteErr := stderrors.New("referential integrity cleanup failed")
	ri := &stubReferentialIntegrity{deleteErr: deleteErr}
	u := newUseCaseWithStubs(ri)

	err := u.removeAllDependencies(context.Background(), entities.StandardID{ID: "application-1"})

	require.ErrorIs(t, err, deleteErr)
	require.Equal(t, 1, ri.deleteCalls)
}

func TestRemoveAllDependencies_DeleteSuccess(t *testing.T) {
	ri := &stubReferentialIntegrity{}
	u := newUseCaseWithStubs(ri)

	err := u.removeAllDependencies(context.Background(), entities.StandardID{ID: "application-1"})

	require.NoError(t, err)
	require.Equal(t, 1, ri.deleteCalls)
}
