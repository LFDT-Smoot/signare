package hsmslot

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

type stubHSMSlotStorage struct {
	HSMSlotStorage
	hsmSlot *HSMSlot
}

func (s *stubHSMSlotStorage) Get(_ context.Context, _ entities.StandardID) (*HSMSlot, error) {
	return s.hsmSlot, nil
}

func newUseCaseWithStubs(ri referentialintegrity.ReferentialIntegrityUseCase) *DefaultUseCase {
	stored := &HSMSlot{}
	stored.ID = "hsm-slot-1"
	stored.InternalResourceID = "internal-hsm-slot-1"
	return &DefaultUseCase{
		hsmSlotStorage:              &stubHSMSlotStorage{hsmSlot: stored},
		referentialIntegrityUseCase: ri,
	}
}

// TestRemoveAllDependencies_DeleteFailurePropagates is the DB-3 regression guard: a
// DeleteMyEntriesIfAny failure must surface rather than be swallowed.
func TestRemoveAllDependencies_DeleteFailurePropagates(t *testing.T) {
	deleteErr := stderrors.New("referential integrity cleanup failed")
	ri := &stubReferentialIntegrity{deleteErr: deleteErr}
	u := newUseCaseWithStubs(ri)

	err := u.removeAllDependencies(context.Background(), entities.StandardID{ID: "hsm-slot-1"})

	require.ErrorIs(t, err, deleteErr)
	require.Equal(t, 1, ri.deleteCalls)
}

func TestRemoveAllDependencies_DeleteSuccess(t *testing.T) {
	ri := &stubReferentialIntegrity{}
	u := newUseCaseWithStubs(ri)

	err := u.removeAllDependencies(context.Background(), entities.StandardID{ID: "hsm-slot-1"})

	require.NoError(t, err)
	require.Equal(t, 1, ri.deleteCalls)
}
