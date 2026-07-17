package hsmmodule

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

type stubHSMModuleStorage struct {
	HSMModuleStorage
	hsmModule    *HSMModule
	removeCalled bool
}

func (s *stubHSMModuleStorage) Get(_ context.Context, _ entities.StandardID) (*HSMModule, error) {
	return s.hsmModule, nil
}

func (s *stubHSMModuleStorage) Remove(_ context.Context, _ entities.StandardID) (*HSMModule, error) {
	s.removeCalled = true
	return s.hsmModule, nil
}

func newUseCaseWithStubs(ri referentialintegrity.ReferentialIntegrityUseCase) *DefaultUseCase {
	stored := &HSMModule{}
	stored.ID = "hsm-module-1"
	stored.InternalResourceID = "internal-hsm-module-1"
	return &DefaultUseCase{
		hsmModuleStorage:            &stubHSMModuleStorage{hsmModule: stored},
		referentialIntegrityUseCase: ri,
	}
}

// TestRemoveAllDependencies_DeleteFailurePropagates is the DB-3 regression guard: a
// DeleteMyEntriesIfAny failure must surface rather than be swallowed.
func TestRemoveAllDependencies_DeleteFailurePropagates(t *testing.T) {
	deleteErr := stderrors.New("referential integrity cleanup failed")
	ri := &stubReferentialIntegrity{deleteErr: deleteErr}
	u := newUseCaseWithStubs(ri)

	err := u.removeAllDependencies(context.Background(), entities.StandardID{ID: "hsm-module-1"})

	require.ErrorIs(t, err, deleteErr)
	require.Equal(t, 1, ri.deleteCalls)
}

func TestRemoveAllDependencies_DeleteSuccess(t *testing.T) {
	ri := &stubReferentialIntegrity{}
	u := newUseCaseWithStubs(ri)

	err := u.removeAllDependencies(context.Background(), entities.StandardID{ID: "hsm-module-1"})

	require.NoError(t, err)
	require.Equal(t, 1, ri.deleteCalls)
}

// TestDeleteHSMModule_AbortsWhenCleanupFails is the end-to-end DB-3 guard: a referential-integrity
// cleanup failure must abort the whole delete, so storage.Remove is never reached. This pins the
// caller ordering (removeAllDependencies before storage.Remove) against future regression.
func TestDeleteHSMModule_AbortsWhenCleanupFails(t *testing.T) {
	deleteErr := stderrors.New("referential integrity cleanup failed")
	ri := &stubReferentialIntegrity{deleteErr: deleteErr}
	stored := &HSMModule{}
	stored.ID = "hsm-module-1"
	stored.InternalResourceID = "internal-hsm-module-1"
	storage := &stubHSMModuleStorage{hsmModule: stored}
	u := &DefaultUseCase{
		hsmModuleStorage:            storage,
		referentialIntegrityUseCase: ri,
	}

	_, err := u.DeleteHSMModule(context.Background(), DeleteHSMModuleInput{StandardID: entities.StandardID{ID: "hsm-module-1"}})

	require.ErrorIs(t, err, deleteErr)
	require.False(t, storage.removeCalled, "storage.Remove must not be called when referential-integrity cleanup fails")
}
