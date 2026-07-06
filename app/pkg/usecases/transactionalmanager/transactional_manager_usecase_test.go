package transactionalmanager_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hyperledger-labs/signare/app/pkg/usecases/transactionalmanager"

	"github.com/stretchr/testify/require"
)

var errBoom = errors.New("boom")

// fakeTxKeyType is the context key under which fakeTransactionalStorage carries its sentinel transaction.
type fakeTxKeyType struct{}

var fakeTxKey = fakeTxKeyType{}

// fakeTransactionalStorage is an in-memory TransactionalStorage that records lifecycle calls and can be
// configured to fail commits, so the manager can be exercised without a real database.
type fakeTransactionalStorage struct {
	failCommit    bool
	beginCount    int
	commitCount   int
	rollbackCount int
}

func (f *fakeTransactionalStorage) BeginTransaction(ctx context.Context) (context.Context, error) {
	f.beginCount++
	return context.WithValue(ctx, fakeTxKey, "tx"), nil
}

func (f *fakeTransactionalStorage) RollbackTransaction(_ context.Context) error {
	f.rollbackCount++
	return nil
}

func (f *fakeTransactionalStorage) CommitTransaction(_ context.Context) error {
	if f.failCommit {
		return errors.New("commit failed")
	}
	f.commitCount++
	return nil
}

func (f *fakeTransactionalStorage) GetTransaction(ctx context.Context) (any, error) {
	tx := ctx.Value(fakeTxKey)
	if tx == nil {
		return nil, errors.New("no transaction in context")
	}
	return tx, nil
}

func newManager(storage transactionalmanager.TransactionalStorage) *transactionalmanager.TransactionalManager {
	return transactionalmanager.ProvideTransactionalManager(transactionalmanager.TransactionalManagerOptions{
		TransactionalStorage: storage,
	})
}

func TestExecuteInTransaction_RunsCallbackAfterCommit(t *testing.T) {
	storage := &fakeTransactionalStorage{}
	manager := newManager(storage)

	executed := false
	_, err := manager.ExecuteInTransaction(context.Background(), func(ctx context.Context) (any, error) {
		require.True(t, manager.RegisterAfterCommitIfTransactionInProgress(ctx, func(context.Context) error {
			executed = true
			return nil
		}))
		return nil, nil
	})

	require.NoError(t, err)
	require.True(t, executed, "callback must run after a successful commit")
	require.Equal(t, 1, storage.commitCount)
	require.Equal(t, 0, storage.rollbackCount)
}

func TestExecuteInTransaction_DoesNotRunCallbackOnFunctionError(t *testing.T) {
	storage := &fakeTransactionalStorage{}
	manager := newManager(storage)

	executed := false
	_, err := manager.ExecuteInTransaction(context.Background(), func(ctx context.Context) (any, error) {
		require.True(t, manager.RegisterAfterCommitIfTransactionInProgress(ctx, func(context.Context) error {
			executed = true
			return nil
		}))
		return nil, errBoom
	})

	require.ErrorIs(t, err, errBoom)
	require.False(t, executed, "callback must not run when the transaction is rolled back")
	require.Equal(t, 1, storage.rollbackCount)
	require.Equal(t, 0, storage.commitCount)
}

func TestExecuteInTransaction_DoesNotRunCallbackOnCommitFailure(t *testing.T) {
	storage := &fakeTransactionalStorage{failCommit: true}
	manager := newManager(storage)

	executed := false
	_, err := manager.ExecuteInTransaction(context.Background(), func(ctx context.Context) (any, error) {
		require.True(t, manager.RegisterAfterCommitIfTransactionInProgress(ctx, func(context.Context) error {
			executed = true
			return nil
		}))
		return nil, nil
	})

	require.Error(t, err)
	require.False(t, executed, "callback must not run when the commit fails")
}

func TestExecuteInTransaction_DoesNotRunCallbackOnPanic(t *testing.T) {
	storage := &fakeTransactionalStorage{}
	manager := newManager(storage)

	executed := false
	_, err := manager.ExecuteInTransaction(context.Background(), func(ctx context.Context) (any, error) {
		require.True(t, manager.RegisterAfterCommitIfTransactionInProgress(ctx, func(context.Context) error {
			executed = true
			return nil
		}))
		panic("boom")
	})

	require.Error(t, err, "a recovered panic must surface as a failure")
	require.False(t, executed, "callback must not run when the transaction panics")
	require.Equal(t, 1, storage.rollbackCount)
	require.Equal(t, 0, storage.commitCount)
}

// TestExecuteInTransaction_RolledBackCallbackIsNotReplayed proves callbacks are not retained beyond their
// transaction's context: a callback registered in a rolled-back transaction is never executed by a later,
// unrelated transaction (the leak the fix removes).
func TestExecuteInTransaction_RolledBackCallbackIsNotReplayed(t *testing.T) {
	storage := &fakeTransactionalStorage{}
	manager := newManager(storage)

	executed := 0
	callback := func(context.Context) error {
		executed++
		return nil
	}

	_, err := manager.ExecuteInTransaction(context.Background(), func(ctx context.Context) (any, error) {
		require.True(t, manager.RegisterAfterCommitIfTransactionInProgress(ctx, callback))
		return nil, errBoom
	})
	require.ErrorIs(t, err, errBoom)
	require.Zero(t, executed)

	_, err = manager.ExecuteInTransaction(context.Background(), func(context.Context) (any, error) {
		return nil, nil
	})
	require.NoError(t, err)
	require.Zero(t, executed, "a rolled-back transaction's callback must not be replayed later")
}

func TestExecuteInTransaction_NestedRunsCallbacksOnceOnOuterCommit(t *testing.T) {
	storage := &fakeTransactionalStorage{}
	manager := newManager(storage)

	executions := 0
	callback := func(context.Context) error {
		executions++
		return nil
	}

	_, err := manager.ExecuteInTransaction(context.Background(), func(outerCtx context.Context) (any, error) {
		require.True(t, manager.RegisterAfterCommitIfTransactionInProgress(outerCtx, callback))

		_, innerErr := manager.ExecuteInTransaction(outerCtx, func(innerCtx context.Context) (any, error) {
			require.True(t, manager.RegisterAfterCommitIfTransactionInProgress(innerCtx, callback))
			return nil, nil
		})
		require.NoError(t, innerErr)
		return nil, nil
	})

	require.NoError(t, err)
	require.Equal(t, 2, executions, "both registered callbacks must run exactly once on the outer commit")
	require.Equal(t, 1, storage.beginCount, "only the outermost transaction begins")
	require.Equal(t, 1, storage.commitCount, "only the outermost transaction commits")
	require.Equal(t, 0, storage.rollbackCount)
}

func TestExecuteInTransaction_NestedInnerErrorRollsBackOuterAndSkipsCallback(t *testing.T) {
	storage := &fakeTransactionalStorage{}
	manager := newManager(storage)

	executed := false
	_, err := manager.ExecuteInTransaction(context.Background(), func(outerCtx context.Context) (any, error) {
		_, innerErr := manager.ExecuteInTransaction(outerCtx, func(innerCtx context.Context) (any, error) {
			require.True(t, manager.RegisterAfterCommitIfTransactionInProgress(innerCtx, func(context.Context) error {
				executed = true
				return nil
			}))
			return nil, errBoom
		})
		require.ErrorIs(t, innerErr, errBoom)
		// the outermost call owns commit/rollback: propagate so it rolls the whole transaction back
		return nil, innerErr
	})

	require.ErrorIs(t, err, errBoom)
	require.False(t, executed, "a callback registered in a nested transaction must not run when the outer rolls back")
	require.Equal(t, 1, storage.beginCount, "only the outermost transaction begins")
	require.Equal(t, 1, storage.rollbackCount, "only the outermost transaction rolls back")
	require.Equal(t, 0, storage.commitCount)
}

func TestExecuteInTransaction_CallbackErrorIsReturned(t *testing.T) {
	storage := &fakeTransactionalStorage{}
	manager := newManager(storage)

	_, err := manager.ExecuteInTransaction(context.Background(), func(ctx context.Context) (any, error) {
		require.True(t, manager.RegisterAfterCommitIfTransactionInProgress(ctx, func(context.Context) error {
			return errBoom
		}))
		return nil, nil
	})

	require.ErrorIs(t, err, errBoom, "a failing after-commit callback must surface its error")
	require.Equal(t, 1, storage.commitCount)
}

func TestRegisterAfterCommitIfTransactionInProgress_FalseWithoutTransaction(t *testing.T) {
	manager := newManager(&fakeTransactionalStorage{})

	registered := manager.RegisterAfterCommitIfTransactionInProgress(context.Background(), func(context.Context) error {
		return nil
	})

	require.False(t, registered, "no callback can be registered when no transaction is in progress")
}
