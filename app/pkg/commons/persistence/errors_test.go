package persistence_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger-labs/signare/app/pkg/commons/persistence"
)

func TestError_IsError(t *testing.T) {
	err := persistence.NewConfigCanNotBeLoadedError()
	require.True(t, persistence.IsConfigCanNotBeLoaded(err))

	err = persistence.NewStatementCouldNotBePreparedError()
	require.True(t, persistence.IsStatementCouldNotBePrepared(err))

	err = persistence.NewStatementExecutionFailedError()
	require.True(t, persistence.IsStatementExecutionFailed(err))

	err = persistence.NewDBResponseCanNotBeProcessedError()
	require.True(t, persistence.IsDBResponseCouldNotBeProcessed(err))

	err = persistence.NewCanNotBeginTransactionError()
	require.True(t, persistence.IsCanNotBeginTransaction(err))

	err = persistence.NewCanNotRollbackTransactionError()
	require.True(t, persistence.IsCanNotRollbackTransaction(err))

	err = persistence.NewCanNotCommitTransactionError()
	require.True(t, persistence.IsCanNotCommitTransaction(err))

	err = persistence.NewAlreadyExistsError()
	require.True(t, persistence.IsAlreadyExists(err))

	err = persistence.NewTxNotInContextError()
	require.True(t, persistence.IsTxNotInContext(err))
}

func TestError_Description(t *testing.T) {
	t.Run("empty description", func(t *testing.T) {
		expectedError := "configuration can not be loaded"

		err := persistence.NewConfigCanNotBeLoadedError()
		require.Equal(t, expectedError, err.Error())
	})

	t.Run("with description", func(t *testing.T) {
		expectedDescription := "test description"
		expectedError := "configuration can not be loaded: " + expectedDescription

		err := persistence.NewConfigCanNotBeLoadedError().WithMessage(expectedDescription)
		require.Equal(t, expectedError, err.Error())
	})

}
