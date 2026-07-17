package signaturemanager_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
)

func TestError_IsError(t *testing.T) {
	var err error
	err = signaturemanager.NewNotImplementedError()
	require.True(t, signaturemanager.IsNotImplementedError(err))

	err = signaturemanager.NewLibFailedError()
	require.True(t, signaturemanager.IsLibFailedError(err))

	err = signaturemanager.NewInvalidSlotError()
	require.True(t, signaturemanager.IsInvalidSlotError(err))

	err = signaturemanager.NewKeyGenerationError()
	require.True(t, signaturemanager.IsKeyGenerationError(err))

	err = signaturemanager.NewInternalError()
	require.True(t, signaturemanager.IsInternalError(err))

	err = signaturemanager.NewNotFoundError()
	require.True(t, signaturemanager.IsNotFoundError(err))

	err = signaturemanager.NewInvalidArgumentError()
	require.True(t, signaturemanager.IsInvalidArgumentError(err))
}

func TestError_Description(t *testing.T) {
	t.Run("empty description", func(t *testing.T) {
		expectedError := "key generation failed"

		err := signaturemanager.NewKeyGenerationError()
		require.Contains(t, err.Error(), expectedError)
	})

	t.Run("with description", func(t *testing.T) {
		expectedDescription := "test description"
		expectedError := "key generation failed: " + expectedDescription

		err := signaturemanager.NewKeyGenerationError().WithMessage(expectedDescription)
		require.Contains(t, err.Error(), expectedError)
	})

}
