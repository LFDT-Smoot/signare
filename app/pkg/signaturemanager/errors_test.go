package signaturemanager_test

import (
	"fmt"
	"sync"
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

// Regression guard for a cross-request information leak: a shared Error must survive a derivation
// unchanged, so one request cannot observe another's error text.
func TestWithMessage_DoesNotMutateReceiver(t *testing.T) {
	shared := signaturemanager.NewPinIncorrectError()
	original := shared.Error()

	derived := shared.WithMessage("slot 7 detail that must not escape")

	require.NotSame(t, shared, derived, "WithMessage must return a new value, not the receiver")
	require.Equal(t, original, shared.Error(), "the shared instance must be unchanged")
	require.Contains(t, derived.Error(), "slot 7 detail that must not escape")
}

// Copies must keep their sentinel, so errors.Is/As classification still works. Without this a
// non-mutating WithMessage could silently break every Is*Error helper.
func TestWithMessage_CopyPreservesClassification(t *testing.T) {
	derived := signaturemanager.NewPinIncorrectError().WithMessage("some detail")
	require.True(t, signaturemanager.IsPinIncorrectError(derived))
	require.False(t, signaturemanager.IsInvalidSlotError(derived))

	slotErr := signaturemanager.NewInvalidSlotError().WithMessage("other detail")
	require.True(t, signaturemanager.IsInvalidSlotError(slotErr))
	require.False(t, signaturemanager.IsPinIncorrectError(slotErr))
}

// Two derivations from the same shared instance must not observe each other.
func TestWithMessage_DerivationsAreIndependent(t *testing.T) {
	shared := signaturemanager.NewAlreadyInitializedError()

	first := shared.WithMessage("first request")
	second := shared.WithMessage("second request")

	require.Contains(t, first.Error(), "first request")
	require.NotContains(t, first.Error(), "second request")
	require.Contains(t, second.Error(), "second request")
}

// Deriving from a shared instance while another goroutine reads it must be race-free. The
// assertions above catch the same bug deterministically; this is the guard that -race can fail.
func TestWithMessage_ConcurrentDerivationsAreRaceFree(t *testing.T) {
	shared := signaturemanager.NewInvalidSlotError()

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = shared.WithMessage(fmt.Sprintf("request %d", i)).Error()
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = shared.Error()
		}
	}()
	wg.Wait()

	require.Equal(t, "invalid slot", shared.Error())
}
