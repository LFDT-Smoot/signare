package hsmconnector

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	signererrors "github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
)

// TestManagerError pins the error class key generation and every signing method return, in particular
// that a key policy refusal is a precondition failure and an unreachable key store a bad gateway.
func TestManagerError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want func(error) bool
	}{
		{"policy refusal is a precondition failure", signaturemanager.NewPolicyRefusedError().WithMessage("refused"), signererrors.IsPreconditionFailed},
		{"wrong pin is a precondition failure", signaturemanager.NewPinIncorrectError(), signererrors.IsPreconditionFailed},
		{"unreachable slot is a bad gateway", signaturemanager.NewInvalidSlotError(), signererrors.IsBadGateway},
		{"unreadable key store is a bad gateway", signaturemanager.NewUnavailableError().WithMessage("403"), signererrors.IsBadGateway},
		{"anything else is internal", signaturemanager.NewInternalError().WithMessage("boom"), signererrors.IsInternal},
		{"a plain error is internal", errors.New("boom"), signererrors.IsInternal},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := managerError(c.err, "1")
			require.Error(t, got)
			require.True(t, c.want(got), got.Error())
		})
	}
	t.Run("the policy message reaches the caller", func(t *testing.T) {
		got := managerError(signaturemanager.NewPolicyRefusedError().WithMessage("this deployment accepts HSM-held keys only"), "1")
		require.Contains(t, got.Error(), "HSM-held keys only")
	})
}
