package pkcs11hsm_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/commons/logger"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager/pkcs11hsm"
	"github.com/lfdt-smoot/signare/app/test/signaturemanagertesthelper"
)

// TestGenerateKeyReadsBackTheProtectionAttributes runs key generation against SoftHSM, whose own
// default for CKA_SENSITIVE is false. Without the protection attributes in the template the generated
// key is readable, so the read-back must refuse it and leave nothing behind. With them, it must succeed.
func TestGenerateKeyReadsBackTheProtectionAttributes(t *testing.T) {
	slotID, _, err := signaturemanagertesthelper.InitializeSoftHSMSlot()
	require.NoError(t, err)
	p := pkcs11.New(signaturemanagertesthelper.SoftHSMLib)
	require.NotNil(t, p)
	require.NoError(t, p.Initialize())
	t.Cleanup(func() { _ = p.Finalize() })

	countObjects := func() int {
		t.Helper()
		slot, parseErr := strconv.ParseUint(*slotID, 10, 32)
		require.NoError(t, parseErr)
		session, openErr := p.OpenSession(uint(slot), pkcs11.CKF_SERIAL_SESSION)
		require.NoError(t, openErr)
		defer func() { _ = p.CloseSession(session) }()
		require.NoError(t, p.Login(session, pkcs11.CKU_USER, signaturemanagertesthelper.SlotPin))
		defer func() { _ = p.Logout(session) }()
		require.NoError(t, p.FindObjectsInit(session, nil))
		objects, _, findErr := p.FindObjects(session, 1000)
		require.NoError(t, findErr)
		require.NoError(t, p.FindObjectsFinal(session))
		return len(objects)
	}
	generate := func(sm *pkcs11hsm.PKCS11HSMSignatureManager) error {
		ctx := context.Background()
		_, genErr := sm.GenerateKey(ctx, signaturemanager.GenerateKeyInput{
			Slot:   *slotID,
			Pin:    signaturemanagertesthelper.SlotPin,
			Tracer: logger.NewTracer(ctx),
		})
		return genErr
	}

	t.Run("a key the token leaves readable is refused and removed", func(t *testing.T) {
		sm, provideErr := pkcs11hsm.ProvidePKCS11HSMSignatureManager(pkcs11hsm.PKCS11HSMSignatureManagerOptions{PkcsContext: p})
		require.NoError(t, provideErr)
		pkcs11hsm.IgnoreKeyProtection(sm)
		before := countObjects()

		genErr := generate(sm)
		require.Error(t, genErr)
		require.True(t, signaturemanager.IsPolicyRefusedError(genErr), "got %v", genErr)
		require.Contains(t, genErr.Error(), "CKA_SENSITIVE false")
		require.Equal(t, before, countObjects(), "the refused key pair must not stay on the token")
	})

	t.Run("a protected key is generated and kept", func(t *testing.T) {
		sm, provideErr := pkcs11hsm.ProvidePKCS11HSMSignatureManager(pkcs11hsm.PKCS11HSMSignatureManagerOptions{PkcsContext: p})
		require.NoError(t, provideErr)
		before := countObjects()

		require.NoError(t, generate(sm))
		require.Equal(t, before+2, countObjects(), "one public and one private key object")
	})
}
