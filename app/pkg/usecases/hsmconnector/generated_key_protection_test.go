package hsmconnector_test

import (
	"errors"
	"strconv"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/test/signaturemanagertesthelper"
)

// TestGeneratedKeyIsSensitiveAndNotExtractable reads the generated private key back over PKCS#11 and
// checks the two attributes signare now sets rather than leaving to the token: the value cannot be
// read out and the key cannot be wrapped out.
func TestGeneratedKeyIsSensitiveAndNotExtractable(t *testing.T) {
	generated, err := app.HSMConnector.GenerateAddress(ctx, hsmconnector.GenerateAddressInput{
		Slot:       slotID,
		PinSource:  slotPinSource,
		ModuleKind: hsmconnector.SoftHSMModuleKind,
	})
	require.NoError(t, err)

	// A second handle on the library the application already initialised. Never finalised: that would
	// close the application's sessions.
	p := pkcs11.New(signaturemanagertesthelper.SoftHSMLib)
	require.NotNil(t, p)
	if initErr := p.Initialize(); initErr != nil {
		var pkcsErr pkcs11.Error
		require.True(t, errors.As(initErr, &pkcsErr) && pkcsErr == pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED, initErr)
	}
	slot, err := strconv.ParseUint(slotID, 10, 32)
	require.NoError(t, err)
	session, err := p.OpenSession(uint(slot), pkcs11.CKF_SERIAL_SESSION)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.CloseSession(session) })
	if loginErr := p.Login(session, pkcs11.CKU_USER, signaturemanagertesthelper.SlotPin); loginErr != nil {
		var pkcsErr pkcs11.Error
		require.True(t, errors.As(loginErr, &pkcsErr) && pkcsErr == pkcs11.CKR_USER_ALREADY_LOGGED_IN, loginErr)
	}

	require.NoError(t, p.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, generated.Address.String()),
	}))
	handles, _, err := p.FindObjects(session, 2)
	require.NoError(t, err)
	require.NoError(t, p.FindObjectsFinal(session))
	require.Len(t, handles, 1, "exactly one private key carries the generated address as its label")

	attributes, err := p.GetAttributeValue(session, handles[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
	})
	require.NoError(t, err)
	flags := map[uint]bool{}
	for _, attribute := range attributes {
		require.NotEmpty(t, attribute.Value)
		flags[attribute.Type] = attribute.Value[0] != 0
	}
	require.True(t, flags[pkcs11.CKA_SENSITIVE], "CKA_SENSITIVE must be true")
	require.False(t, flags[pkcs11.CKA_EXTRACTABLE], "CKA_EXTRACTABLE must be false")

	_, err = p.GetAttributeValue(session, handles[0], []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
	require.Error(t, err, "the private key value must not be readable")
}
