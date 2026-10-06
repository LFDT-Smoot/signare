package hsmconnector_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/test/signaturemanagertesthelper"

	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

const foreignKeyLabel = "not-an-ethereum-key"

// TestListAddresses_SkipsKeyNotOnSecp256k1 guards listing against a token object signare cannot derive
// an address from. An operator importing a key with softhsm2-util can pick the wrong curve; that
// object must be skipped, not take down every eth_accounts call on the slot.
func TestListAddresses_SkipsKeyNotOnSecp256k1(t *testing.T) {
	foreign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(foreign)
	require.NoError(t, err)
	keyPath := filepath.Join(t.TempDir(), "p256.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))

	t.Cleanup(func() {
		require.Zero(t, destroyObjectsLabelled(t, foreignKeyLabel), "cleanup must leave no foreign object in the shared slot")
	})
	output, err := exec.Command("softhsm2-util", //nolint:gosec
		"--import", keyPath,
		"--slot", slotID,
		"--label", foreignKeyLabel,
		"--id", "0f0f",
		"--pin", signaturemanagertesthelper.SlotPin,
	).CombinedOutput()
	require.NoError(t, err, string(output))

	var listed *hsmconnector.ListAddressesOutput
	require.NotPanics(t, func() {
		listed, err = app.HSMConnector.ListAddresses(ctx, hsmconnector.ListAddressesInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				PinSource:  slotPinSource,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
		})
	})
	require.NoError(t, err)

	found := false
	for _, addr := range listed.Items {
		found = found || addr.String() == signaturemanagertesthelper.ImportedKeyAddress
	}
	require.True(t, found, "the secp256k1 keys in the slot must still be listed")
}

// destroyObjectsLabelled deletes every object in the test slot carrying label and returns how many are
// left afterwards. softhsm2-util cannot delete an object, so this goes through PKCS#11. The library is
// already initialised by the application under test, so that error is expected, and it is never
// finalised here, which would close the application's sessions too.
func destroyObjectsLabelled(t *testing.T, label string) int {
	t.Helper()
	module := pkcs11.New(signaturemanagertesthelper.SoftHSMLib)
	require.NotNil(t, module)
	if err := module.Initialize(); err != nil && !errors.Is(err, pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
		require.NoError(t, err)
	}
	slot, err := strconv.ParseUint(slotID, 10, 32)
	require.NoError(t, err)
	session, err := module.OpenSession(uint(slot), pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	require.NoError(t, err)
	defer func() { _ = module.CloseSession(session) }()
	if err = module.Login(session, pkcs11.CKU_USER, signaturemanagertesthelper.SlotPin); err != nil && !errors.Is(err, pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN)) {
		require.NoError(t, err)
	}
	defer func() { _ = module.Logout(session) }()

	find := func() []pkcs11.ObjectHandle {
		require.NoError(t, module.FindObjectsInit(session, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)}))
		objects, _, findErr := module.FindObjects(session, 16)
		require.NoError(t, findErr)
		require.NoError(t, module.FindObjectsFinal(session))
		return objects
	}
	for _, object := range find() {
		require.NoError(t, module.DestroyObject(session, object))
	}
	return len(find())
}
