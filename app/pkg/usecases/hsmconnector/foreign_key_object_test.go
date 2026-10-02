package hsmconnector_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"
	"github.com/lfdt-smoot/signare/app/test/signaturemanagertesthelper"

	"github.com/stretchr/testify/require"
)

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

	output, err := exec.Command("softhsm2-util", //nolint:gosec
		"--import", keyPath,
		"--slot", slotID,
		"--label", "not-an-ethereum-key",
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
