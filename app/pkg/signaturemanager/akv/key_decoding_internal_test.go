package akv

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
)

// vaultKey decodes a key the way the SDK decodes the vault's response, so the check is tested against
// the wire format and not against structs built in Go.
func vaultKey(t *testing.T, kty string, platform string, exportable bool) azkeys.GetKeyResponse {
	t.Helper()
	body := fmt.Sprintf(`{"key":{"kid":"https://vault.vault.azure.net/keys/k/v1","kty":%q,"crv":"P-256K","key_ops":["sign","verify"]},"attributes":{"enabled":true,"exportable":%t,"hsmPlatform":%q,"recoveryLevel":"Recoverable+Purgeable"}}`, kty, exportable, platform)
	var bundle azkeys.KeyBundle
	require.NoError(t, json.Unmarshal([]byte(body), &bundle))
	return azkeys.GetKeyResponse{KeyBundle: bundle}
}

func TestDescribeKeyReadsTheVaultsWireFormat(t *testing.T) {
	for _, platform := range []string{"0", "1", "2"} {
		vault := &fakeVault{key: vaultKey(t, "EC-HSM", platform, true)}
		d, err := azkeysReader{client: vault}.describeKey(context.Background(), "k", "v1")
		require.NoError(t, err)
		require.Equal(t, platform, d.hsmPlatform, "hsmPlatform must survive the SDK's decoding")
		require.True(t, d.exportable, "exportable must survive the SDK's decoding")
	}
}

func TestSignRefusesKeysTheVaultReportsAsUnprotected(t *testing.T) {
	cases := []struct {
		name       string
		kty        string
		platform   string
		exportable bool
		refused    bool
	}{
		{"HSM key on the current platform", "EC-HSM", "2", false, false},
		{"HSM key on the previous FIPS 140-2 platform", "EC-HSM", "1", false, true},
		{"software key", "EC", "0", false, true},
		{"exportable HSM key", "EC-HSM", "2", true, true},
		{"exportable HSM key on the previous platform", "EC-HSM", "1", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vault := &fakeVault{key: vaultKey(t, c.kty, c.platform, c.exportable)}
			_, err := newAKVSignatureManager(vault, true).Sign(context.Background(), signInput())
			if !c.refused {
				require.NoError(t, err)
				require.Equal(t, []string{"GetKey", "Sign"}, vault.calls)
				return
			}
			require.True(t, signaturemanager.IsPolicyRefusedError(err), "want a policy refusal, got %v", err)
			require.Equal(t, []string{"GetKey"}, vault.calls, "a refused key is never asked to sign")
			if c.exportable {
				require.Contains(t, err.Error(), "exportable", "the refusal names the reason")
			}
		})
	}
}

// TestSignAcceptsAKeyWhoseResponseOmitsExportable covers an ordinary vault response that carries no
// exportable attribute at all: absence must not be read as exportable.
func TestSignAcceptsAKeyWhoseResponseOmitsExportable(t *testing.T) {
	body := `{"key":{"kid":"https://vault.vault.azure.net/keys/k/v1","kty":"EC-HSM","crv":"P-256K","key_ops":["sign","verify"]},"attributes":{"enabled":true,"hsmPlatform":"2","recoveryLevel":"Recoverable+Purgeable"}}`
	var bundle azkeys.KeyBundle
	require.NoError(t, json.Unmarshal([]byte(body), &bundle))
	vault := &fakeVault{key: azkeys.GetKeyResponse{KeyBundle: bundle}}

	_, err := newAKVSignatureManager(vault, true).Sign(context.Background(), signInput())
	require.NoError(t, err)
	require.Equal(t, []string{"GetKey", "Sign"}, vault.calls)
}
