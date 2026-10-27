package akv

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/stretchr/testify/require"

	"github.com/lfdt-smoot/signare/app/pkg/commons/logger"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
)

// fakeVault records the order of the calls it receives, so the test can prove the key is checked
// before anything is signed, and that a refused key is never asked to sign.
type fakeVault struct {
	key   azkeys.GetKeyResponse
	calls []string
}

func (f *fakeVault) GetKey(_ context.Context, _ string, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	f.calls = append(f.calls, "GetKey")
	return f.key, nil
}

func (f *fakeVault) Sign(_ context.Context, _ string, _ string, _ azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
	f.calls = append(f.calls, "Sign")
	return azkeys.SignResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: make([]byte, 64)}}, nil
}

func keyResponse(kty azkeys.KeyType, crv azkeys.CurveName, platform string) azkeys.GetKeyResponse {
	return azkeys.GetKeyResponse{KeyBundle: azkeys.KeyBundle{
		Key:        &azkeys.JSONWebKey{Kty: to.Ptr(kty), Crv: to.Ptr(crv)},
		Attributes: &azkeys.KeyAttributes{HSMPlatform: to.Ptr(platform)},
	}}
}

func signInput() signaturemanager.SignInput {
	from := address.MustNewFromHexString("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
	return signaturemanager.SignInput{
		Tracer: logger.NewTracer(context.Background()),
		From:   from,
		Data:   make([]byte, 32),
		Config: signaturemanager.SlotConfig{AKV: []signaturemanager.AKVConfig{{KeyName: "k", KeyVersion: "v1", KeyPublicAddress: from.String()}}},
	}
}

func TestSignChecksTheKeyBeforeSigning(t *testing.T) {
	vault := &fakeVault{key: keyResponse(azkeys.KeyTypeECHSM, azkeys.CurveNameP256K, "2")}
	sm := newAKVSignatureManager(vault, true)

	out, err := sm.Sign(context.Background(), signInput())
	require.NoError(t, err)
	require.Len(t, out.Signature, 64)
	require.Equal(t, []string{"GetKey", "Sign"}, vault.calls, "the key is read before the digest is sent")

	_, err = sm.Sign(context.Background(), signInput())
	require.NoError(t, err)
	require.Equal(t, []string{"GetKey", "Sign", "Sign"}, vault.calls, "a verified key version is not read again")
}

func TestSignRefusesASoftwareKeyWithoutSigning(t *testing.T) {
	vault := &fakeVault{key: keyResponse(azkeys.KeyTypeEC, azkeys.CurveNameP256K, "0")}
	sm := newAKVSignatureManager(vault, true)

	_, err := sm.Sign(context.Background(), signInput())
	require.Error(t, err)
	require.True(t, signaturemanager.IsPolicyRefusedError(err))
	require.Equal(t, []string{"GetKey"}, vault.calls, "a refused key is never asked to sign")
}

func TestSignWithPolicyOffSignsWithASoftwareKey(t *testing.T) {
	vault := &fakeVault{key: keyResponse(azkeys.KeyTypeEC, azkeys.CurveNameP256K, "0")}
	sm := newAKVSignatureManager(vault, false)

	_, err := sm.Sign(context.Background(), signInput())
	require.NoError(t, err)
	require.Equal(t, []string{"GetKey", "Sign"}, vault.calls)
}
