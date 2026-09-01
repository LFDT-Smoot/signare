package rpcin

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra/rpcerrors"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/eip191"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/eip712"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnection"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"

	"github.com/stretchr/testify/require"
)

type fakeConnectionResolver struct {
	connection *hsmconnection.HSMConnection
}

func (f fakeConnectionResolver) ByApplication(context.Context, hsmconnection.ByApplicationInput) (*hsmconnection.HSMConnection, error) {
	return f.connection, nil
}

// fakeHSMConnector only exercises SignTypedData and PersonalSign; the other interface methods are
// promoted from the embedded nil interface and would panic if the code under test called them
// unexpectedly.
type fakeHSMConnector struct {
	hsmconnector.HSMConnector
	gotInput             hsmconnector.SignTypedDataInput
	output               *hsmconnector.SignTypedDataOutput
	gotPersonalSignInput hsmconnector.PersonalSignInput
	personalSignOutput   *hsmconnector.PersonalSignOutput
	called               bool
}

func (f *fakeHSMConnector) SignTypedData(_ context.Context, input hsmconnector.SignTypedDataInput) (*hsmconnector.SignTypedDataOutput, error) {
	f.called = true
	f.gotInput = input
	return f.output, nil
}

func (f *fakeHSMConnector) PersonalSign(_ context.Context, input hsmconnector.PersonalSignInput) (*hsmconnector.PersonalSignOutput, error) {
	f.called = true
	f.gotPersonalSignInput = input
	return f.personalSignOutput, nil
}

// TestAdaptSignTypedData_ScopesToApplicationChainAndSigner asserts the adapter signs with the
// application's default chain and the requested account, so the signature is bound to the application's
// chain regardless of the request payload.
func TestAdaptSignTypedData_ScopesToApplicationChainAndSigner(t *testing.T) {
	const signer = "0x970e8128ab834e8eac17ab8e3812f010678cf791"
	connection := &hsmconnection.HSMConnection{
		ModuleKind:                hsmconnector.SoftHSMModuleKind,
		ApplicationDefaultChainID: *entities.NewInt256FromInt(11155111),
	}
	connector := &fakeHSMConnector{output: &hsmconnector.SignTypedDataOutput{SignedData: "0xsignature"}}
	adapter := &DefaultAPIAdapter{
		hsmConnectionResolver: fakeConnectionResolver{connection: connection},
		hsmConnector:          connector,
	}

	out, rpcErr := adapter.AdaptSignTypedData(context.Background(), rpcinfra.SignTypedDataRequestParams{
		ApplicationID: "app1",
		Address:       signer,
	})

	require.Nil(t, rpcErr)
	require.Equal(t, "0xsignature", *out)
	require.Equal(t, int64(11155111), connector.gotInput.ChainID.BigInt().Int64())
	require.Truef(t, strings.EqualFold(signer, connector.gotInput.Address.String()),
		"expected signer %s, got %s", signer, connector.gotInput.Address.String())
}

// TestAdaptSignTypedData_InvalidAddressReturnsInvalidParams asserts an unparseable account is rejected
// as invalid params rather than reaching the signing backend.
func TestAdaptSignTypedData_InvalidAddressReturnsInvalidParams(t *testing.T) {
	connection := &hsmconnection.HSMConnection{
		ModuleKind:                hsmconnector.SoftHSMModuleKind,
		ApplicationDefaultChainID: *entities.NewInt256FromInt(1),
	}
	adapter := &DefaultAPIAdapter{
		hsmConnectionResolver: fakeConnectionResolver{connection: connection},
		hsmConnector:          &fakeHSMConnector{},
	}

	_, rpcErr := adapter.AdaptSignTypedData(context.Background(), rpcinfra.SignTypedDataRequestParams{
		ApplicationID: "app1",
		Address:       "not-an-address",
	})

	require.NotNil(t, rpcErr)
	require.Equal(t, rpcerrors.InvalidParamsErrorCode, rpcErr.Code)
}

// TestAdaptSignTypedData_DomainChainIDMismatchRejectedBeforeSigning asserts that a typed data domain
// declaring a chainId other than the application's default chain is rejected with invalid params and
// never reaches the signing backend.
func TestAdaptSignTypedData_DomainChainIDMismatchRejectedBeforeSigning(t *testing.T) {
	connection := &hsmconnection.HSMConnection{
		ModuleKind:                hsmconnector.SoftHSMModuleKind,
		ApplicationDefaultChainID: *entities.NewInt256FromInt(1),
	}
	connector := &fakeHSMConnector{output: &hsmconnector.SignTypedDataOutput{SignedData: "0xsignature"}}
	adapter := &DefaultAPIAdapter{
		hsmConnectionResolver: fakeConnectionResolver{connection: connection},
		hsmConnector:          connector,
	}

	_, rpcErr := adapter.AdaptSignTypedData(context.Background(), rpcinfra.SignTypedDataRequestParams{
		ApplicationID: "app1",
		Address:       "0x970e8128ab834e8eac17ab8e3812f010678cf791",
		TypedData: eip712.TypedData{
			Domain: eip712.EIP712Domain{ChainId: big.NewInt(999)},
		},
	})

	require.NotNil(t, rpcErr)
	require.Equal(t, rpcerrors.InvalidParamsErrorCode, rpcErr.Code)
	require.False(t, connector.called, "signing backend must not be reached on a chainId mismatch")
}

// TestAdaptSignTypedData_DomainChainIDMatchingAppChainSigns asserts that a domain chainId equal to the
// application's default chain is accepted and reaches the signing backend.
func TestAdaptSignTypedData_DomainChainIDMatchingAppChainSigns(t *testing.T) {
	connection := &hsmconnection.HSMConnection{
		ModuleKind:                hsmconnector.SoftHSMModuleKind,
		ApplicationDefaultChainID: *entities.NewInt256FromInt(11155111),
	}
	connector := &fakeHSMConnector{output: &hsmconnector.SignTypedDataOutput{SignedData: "0xsignature"}}
	adapter := &DefaultAPIAdapter{
		hsmConnectionResolver: fakeConnectionResolver{connection: connection},
		hsmConnector:          connector,
	}

	out, rpcErr := adapter.AdaptSignTypedData(context.Background(), rpcinfra.SignTypedDataRequestParams{
		ApplicationID: "app1",
		Address:       "0x970e8128ab834e8eac17ab8e3812f010678cf791",
		TypedData: eip712.TypedData{
			Domain: eip712.EIP712Domain{ChainId: big.NewInt(11155111)},
		},
	})

	require.Nil(t, rpcErr)
	require.Equal(t, "0xsignature", *out)
	require.True(t, connector.called)
}

// TestAdaptPersonalSign_HashesTheDecodedBytesNotTheHexString is the link no other test covers. The
// use-case tests hand a raw []byte straight to PersonalSign and the params tests only check that
// Message still equals the string "0x48656c6c6f", so an adapter that passed the hex string through
// undecoded would sign eleven ASCII bytes instead of the five bytes of "Hello" and every other test
// would still pass, while every SIWE verifier would reject the signature.
func TestAdaptPersonalSign_HashesTheDecodedBytesNotTheHexString(t *testing.T) {
	const (
		signer     = "0x970e8128ab834e8eac17ab8e3812f010678cf791"
		hexMessage = "0x48656c6c6f"
	)
	decoded := []byte("Hello")

	connector := &fakeHSMConnector{personalSignOutput: &hsmconnector.PersonalSignOutput{SignedData: "0xsignature"}}
	adapter := &DefaultAPIAdapter{
		hsmConnectionResolver: fakeConnectionResolver{connection: &hsmconnection.HSMConnection{
			ModuleKind: hsmconnector.SoftHSMModuleKind,
		}},
		hsmConnector: connector,
	}

	out, rpcErr := adapter.AdaptPersonalSign(context.Background(), rpcinfra.PersonalSignRequestParams{
		ApplicationID: "app1",
		Address:       signer,
		Message:       hexMessage,
	})

	require.Nil(t, rpcErr)
	require.Equal(t, "0xsignature", *out)
	require.True(t, connector.called)
	require.Equal(t, decoded, connector.gotPersonalSignInput.Message,
		"the adapter must hand the decoded bytes to the use case, not the hex string")
	require.Truef(t, strings.EqualFold(signer, connector.gotPersonalSignInput.Address.String()),
		"expected signer %s, got %s", signer, connector.gotPersonalSignInput.Address.String())

	// The digest the use case would take over what it actually received must be the digest over the
	// decoded bytes, and must differ from the digest over the hex string itself.
	signedDigest, err := eip191.HashPersonalMessage(connector.gotPersonalSignInput.Message)
	require.NoError(t, err)
	wantDigest, err := eip191.HashPersonalMessage(decoded)
	require.NoError(t, err)
	literalDigest, err := eip191.HashPersonalMessage([]byte(hexMessage))
	require.NoError(t, err)

	require.Equal(t, hex.EncodeToString(wantDigest), hex.EncodeToString(signedDigest))
	require.NotEqual(t, hex.EncodeToString(literalDigest), hex.EncodeToString(signedDigest),
		"signing the hex string itself must not produce the same digest as signing the decoded bytes")
}

// TestAdaptPersonalSign_InvalidMessageReturnsInvalidParams covers the only place malformed hex is
// rejected. ValidateParams checks the 0x prefix and non-emptiness only, so odd-length and non-hex
// input reaches entities.NewHexBytesFromString here and nowhere else.
func TestAdaptPersonalSign_InvalidMessageReturnsInvalidParams(t *testing.T) {
	for name, message := range map[string]string{
		"odd-length hex":       "0xabc",
		"non-hex characters":   "0xzz",
		"non-hex after prefix": "0x48656c6c6g",
	} {
		t.Run(name, func(t *testing.T) {
			connector := &fakeHSMConnector{}
			adapter := &DefaultAPIAdapter{
				hsmConnectionResolver: fakeConnectionResolver{connection: &hsmconnection.HSMConnection{
					ModuleKind: hsmconnector.SoftHSMModuleKind,
				}},
				hsmConnector: connector,
			}

			_, rpcErr := adapter.AdaptPersonalSign(context.Background(), rpcinfra.PersonalSignRequestParams{
				ApplicationID: "app1",
				Address:       "0x970e8128ab834e8eac17ab8e3812f010678cf791",
				Message:       message,
			})

			require.NotNil(t, rpcErr)
			require.Equal(t, rpcerrors.InvalidParamsErrorCode, rpcErr.Code)
			require.False(t, connector.called, "signing backend must not be reached on malformed hex")
		})
	}
}

// TestAdaptPersonalSign_InvalidAddressReturnsInvalidParams is the mirror of
// TestAdaptSignTypedData_InvalidAddressReturnsInvalidParams: an unparseable account is rejected as
// invalid params rather than reaching the signing backend.
func TestAdaptPersonalSign_InvalidAddressReturnsInvalidParams(t *testing.T) {
	connector := &fakeHSMConnector{}
	adapter := &DefaultAPIAdapter{
		hsmConnectionResolver: fakeConnectionResolver{connection: &hsmconnection.HSMConnection{
			ModuleKind: hsmconnector.SoftHSMModuleKind,
		}},
		hsmConnector: connector,
	}

	_, rpcErr := adapter.AdaptPersonalSign(context.Background(), rpcinfra.PersonalSignRequestParams{
		ApplicationID: "app1",
		Address:       "not-an-address",
		Message:       "0x48656c6c6f",
	})

	require.NotNil(t, rpcErr)
	require.Equal(t, rpcerrors.InvalidParamsErrorCode, rpcErr.Code)
	require.False(t, connector.called, "signing backend must not be reached on an invalid address")
}
