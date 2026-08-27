package rpcin

import (
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra"
	"github.com/lfdt-smoot/signare/app/pkg/infra/rpcinfra/rpcerrors"
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

// fakeHSMConnector only exercises SignTypedData and SignTx; the other interface methods are promoted
// from the embedded nil interface and would panic if the code under test called them unexpectedly.
type fakeHSMConnector struct {
	hsmconnector.HSMConnector
	gotInput       hsmconnector.SignTypedDataInput
	gotSignTxInput hsmconnector.SignTxInput
	output         *hsmconnector.SignTypedDataOutput
	called         bool
}

func (f *fakeHSMConnector) SignTypedData(_ context.Context, input hsmconnector.SignTypedDataInput) (*hsmconnector.SignTypedDataOutput, error) {
	f.called = true
	f.gotInput = input
	return f.output, nil
}

func (f *fakeHSMConnector) SignTx(_ context.Context, input hsmconnector.SignTxInput) (*hsmconnector.SignTxOutput, error) {
	f.called = true
	f.gotSignTxInput = input
	return &hsmconnector.SignTxOutput{SignedTx: "0xsignedtx"}, nil
}

// TestAdaptSignTx_AccessListPresenceReachesTheUseCase asserts the adapter carries accessList presence
// across the boundary rather than normalising it away. The use case infers an EIP-2930 (Type 1)
// transaction from a non-nil access list, so an explicitly empty one must not arrive as nil: that would
// sign a legacy transaction over different bytes than the caller asked for.
func TestAdaptSignTx_AccessListPresenceReachesTheUseCase(t *testing.T) {
	const (
		from     = "0x970e8128ab834e8eac17ab8e3812f010678cf791"
		accessed = "0xcccccccccccccccccccccccccccccccccccccccc"
		storeKey = "0x0000000000000000000000000000000000000000000000000000000000000001"
	)
	baseParams := func() rpcinfra.SignTXRequestParams {
		return rpcinfra.SignTXRequestParams{
			ApplicationID: "app1",
			From:          from,
			Data:          "0x",
			Nonce:         "0x1",
		}
	}
	newAdapter := func(connector *fakeHSMConnector) *DefaultAPIAdapter {
		return &DefaultAPIAdapter{
			hsmConnectionResolver: fakeConnectionResolver{connection: &hsmconnection.HSMConnection{
				ModuleKind:                hsmconnector.SoftHSMModuleKind,
				ApplicationDefaultChainID: *entities.NewInt256FromInt(11155111),
			}},
			hsmConnector: connector,
		}
	}

	t.Run("omitted accessList arrives nil", func(t *testing.T) {
		connector := &fakeHSMConnector{}
		out, rpcErr := newAdapter(connector).AdaptSignTx(context.Background(), baseParams())

		require.Nil(t, rpcErr)
		require.Equal(t, "0xsignedtx", *out)
		require.Nil(t, connector.gotSignTxInput.AccessList)
	})

	t.Run("empty accessList arrives non-nil", func(t *testing.T) {
		params := baseParams()
		params.AccessList = []rpcinfra.AccessListParamEntry{}
		connector := &fakeHSMConnector{}
		out, rpcErr := newAdapter(connector).AdaptSignTx(context.Background(), params)

		require.Nil(t, rpcErr)
		require.Equal(t, "0xsignedtx", *out)
		require.NotNil(t, connector.gotSignTxInput.AccessList)
		require.Empty(t, connector.gotSignTxInput.AccessList)
	})

	t.Run("populated accessList arrives with its entries adapted", func(t *testing.T) {
		params := baseParams()
		params.AccessList = []rpcinfra.AccessListParamEntry{
			{Address: accessed, StorageKeys: []string{storeKey}},
		}
		connector := &fakeHSMConnector{}
		out, rpcErr := newAdapter(connector).AdaptSignTx(context.Background(), params)

		require.Nil(t, rpcErr)
		require.Equal(t, "0xsignedtx", *out)
		require.Len(t, connector.gotSignTxInput.AccessList, 1)
		require.Truef(t, strings.EqualFold(accessed, connector.gotSignTxInput.AccessList[0].Address.String()),
			"expected accessed address %s, got %s", accessed, connector.gotSignTxInput.AccessList[0].Address.String())
		require.Len(t, connector.gotSignTxInput.AccessList[0].StorageKeys, 1)
		// HexBytes32.Encode returns unprefixed hex, despite what its doc comment claims.
		require.Equal(t, strings.TrimPrefix(storeKey, "0x"), connector.gotSignTxInput.AccessList[0].StorageKeys[0].Encode())
	})

	t.Run("invalid accessList address is rejected before signing", func(t *testing.T) {
		params := baseParams()
		params.AccessList = []rpcinfra.AccessListParamEntry{
			{Address: "not-an-address", StorageKeys: []string{storeKey}},
		}
		connector := &fakeHSMConnector{}
		out, rpcErr := newAdapter(connector).AdaptSignTx(context.Background(), params)

		require.Nil(t, out)
		require.NotNil(t, rpcErr)
		require.Equal(t, rpcerrors.InvalidParamsErrorCode, rpcErr.Code)
		require.False(t, connector.called)
	})
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
