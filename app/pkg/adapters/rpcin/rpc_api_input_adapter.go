// Package rpcin defines the implementation of the input adapters for the JSON RPC infra.
package rpcin

import (
	"context"
	"errors"
	"fmt"

	"github.com/hyperledger-labs/signare/app/pkg/entities"
	"github.com/hyperledger-labs/signare/app/pkg/entities/address"
	"github.com/hyperledger-labs/signare/app/pkg/infra/rpcinfra"
	"github.com/hyperledger-labs/signare/app/pkg/infra/rpcinfra/rpcerrors"
	"github.com/hyperledger-labs/signare/app/pkg/usecases/hsmconnection"
	"github.com/hyperledger-labs/signare/app/pkg/usecases/hsmconnector"
	"github.com/hyperledger-labs/signare/app/pkg/usecases/hsmslot"
	"github.com/hyperledger-labs/signare/app/pkg/usecases/user"
)

var _ rpcinfra.JSONRPCAPIAdapter = new(DefaultAPIAdapter)

func (adapter *DefaultAPIAdapter) AdaptGenerateAccount(ctx context.Context, data rpcinfra.GenerateAccountRequestParams) (*string, *rpcerrors.RPCError) {
	input := hsmconnection.ByApplicationInput{
		ApplicationID: data.ApplicationID,
	}
	hsmConnection, err := adapter.hsmConnectionResolver.ByApplication(ctx, input)
	if err != nil {
		return nil, adaptError(err)
	}

	generateAddressInput := hsmconnector.GenerateAddressInput{
		SlotConnectionData: hsmconnector.SlotConnectionData{
			Pin:        hsmConnection.Slot.Pin,
			Slot:       hsmConnection.Slot.Slot,
			ModuleKind: hsmConnection.ModuleKind,
		},
	}
	out, err := adapter.hsmConnector.GenerateAddress(ctx, generateAddressInput)
	if err != nil {
		return nil, adaptError(err)
	}
	response := out.Address.String()
	return &response, nil
}

func (adapter *DefaultAPIAdapter) AdaptImportAccount(ctx context.Context, data rpcinfra.ImportAccountRequestParams) (*string, *rpcerrors.RPCError) {
	if len(data.PrivateKey) == 0 {
		return nil, rpcerrors.NewInvalidRequest()
	}

	privateKey, err := entities.NewHexBytesFromString(data.PrivateKey)
	if err != nil {
		return nil, rpcerrors.NewInvalidParamsFromErr(err)
	}

	getHSMConnectionInput := hsmconnection.ByApplicationInput{
		ApplicationID: data.ApplicationID,
	}
	hsmConnection, err := adapter.hsmConnectionResolver.ByApplication(ctx, getHSMConnectionInput)
	if err != nil {
		return nil, adaptError(err)
	}

	deriveAddressInput := hsmconnector.DeriveAddressFromPrivateKeyInput{
		PrivateKey: privateKey,
		ModuleKind: hsmConnection.ModuleKind,
	}
	deriveAddressOutput, err := adapter.hsmConnector.DeriveAddressFromPrivateKey(ctx, deriveAddressInput)
	if err != nil {
		return nil, adaptError(err)
	}

	addLocalKeyInput := hsmslot.AddLocalKeyInput{
		StandardID: hsmConnection.Slot.StandardID,
		PrivateKey: privateKey,
		Address:    deriveAddressOutput.Address,
	}
	err = adapter.slotUseCase.AddLocalKey(ctx, addLocalKeyInput)
	if err != nil {
		return nil, adaptError(err)
	}

	response := deriveAddressOutput.Address.String()
	return &response, nil
}

func (adapter *DefaultAPIAdapter) AdaptRemoveAccount(ctx context.Context, data rpcinfra.RemoveAccountRequestParams) (*string, *rpcerrors.RPCError) {
	addr, err := address.NewFromHexStringChecksum(data.Address)
	if err != nil {
		return nil, rpcerrors.NewInvalidParamsFromErr(err)
	}
	input := user.DeleteAllAccountsForAddressInput{
		Address:       addr,
		ApplicationID: data.ApplicationID,
	}
	_, deleteErr := adapter.accountUseCase.DeleteAllAccountsForAddress(ctx, input)
	if deleteErr != nil {
		return nil, adaptError(deleteErr)
	}
	response := addr.String()
	return &response, nil
}

func (adapter *DefaultAPIAdapter) AdaptListAccounts(ctx context.Context, data rpcinfra.ListAccountsRequestParams) ([]string, *rpcerrors.RPCError) {
	input := hsmconnection.ByApplicationInput{
		ApplicationID: data.ApplicationID,
	}
	hsmConnection, err := adapter.hsmConnectionResolver.ByApplication(ctx, input)
	if err != nil {
		return nil, adaptError(err)
	}

	if hsmConnection.ModuleKind == hsmconnector.LKVModuleKind {
		listLocalKeysInput := hsmslot.ListLocalKeysInput{
			StandardID: entities.StandardID{
				ID: hsmConnection.Slot.ID,
			},
		}
		out, listErr := adapter.slotUseCase.ListLocalKeys(ctx, listLocalKeysInput)
		if listErr != nil {
			return nil, adaptError(err)
		}
		response := make([]string, len(out.Addresses))
		for i, addr := range out.Addresses {
			response[i] = addr.String()
		}
		return response, nil
	}

	listAddressesInput := hsmconnector.ListAddressesInput{
		SlotConnectionData: hsmconnector.SlotConnectionData{
			Pin:        hsmConnection.Slot.Pin,
			Slot:       hsmConnection.Slot.Slot,
			ModuleKind: hsmConnection.ModuleKind,
		},
	}
	out, err := adapter.hsmConnector.ListAddresses(ctx, listAddressesInput)
	if err != nil {
		return nil, adaptError(err)
	}
	response := make([]string, len(out.Items))
	for i, addr := range out.Items {
		response[i] = addr.String()
	}
	return response, nil
}

func (adapter *DefaultAPIAdapter) AdaptSignTx(ctx context.Context, data rpcinfra.SignTXRequestParams) (*string, *rpcerrors.RPCError) {
	byApplicationInput := hsmconnection.ByApplicationInput{
		ApplicationID: data.ApplicationID,
	}
	hsmConnection, err := adapter.hsmConnectionResolver.ByApplication(ctx, byApplicationInput)
	if err != nil {
		return nil, adaptError(err)
	}

	moduleKind := hsmConnection.ModuleKind

	signTxInput, hsmModuleError := adaptHSMModule(moduleKind, hsmConnection)
	if hsmModuleError != nil {
		return nil, hsmModuleError
	}

	if len(data.Data) > 0 {
		inputData, encodeDataErr := entities.NewHexBytesFromString(data.Data)
		if encodeDataErr != nil {
			return nil, rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("invalid [data]: %w", encodeDataErr))
		}
		signTxInput.Data = inputData
	}

	nonce, err := entities.NewHexUInt64FromString(data.Nonce)
	if err != nil {
		return nil, rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("invalid [nonce]: %w", err))
	}
	signTxInput.Nonce = nonce

	from, err := address.NewFromHexString(data.From)
	if err != nil {
		return nil, rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("invalid [from]: %w", err))
	}
	signTxInput.From = from

	if data.To != nil {
		to, errTo := address.NewFromHexString(*data.To)
		if errTo != nil {
			return nil, rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("invalid [to]: %w", errTo))
		}
		signTxInput.To = &to
	}

	if data.Gas != nil {
		gas, errGas := entities.NewHexUInt64FromString(*data.Gas)
		if errGas != nil {
			return nil, rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("invalid [gas]: %w", errGas))
		}
		signTxInput.Gas = &gas
	}

	if data.GasPrice != nil {
		gasPrice, errGasPrice := entities.NewHexInt256FromString(*data.GasPrice)
		if errGasPrice != nil {
			return nil, rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("invalid [gasPrice]: %w", errGasPrice))
		}
		signTxInput.GasPrice = gasPrice
	}

	if data.Value != nil && len(*data.Value) > 0 {
		value, errValue := entities.NewHexInt256FromString(*data.Value)
		if errValue != nil {
			return nil, rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("invalid [value]: %w", errValue))
		}
		signTxInput.Value = value
	}

	// EIP-1559 fields
	if data.MaxFeePerGas != nil {
		maxFeePerGas, errMaxFee := entities.NewHexInt256FromString(*data.MaxFeePerGas)
		if errMaxFee != nil {
			return nil, rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("invalid [maxFeePerGas]: %w", errMaxFee))
		}
		signTxInput.MaxFeePerGas = maxFeePerGas
	}

	if data.MaxPriorityFeePerGas != nil {
		maxPriorityFee, errMaxPriority := entities.NewHexInt256FromString(*data.MaxPriorityFeePerGas)
		if errMaxPriority != nil {
			return nil, rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("invalid [maxPriorityFeePerGas]: %w", errMaxPriority))
		}
		signTxInput.MaxPriorityFeePerGas = maxPriorityFee
	}

	if data.AccessList != nil {
		accessList, accessListError := adaptAccessList(data)
		if accessListError != nil {
			return nil, accessListError
		}
		signTxInput.AccessList = *accessList
	}

	// EIP-4844 fields
	if eip4844Err := adaptEIP4844Fields(data, signTxInput); eip4844Err != nil {
		return nil, eip4844Err
	}

	// EIP-7702 fields
	if data.AuthorizationList != nil {
		authorizationList, authorizationListError := adaptAuthorizationList(data)
		if authorizationListError != nil {
			return nil, authorizationListError
		}
		signTxInput.AuthorizationList = *authorizationList
	}

	signTxInput.ChainID = *entities.NewHexInt256(hsmConnection.ApplicationDefaultChainID.BigInt())

	if data.ChainID != nil {
		hexChainID, hexChainIDErr := entities.NewHexInt256FromString(*data.ChainID)
		if hexChainIDErr != nil {
			return nil, rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("invalid [chainId]: %w", hexChainIDErr))
		}
		signTxInput.ChainID = *hexChainID
	}

	out, err := adapter.hsmConnector.SignTx(ctx, *signTxInput)
	if err != nil {
		return nil, adaptError(err)
	}
	response := out.SignedTx
	return &response, nil
}

func (adapter *DefaultAPIAdapter) AdaptSignTypedData(ctx context.Context, data rpcinfra.SignTypedDataRequestParams) (*string, *rpcerrors.RPCError) {
	byApplicationInput := hsmconnection.ByApplicationInput{
		ApplicationID: data.ApplicationID,
	}
	hsmConnection, err := adapter.hsmConnectionResolver.ByApplication(ctx, byApplicationInput)
	if err != nil {
		return nil, adaptError(err)
	}

	// Reject a typed data domain that targets a chain other than the application's default chain before
	// touching the signing backend. The use case enforces this too; performing it here fails fast and
	// keeps the rule covered by lean unit tests that do not require an HSM.
	appChainID := hsmConnection.ApplicationDefaultChainID.BigInt()
	if domainChainID := data.TypedData.Domain.ChainId; domainChainID != nil && domainChainID.Cmp(appChainID) != 0 {
		return nil, rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("typed data domain chainId %s does not match the application default chain %s", domainChainID.String(), appChainID.String()))
	}

	slotConnectionData, moduleErr := adaptSlotConnectionData(hsmConnection.ModuleKind, hsmConnection)
	if moduleErr != nil {
		return nil, moduleErr
	}

	signer, err := address.NewFromHexString(data.Address)
	if err != nil {
		return nil, rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("invalid [address]: %w", err))
	}

	signTypedDataInput := hsmconnector.SignTypedDataInput{
		SlotConnectionData: *slotConnectionData,
		// ChainID is the application's default chain. It is used only to reject a typed data domain that
		// declares a different chainId (checked above and again in the use case); it is not injected into
		// the EIP-712 domain separator, so it does not bind the signature to a chain when the domain omits
		// chainId.
		ChainID:   *entities.NewHexInt256(appChainID),
		Address:   signer,
		TypedData: data.TypedData,
	}

	out, err := adapter.hsmConnector.SignTypedData(ctx, signTypedDataInput)
	if err != nil {
		return nil, adaptError(err)
	}
	response := out.SignedData
	return &response, nil
}

func adaptHSMModule(moduleKind hsmconnector.ModuleKind, hsmConnection *hsmconnection.HSMConnection) (*hsmconnector.SignTxInput, *rpcerrors.RPCError) {
	slotConnectionData, err := adaptSlotConnectionData(moduleKind, hsmConnection)
	if err != nil {
		return nil, err
	}
	return &hsmconnector.SignTxInput{
		SlotConnectionData: *slotConnectionData,
	}, nil
}

// adaptSlotConnectionData builds the slot connection data shared by every signing operation from the
// resolved HSM connection, applying the configuration specific to each supported module kind.
func adaptSlotConnectionData(moduleKind hsmconnector.ModuleKind, hsmConnection *hsmconnection.HSMConnection) (*hsmconnector.SlotConnectionData, *rpcerrors.RPCError) {
	if !hsmconnector.IsModuleSupported(moduleKind) {
		return nil, rpcerrors.NewInternal()
	}
	slotConnectionData := hsmconnector.SlotConnectionData{
		ModuleKind: moduleKind,
	}
	if moduleKind == hsmconnector.SoftHSMModuleKind {
		slotConnectionData.Slot = hsmConnection.Slot.Slot
		slotConnectionData.Pin = hsmConnection.Slot.Pin
	}
	if moduleKind == hsmconnector.AKVModuleKind {
		slotConnectionData.Config.AKV = make([]hsmconnector.AKVConfig, len(hsmConnection.Slot.Config.AKV))
		for i, akvConfigItem := range hsmConnection.Slot.Config.AKV {
			slotConnectionData.Config.AKV[i] = hsmconnector.AKVConfig{
				KeyName:          akvConfigItem.KeyName,
				KeyVersion:       akvConfigItem.KeyVersion,
				KeyPublicAddress: akvConfigItem.KeyPublicAddress,
			}
		}
	}
	if moduleKind == hsmconnector.LKVModuleKind && hsmConnection.Slot.Config.LocalKeyVault != nil {
		slotConnectionData.Config.LocalKeyVault = &hsmconnector.LocalKeyVaultConfig{
			KeyStore: make(map[address.Address]string),
		}
		for addr, privateKey := range hsmConnection.Slot.Config.LocalKeyVault.KeyStore {
			slotConnectionData.Config.LocalKeyVault.KeyStore[addr] = privateKey
		}
	}
	return &slotConnectionData, nil
}

func adaptAccessList(data rpcinfra.SignTXRequestParams) (*hsmconnector.AccessList, *rpcerrors.RPCError) {
	accessList := make(hsmconnector.AccessList, len(data.AccessList))
	for i, entry := range data.AccessList {
		addr, errAddr := address.NewFromHexString(entry.Address)
		if errAddr != nil {
			return nil, rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("invalid [accessList] address: %w", errAddr))
		}
		keys := make([]entities.HexBytes32, len(entry.StorageKeys))
		for j, key := range entry.StorageKeys {
			keyBytes, errKey := entities.NewHexBytes32FromString(key)
			if errKey != nil {
				return nil, rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("invalid [accessList] storageKey: %w", errKey))
			}
			keys[j] = keyBytes
		}
		accessList[i] = hsmconnector.AccessListEntry{
			Address:     addr,
			StorageKeys: keys,
		}
	}
	return &accessList, nil
}

func adaptAuthorizationList(data rpcinfra.SignTXRequestParams) (*hsmconnector.AuthorizationList, *rpcerrors.RPCError) {
	authorizationList := make(hsmconnector.AuthorizationList, len(data.AuthorizationList))
	for i, entry := range data.AuthorizationList {
		addr, errAddr := address.NewFromHexString(entry.Address)
		if errAddr != nil {
			return nil, rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("invalid [authorizationList] address: %w", errAddr))
		}
		keys := make([]entities.HexBytes32, len(entry.StorageKeys))
		for j, key := range entry.StorageKeys {
			keyBytes, errKey := entities.NewHexBytes32FromString(key)
			if errKey != nil {
				return nil, rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("invalid [authorizationList] storageKey: %w", errKey))
			}
			keys[j] = keyBytes
		}
		authorizationList[i] = hsmconnector.AuthorizationListEntry{
			Address:     addr,
			StorageKeys: keys,
		}
	}
	return &authorizationList, nil
}

func adaptEIP4844Fields(data rpcinfra.SignTXRequestParams, signTxInput *hsmconnector.SignTxInput) *rpcerrors.RPCError {
	if data.MaxFeePerBlobGas != nil {
		maxFeePerBlobGas, errMaxFeePerBlobGas := entities.NewHexInt256FromString(*data.MaxFeePerBlobGas)
		if errMaxFeePerBlobGas != nil {
			return rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("invalid [maxFeePerBlobGas]: %w", errMaxFeePerBlobGas))
		}
		signTxInput.MaxFeePerBlobGas = maxFeePerBlobGas
	}

	if len(data.BlobVersionedHashes) > 0 {
		blobVersionedHashes := make([]entities.HexBytes32, len(data.BlobVersionedHashes))
		for i, h := range data.BlobVersionedHashes {
			hash, errHash := entities.NewHexBytes32FromString(h)
			if errHash != nil {
				return rpcerrors.NewInvalidParamsFromErr(fmt.Errorf("invalid [blobVersionedHashes]: %w", errHash))
			}
			blobVersionedHashes[i] = hash
		}
		signTxInput.BlobVersionedHashes = blobVersionedHashes
	}
	return nil
}

// DefaultAPIAdapter implements JSONRPCAPIAdapter.
type DefaultAPIAdapter struct {
	accountUseCase        user.AccountUseCase
	slotUseCase           hsmslot.HSMSlotUseCase
	hsmConnectionResolver hsmconnection.Resolver
	hsmConnector          hsmconnector.HSMConnector
}

// DefaultAPIAdapterOptions options to create a new DefaultAPIAdapter.
type DefaultAPIAdapterOptions struct {
	AccountUseCase        user.AccountUseCase
	SlotUseCase           hsmslot.HSMSlotUseCase
	HSMConnectionResolver hsmconnection.Resolver
	HSMConnector          hsmconnector.HSMConnector
}

// NewDefaultAPIAdapter creates a new DefaultAPIAdapter instance.
func NewDefaultAPIAdapter(options DefaultAPIAdapterOptions) (*DefaultAPIAdapter, error) {
	if options.AccountUseCase == nil {
		return nil, errors.New("mandatory 'AccountUseCase' not provided")
	}
	if options.SlotUseCase == nil {
		return nil, errors.New("mandatory 'SlotUseCase' not provided")
	}
	if options.HSMConnectionResolver == nil {
		return nil, errors.New("mandatory 'Resolver' not provided")
	}
	if options.HSMConnector == nil {
		return nil, errors.New("mandatory 'HSMConnector' not provided")
	}

	return &DefaultAPIAdapter{
		accountUseCase:        options.AccountUseCase,
		slotUseCase:           options.SlotUseCase,
		hsmConnectionResolver: options.HSMConnectionResolver,
		hsmConnector:          options.HSMConnector,
	}, nil
}
