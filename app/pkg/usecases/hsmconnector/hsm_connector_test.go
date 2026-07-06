package hsmconnector_test

import (
	"context"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/hyperledger-labs/signare/app/pkg/commons/validators"
	"github.com/hyperledger-labs/signare/app/pkg/entities"
	"github.com/hyperledger-labs/signare/app/pkg/entities/address"
	"github.com/hyperledger-labs/signare/app/pkg/graph"
	"github.com/hyperledger-labs/signare/app/pkg/internal/errors"
	"github.com/hyperledger-labs/signare/app/pkg/usecases/application"
	"github.com/hyperledger-labs/signare/app/pkg/usecases/hsmconnector"
	"github.com/hyperledger-labs/signare/app/pkg/usecases/hsmmodule"
	"github.com/hyperledger-labs/signare/app/pkg/usecases/hsmslot"
	"github.com/hyperledger-labs/signare/app/test/dbtesthelper"
	"github.com/hyperledger-labs/signare/app/test/signaturemanagertesthelper"

	"github.com/stretchr/testify/require"
)

var (
	app    graph.GraphShared
	slotID string
	ctx    context.Context

	applicationID = "my-app"
	moduleID      = "module-id"
	chainID       = entities.NewInt256FromInt(44844)
	chainIDHex    = entities.NewHexInt256(big.NewInt(44844))
	validAddress  = address.MustNewFromHexString("0x970e8128ab834e8eac17ab8e3812f010678cf791")
	slotPin       = signaturemanagertesthelper.SlotPin
)

func TestMain(m *testing.M) {
	initializedSlotID, _, err := signaturemanagertesthelper.InitializeSoftHSMSlot()
	if err != nil {
		panic(err)
	}
	slotID = *initializedSlotID

	a, err := dbtesthelper.InitializeApp()
	if err != nil {
		panic(err)
	}
	app = *a

	ctx = context.Background()
	err = provisionTest(ctx)
	if err != nil {
		panic(err)
	}

	validators.SetValidators()
	os.Exit(m.Run())
}

func TestProvideDefaultUseCase(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		options := hsmconnector.DefaultUseCaseOptions{
			DigitalSignatureManagerFactory: app.DigitalSignatureManagerFactory,
		}
		defaultUseCase, err := hsmconnector.ProvideDefaultHSMConnector(options)
		require.NoError(t, err)
		require.NotNil(t, defaultUseCase)
	})
	t.Run("nil digitalSignatureManagerFactory", func(t *testing.T) {
		options := hsmconnector.DefaultUseCaseOptions{
			DigitalSignatureManagerFactory: nil,
		}
		defaultUseCase, err := hsmconnector.ProvideDefaultHSMConnector(options)
		require.Error(t, err)
		require.Nil(t, defaultUseCase)
	})

}

func TestDefaultUseCase_GenerateAddress(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		generateAddressInput := hsmconnector.GenerateAddressInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
		}
		generateAddressOutput, generateAddressErr := app.HSMConnector.GenerateAddress(ctx, generateAddressInput)
		require.NoError(t, generateAddressErr)
		require.NotNil(t, generateAddressOutput)

		// Clean up the created resource
		removeAddressInput := hsmconnector.RemoveAddressInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			Address: generateAddressOutput.Address,
		}
		removeAddressOutput, removeAddressErr := app.HSMConnector.RemoveAddress(ctx, removeAddressInput)
		require.NoError(t, removeAddressErr)
		require.NotNil(t, removeAddressOutput)
	})

	t.Run("failure: invalid input arguments", func(t *testing.T) {
		generateAddressInput := hsmconnector.GenerateAddressInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: "invalid module kind",
			},
		}
		generateAddressOutput, generateAddressErr := app.HSMConnector.GenerateAddress(ctx, generateAddressInput)
		require.Error(t, generateAddressErr)
		require.True(t, errors.IsInvalidArgument(generateAddressErr))
		require.Nil(t, generateAddressOutput)
	})
}

func TestDefaultUseCase_RemoveAddress(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		createAddressInput := hsmconnector.GenerateAddressInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
		}
		createAddressOutput, createAddressErr := app.HSMConnector.GenerateAddress(ctx, createAddressInput)
		require.NoError(t, createAddressErr)
		require.NotNil(t, createAddressOutput)

		removeAddressInput := hsmconnector.RemoveAddressInput{
			Address: createAddressOutput.Address,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
		}
		removeAddressOutput, removeAddressErr := app.HSMConnector.RemoveAddress(ctx, removeAddressInput)
		require.NoError(t, removeAddressErr)
		require.NotNil(t, removeAddressOutput)
	})

	t.Run("failure: invalid input arguments", func(t *testing.T) {
		removeAddressInput := hsmconnector.RemoveAddressInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: "invalid type",
			},
			Address: validAddress,
		}
		removeAddressOutput, removeAddressErr := app.HSMConnector.RemoveAddress(ctx, removeAddressInput)
		require.Error(t, removeAddressErr)
		require.True(t, errors.IsInvalidArgument(removeAddressErr))
		require.Nil(t, removeAddressOutput)

		removeAddressInput = hsmconnector.RemoveAddressInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			Address: address.ZeroAddress,
		}
		removeAddressOutput, removeAddressErr = app.HSMConnector.RemoveAddress(ctx, removeAddressInput)
		require.Error(t, removeAddressErr)
		require.True(t, errors.IsInvalidArgument(removeAddressErr))
		require.Nil(t, removeAddressOutput)
	})

	t.Run("failure: address doesn't exist", func(t *testing.T) {
		removeAddressInput := hsmconnector.RemoveAddressInput{
			Address: validAddress,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
		}
		removeAddressOutput, removeAddressErr := app.HSMConnector.RemoveAddress(ctx, removeAddressInput)
		require.Error(t, removeAddressErr)
		require.True(t, errors.IsNotFound(removeAddressErr))
		require.Nil(t, removeAddressOutput)
	})
}

func TestDefaultUseCase_ListAddress(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		createAddressInput := hsmconnector.GenerateAddressInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
		}
		createAddressOutputOne, createAddressOneErr := app.HSMConnector.GenerateAddress(ctx, createAddressInput)
		require.NoError(t, createAddressOneErr)
		require.NotNil(t, createAddressOutputOne)

		createAddressOutputTwo, createAddressTwoErr := app.HSMConnector.GenerateAddress(ctx, createAddressInput)
		require.NoError(t, createAddressTwoErr)
		require.NotNil(t, createAddressOutputTwo)
		listAddressInput := hsmconnector.ListAddressesInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
		}

		listAddressOutput, listAddressErr := app.HSMConnector.ListAddresses(ctx, listAddressInput)
		require.NoError(t, listAddressErr)
		require.NotNil(t, listAddressOutput)
		require.NotEmpty(t, listAddressOutput.Items)

		defaultLoadedAddressIncluded := false
		addressOneIncluded := false
		addressTwoIncluded := false
		for _, addr := range listAddressOutput.Items {
			if addr.String() == createAddressOutputOne.Address.String() {
				addressOneIncluded = true
			}
			if addr.String() == createAddressOutputTwo.Address.String() {
				addressTwoIncluded = true
			}
			if addr.String() == signaturemanagertesthelper.ImportedKeyAddress {
				defaultLoadedAddressIncluded = true
			}
		}
		require.True(t, addressOneIncluded)
		require.True(t, addressTwoIncluded)
		require.True(t, defaultLoadedAddressIncluded)
	})

	t.Run("failure: invalid input arguments", func(t *testing.T) {
		listAddressInput := hsmconnector.ListAddressesInput{
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: "invalid module kind",
			},
		}
		listAddressOutput, listAddressErr := app.HSMConnector.ListAddresses(ctx, listAddressInput)
		require.Error(t, listAddressErr)
		require.True(t, errors.IsInvalidArgument(listAddressErr))
		require.Nil(t, listAddressOutput)
	})
}

func TestDefaultUseCase_SignTx(t *testing.T) {
	toAddress := address.MustNewFromHexString("0xA4F666f1860D2aCbe49b342C87867754a21dE850")
	gasPrice := big.NewInt(20)
	value := big.NewInt(3)
	nonce := entities.UInt64(1)

	t.Run("success: legacy transaction filled values", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873")) // simpleMethod()
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas: &entities.HexUInt64{
				UInt64: 1000,
			},
			GasPrice: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *gasPrice,
				},
			},
			Value: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *value,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.NoError(t, err)
		require.NotNil(t, signTxOutput)
	})
	t.Run("success: legacy transaction defaults for optional values", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x"))
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From:     address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:       &toAddress,
			Gas:      nil,
			GasPrice: nil,
			Value:    nil,
			Data:     *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.NoError(t, err)
		require.NotNil(t, signTxOutput)
	})
	t.Run("success: smart contract deployment (nil to address)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1234"))
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   nil,
			Gas: &entities.HexUInt64{
				UInt64: 1000,
			},
			GasPrice: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *gasPrice,
				},
			},
			Value: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *value,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.NoError(t, err)
		require.NotNil(t, signTxOutput)
	})

	t.Run("success: EIP-1559 transaction with all fields filled", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		maxPriorityFeePerGas := big.NewInt(10)
		storageKey := entities.HexBytes32{}
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas: &entities.HexUInt64{
				UInt64: 1000,
			},
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			Value: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *value,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{
				{
					Address:     toAddress,
					StorageKeys: []entities.HexBytes32{storageKey},
				},
			},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.NoError(t, err)
		require.NotNil(t, signTxOutput)
		require.NotNil(t, signTxOutput.EIP1559Tx)
		require.NotEmpty(t, signTxOutput.SignedTx)
	})

	t.Run("success: EIP-1559 transaction with nil To (contract deployment)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1234"))
		maxFeePerGas := big.NewInt(100)
		maxPriorityFeePerGas := big.NewInt(10)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   nil,
			Gas: &entities.HexUInt64{
				UInt64: 1000,
			},
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			Value: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *value,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.NoError(t, err)
		require.NotNil(t, signTxOutput)
		require.NotNil(t, signTxOutput.EIP1559Tx)
		require.Nil(t, signTxOutput.EIP1559Tx.To)
	})

	t.Run("success: EIP-1559 transaction with default gas", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		maxPriorityFeePerGas := big.NewInt(10)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas:  nil,
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.NoError(t, err)
		require.NotNil(t, signTxOutput)
		require.NotNil(t, signTxOutput.EIP1559Tx)
	})

	t.Run("success: EIP-1559 transaction with nil value", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		maxPriorityFeePerGas := big.NewInt(10)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas: &entities.HexUInt64{
				UInt64: 1000,
			},
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			Value: nil,
			Data:  *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.NoError(t, err)
		require.NotNil(t, signTxOutput)
		require.NotNil(t, signTxOutput.EIP1559Tx)
	})

	t.Run("success: EIP-1559 transaction with empty access list", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		maxPriorityFeePerGas := big.NewInt(10)
		storageKey2 := entities.HexBytes32{}
		storageKey2[31] = 0x01
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas: &entities.HexUInt64{
				UInt64: 2000,
			},
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			Value: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *value,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.NoError(t, err)
		require.NotNil(t, signTxOutput)
		require.NotNil(t, signTxOutput.EIP1559Tx)
		require.Len(t, signTxOutput.EIP1559Tx.AccessList, 0)
	})

	t.Run("success: EIP-1559 transaction with populated access list", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		maxPriorityFeePerGas := big.NewInt(10)
		storageKey1 := entities.HexBytes32{}
		storageKey2 := entities.HexBytes32{}
		storageKey2[31] = 0x01
		anotherAddress := address.MustNewFromHexString("0x1234567890abcdef1234567890abcdef12345678")
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas: &entities.HexUInt64{
				UInt64: 2000,
			},
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			Value: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *value,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{
				{
					Address:     toAddress,
					StorageKeys: []entities.HexBytes32{storageKey1, storageKey2},
				},
				{
					Address:     anotherAddress,
					StorageKeys: []entities.HexBytes32{},
				},
			},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.NoError(t, err)
		require.NotNil(t, signTxOutput)
		require.NotNil(t, signTxOutput.EIP1559Tx)
		require.Len(t, signTxOutput.EIP1559Tx.AccessList, 2)
	})

	t.Run("success: EIP-1559 output contains valid signature fields", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		maxPriorityFeePerGas := big.NewInt(10)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas: &entities.HexUInt64{
				UInt64: 1000,
			},
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			Value: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *value,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.NoError(t, err)
		require.NotNil(t, signTxOutput)
		require.NotNil(t, signTxOutput.EIP1559Tx)
		require.NotNil(t, signTxOutput.EIP1559Tx.Signature)
		// YParity should be 0 or 1 for EIP-1559
		yParity := signTxOutput.EIP1559Tx.Signature.YParity.Int64()
		require.True(t, yParity == 0 || yParity == 1, "YParity should be 0 or 1, got %d", yParity)
		// R and S should be non-zero
		require.NotEqual(t, big.NewInt(0), &signTxOutput.EIP1559Tx.Signature.R.Int)
		require.NotEqual(t, big.NewInt(0), &signTxOutput.EIP1559Tx.Signature.S.Int)
	})

	t.Run("success: EIP-1559 output preserves input fields correctly", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		maxPriorityFeePerGas := big.NewInt(10)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas: &entities.HexUInt64{
				UInt64: 5000,
			},
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			Value: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *value,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.NoError(t, err)
		require.NotNil(t, signTxOutput)
		require.NotNil(t, signTxOutput.EIP1559Tx)
		require.Equal(t, signTxInput.From.String(), signTxOutput.EIP1559Tx.From.String())
		require.Equal(t, signTxInput.To.String(), signTxOutput.EIP1559Tx.To.String())
		require.Equal(t, entities.UInt64(5000), signTxOutput.EIP1559Tx.Gas.UInt64)
		require.Equal(t, int64(100), signTxOutput.EIP1559Tx.MaxFeePerGas.Int64())
		require.Equal(t, int64(10), signTxOutput.EIP1559Tx.MaxPriorityFeePerGas.Int64())
		require.Equal(t, nonce, signTxOutput.EIP1559Tx.Nonce.UInt64)
	})

	t.Run("success: EIP-1559 signed tx has type 2 prefix", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		maxPriorityFeePerGas := big.NewInt(10)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas: &entities.HexUInt64{
				UInt64: 1000,
			},
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.NoError(t, err)
		require.NotNil(t, signTxOutput)
		require.NotEmpty(t, signTxOutput.SignedTx)
		require.True(t, len(signTxOutput.SignedTx) > 4, "signed tx should not be empty")
		// EIP-1559 (Type 2) transactions should start with 0x02
		require.True(t, strings.HasPrefix(signTxOutput.SignedTx, "0x02"))
	})

	t.Run("failure: gasPrice field and EIP-1559 fields set", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		maxPriorityFeePerGas := big.NewInt(10)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas: &entities.HexUInt64{
				UInt64: 1000,
			},
			GasPrice: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *gasPrice,
				},
			},
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			Value: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *value,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
	})

	t.Run("success: neither legacy nor EIP-1559 (no gas pricing fields)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From:     address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:       &toAddress,
			GasPrice: nil,
			Data:     *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.NoError(t, err)
		require.NotNil(t, signTxOutput)
		require.NotNil(t, signTxOutput.Transaction)
	})

	t.Run("failure: partial EIP-1559 fields (only MaxFeePerGas)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
	})

	t.Run("failure: partial EIP-1559 fields (only MaxPriorityFeePerGas)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxPriorityFeePerGas := big.NewInt(10)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
	})

	t.Run("failure: partial EIP-1559 fields (MaxFeePerGas and MaxPriorityFeePerGas but no AccessList)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		maxPriorityFeePerGas := big.NewInt(10)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
	})

	t.Run("failure: type 1 (EIP-2930) transaction is not supported", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas: &entities.HexUInt64{
				UInt64: 1000,
			},
			GasPrice: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *gasPrice,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
		useCaseErr, ok := errors.CastAsUseCaseError(err)
		require.True(t, ok)
		require.NotNil(t, useCaseErr.HumanReadableMessage())
		require.Equal(t, "Not supported transaction type", *useCaseErr.HumanReadableMessage())
	})

	t.Run("failure: type 1 (EIP-2930) transaction is not supported (non-empty AccessList)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		storageKey := entities.HexBytes32{}
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas: &entities.HexUInt64{
				UInt64: 1000,
			},
			GasPrice: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *gasPrice,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{
				{
					Address:     toAddress,
					StorageKeys: []entities.HexBytes32{storageKey},
				},
			},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
		useCaseErr, ok := errors.CastAsUseCaseError(err)
		require.True(t, ok)
		require.NotNil(t, useCaseErr.HumanReadableMessage())
		require.Equal(t, "Not supported transaction type", *useCaseErr.HumanReadableMessage())
	})

	t.Run("failure: type 3 (EIP-4844) transaction is not supported (MaxFeePerBlobGas field is not nil)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		maxPriorityFeePerGas := big.NewInt(10)
		maxFeePerBlobGas := big.NewInt(1)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas: &entities.HexUInt64{
				UInt64: 1000,
			},
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			MaxFeePerBlobGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerBlobGas,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
		useCaseErr, ok := errors.CastAsUseCaseError(err)
		require.True(t, ok)
		require.NotNil(t, useCaseErr.HumanReadableMessage())
		require.Equal(t, "Not supported transaction type", *useCaseErr.HumanReadableMessage())
	})

	t.Run("failure: type 3 (EIP-4844) transaction is not supported (BlobVersionedHashes field is not nil)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		maxPriorityFeePerGas := big.NewInt(10)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas: &entities.HexUInt64{
				UInt64: 1000,
			},
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			BlobVersionedHashes: []entities.HexBytes32{{}},
			Data:                *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
		useCaseErr, ok := errors.CastAsUseCaseError(err)
		require.True(t, ok)
		require.NotNil(t, useCaseErr.HumanReadableMessage())
		require.Equal(t, "Not supported transaction type", *useCaseErr.HumanReadableMessage())
	})

	t.Run("failure: type 3 (EIP-4844) transaction is not supported (BlobVersionedHashes and MaxFeePerBlobGas fields are not nil)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		maxPriorityFeePerGas := big.NewInt(10)
		maxFeePerBlobGas := big.NewInt(1)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas: &entities.HexUInt64{
				UInt64: 1000,
			},
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			MaxFeePerBlobGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerBlobGas,
				},
			},
			BlobVersionedHashes: []entities.HexBytes32{{}},
			Data:                *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
		useCaseErr, ok := errors.CastAsUseCaseError(err)
		require.True(t, ok)
		require.NotNil(t, useCaseErr.HumanReadableMessage())
		require.Equal(t, "Not supported transaction type", *useCaseErr.HumanReadableMessage())
	})

	t.Run("failure: type 3 (EIP-4844) transaction is not supported (MaxFeePerBlobGas is zero but not nil)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		maxPriorityFeePerGas := big.NewInt(10)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas: &entities.HexUInt64{
				UInt64: 1000,
			},
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			MaxFeePerBlobGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *big.NewInt(0),
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
		useCaseErr, ok := errors.CastAsUseCaseError(err)
		require.True(t, ok)
		require.NotNil(t, useCaseErr.HumanReadableMessage())
		require.Equal(t, "Not supported transaction type", *useCaseErr.HumanReadableMessage())
	})

	t.Run("failure: type 4 (EIP-7702) transaction is not supported (AuthorizationList field is not nil)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		maxPriorityFeePerGas := big.NewInt(10)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas: &entities.HexUInt64{
				UInt64: 1000,
			},
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList:        hsmconnector.AccessList{},
			AuthorizationList: hsmconnector.AuthorizationList{},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
		useCaseErr, ok := errors.CastAsUseCaseError(err)
		require.True(t, ok)
		require.NotNil(t, useCaseErr.HumanReadableMessage())
		require.Equal(t, "Not supported transaction type", *useCaseErr.HumanReadableMessage())
	})
	t.Run("failure: type 4 (EIP-7702) transaction is not supported (non-empty AuthorizationList)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		maxPriorityFeePerGas := big.NewInt(10)
		storageKey := entities.HexBytes32{}
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			Gas: &entities.HexUInt64{
				UInt64: 1000,
			},
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{},
			AuthorizationList: hsmconnector.AuthorizationList{
				{
					Address:     toAddress,
					StorageKeys: []entities.HexBytes32{storageKey},
				},
			},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
		useCaseErr, ok := errors.CastAsUseCaseError(err)
		require.True(t, ok)
		require.NotNil(t, useCaseErr.HumanReadableMessage())
		require.Equal(t, "Not supported transaction type", *useCaseErr.HumanReadableMessage())
	})

	t.Run("failure: ambiguous transaction type (GasPrice and MaxFeePerGas are set)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			GasPrice: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *gasPrice,
				},
			},
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
		useCaseErr, ok := errors.CastAsUseCaseError(err)
		require.True(t, ok)
		require.NotNil(t, useCaseErr.HumanReadableMessage())
		require.Equal(t, "Could not determine transaction type", *useCaseErr.HumanReadableMessage())
	})

	t.Run("failure: ambiguous transaction type (GasPrice and MaxPriorityFeePerGas are set)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxPriorityFeePerGas := big.NewInt(10)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			GasPrice: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *gasPrice,
				},
			},
			MaxPriorityFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxPriorityFeePerGas,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
		useCaseErr, ok := errors.CastAsUseCaseError(err)
		require.True(t, ok)
		require.NotNil(t, useCaseErr.HumanReadableMessage())
		require.Equal(t, "Could not determine transaction type", *useCaseErr.HumanReadableMessage())
	})

	t.Run("failure: ambiguous transaction type (GasPrice and MaxFeePerBlobGas are set)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerBlobGas := big.NewInt(1)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			GasPrice: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *gasPrice,
				},
			},
			MaxFeePerBlobGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerBlobGas,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
		useCaseErr, ok := errors.CastAsUseCaseError(err)
		require.True(t, ok)
		require.NotNil(t, useCaseErr.HumanReadableMessage())
		require.Equal(t, "Could not determine transaction type", *useCaseErr.HumanReadableMessage())
	})

	t.Run("failure: ambiguous transaction type (GasPrice and BlobVersionedHashes are set)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			GasPrice: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *gasPrice,
				},
			},
			BlobVersionedHashes: []entities.HexBytes32{{}},
			Data:                *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
		useCaseErr, ok := errors.CastAsUseCaseError(err)
		require.True(t, ok)
		require.NotNil(t, useCaseErr.HumanReadableMessage())
		require.Equal(t, "Could not determine transaction type", *useCaseErr.HumanReadableMessage())
	})

	t.Run("failure: ambiguous transaction type (GasPrice and AuthorizationList are set)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			GasPrice: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *gasPrice,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AuthorizationList: hsmconnector.AuthorizationList{},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
		useCaseErr, ok := errors.CastAsUseCaseError(err)
		require.True(t, ok)
		require.NotNil(t, useCaseErr.HumanReadableMessage())
		require.Equal(t, "Could not determine transaction type", *useCaseErr.HumanReadableMessage())
	})

	t.Run("failure: ambiguous transaction type (GasPrice, MaxFeePerGas and AccessList are set)", func(t *testing.T) {
		data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
		maxFeePerGas := big.NewInt(100)
		signTxInput := hsmconnector.SignTxInput{
			ChainID: *chainIDHex,
			SlotConnectionData: hsmconnector.SlotConnectionData{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			},
			From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
			To:   &toAddress,
			GasPrice: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *gasPrice,
				},
			},
			MaxFeePerGas: &entities.HexInt256{
				Int256: entities.Int256{
					Int: *maxFeePerGas,
				},
			},
			Data: *data,
			Nonce: entities.HexUInt64{
				UInt64: nonce,
			},
			AccessList: hsmconnector.AccessList{},
		}
		signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
		require.Error(t, err)
		require.True(t, errors.IsInvalidArgument(err))
		require.Nil(t, signTxOutput)
		useCaseErr, ok := errors.CastAsUseCaseError(err)
		require.True(t, ok)
		require.NotNil(t, useCaseErr.HumanReadableMessage())
		require.Equal(t, "Could not determine transaction type", *useCaseErr.HumanReadableMessage())
	})

}

// TestDefaultUseCase_SignTx_RejectsNonPositiveChainID guards CRY-2/UC-5: a non-positive chain ID
// (reachable via the request-level chainId override even when the application's default is valid)
// must be rejected for every transaction type, before any hash is computed or signature emitted.
func TestDefaultUseCase_SignTx_RejectsNonPositiveChainID(t *testing.T) {
	toAddress := address.MustNewFromHexString("0xA4F666f1860D2aCbe49b342C87867754a21dE850")
	gasPrice := big.NewInt(20)
	maxFeePerGas := big.NewInt(100)
	maxPriorityFeePerGas := big.NewInt(10)
	data := entities.NewHexBytes(hexStringToBytes("0x1f170873"))
	nonce := entities.HexUInt64{UInt64: 1}
	from := address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress)
	slot := hsmconnector.SlotConnectionData{
		Slot:       slotID,
		Pin:        slotPin,
		ModuleKind: hsmconnector.SoftHSMModuleKind,
	}

	for _, invalid := range []*big.Int{big.NewInt(0), big.NewInt(-1)} {
		invalid := invalid
		chainID := entities.HexInt256{Int256: entities.Int256{Int: *invalid}}

		t.Run("legacy chainID "+invalid.String(), func(t *testing.T) {
			signTxInput := hsmconnector.SignTxInput{
				ChainID:            chainID,
				SlotConnectionData: slot,
				From:               from,
				To:                 &toAddress,
				GasPrice:           &entities.HexInt256{Int256: entities.Int256{Int: *gasPrice}},
				Data:               *data,
				Nonce:              nonce,
			}
			signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
			require.Error(t, err)
			require.True(t, errors.IsInvalidArgument(err))
			require.Nil(t, signTxOutput)
		})

		t.Run("EIP-1559 chainID "+invalid.String(), func(t *testing.T) {
			signTxInput := hsmconnector.SignTxInput{
				ChainID:              chainID,
				SlotConnectionData:   slot,
				From:                 from,
				To:                   &toAddress,
				MaxFeePerGas:         &entities.HexInt256{Int256: entities.Int256{Int: *maxFeePerGas}},
				MaxPriorityFeePerGas: &entities.HexInt256{Int256: entities.Int256{Int: *maxPriorityFeePerGas}},
				Data:                 *data,
				Nonce:                nonce,
			}
			signTxOutput, err := app.HSMConnector.SignTx(ctx, signTxInput)
			require.Error(t, err)
			require.True(t, errors.IsInvalidArgument(err))
			require.Nil(t, signTxOutput)
		})
	}
}

func hexStringToBytes(input string) []byte {
	if len(input) == 0 {
		panic("empty string")
	}
	if !has0xPrefix(input) {
		panic("missing '0x' prefix")
	}
	b, err := hex.DecodeString(input[2:])
	if err != nil {
		panic(err.Error())
	}
	return b
}

func has0xPrefix(input string) bool {
	return len(input) >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')
}

func provisionTest(ctx context.Context) error {
	createApplicationInput := application.CreateApplicationInput{
		ID:      &applicationID,
		ChainID: *chainID,
	}
	_, err := app.ApplicationUseCase.CreateApplication(ctx, createApplicationInput)
	if err != nil {
		return err
	}

	createModuleInput := hsmmodule.CreateHSMModuleInput{
		ID: &moduleID,
		Configuration: hsmmodule.HSMModuleConfiguration{
			SoftHSMConfiguration: &hsmmodule.SoftHSMConfiguration{},
		},
		ModuleKind: hsmmodule.SoftHSMModuleKind,
	}
	_, err = app.HSMModuleUseCase.CreateHSMModule(ctx, createModuleInput)
	if err != nil {
		return err
	}

	createSlotInput := hsmslot.CreateHSMSlotInput{
		ApplicationID: applicationID,
		HSMModuleID:   moduleID,
		Slot:          slotID,
		Pin:           slotPin,
	}
	_, err = app.HSMSlotUseCase.CreateHSMSlot(ctx, createSlotInput)
	if err != nil {
		return err
	}
	return nil
}

func Benchmark_Concurrent_SignTx(b *testing.B) {
	var wg sync.WaitGroup
	errs := make([]error, 0)
	toAddress := address.MustNewFromHexString("0xA4F666f1860D2aCbe49b342C87867754a21dE850")
	gasPrice := big.NewInt(20)
	value := big.NewInt(3)
	nonce := entities.UInt64(1)

	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data := entities.NewHexBytes(hexStringToBytes("0x1f170873")) // simpleMethod()
			signTxInput := hsmconnector.SignTxInput{
				ChainID: *chainIDHex,
				SlotConnectionData: hsmconnector.SlotConnectionData{
					Slot:       slotID,
					Pin:        slotPin,
					ModuleKind: hsmconnector.SoftHSMModuleKind,
				},
				From: address.MustNewFromHexString(signaturemanagertesthelper.ImportedKeyAddress),
				To:   &toAddress,
				Gas: &entities.HexUInt64{
					UInt64: 1000,
				},
				GasPrice: &entities.HexInt256{
					Int256: entities.Int256{
						Int: *gasPrice,
					},
				},
				Value: &entities.HexInt256{
					Int256: entities.Int256{
						Int: *value,
					},
				},
				Data: *data,
				Nonce: entities.HexUInt64{
					UInt64: nonce,
				},
			}
			_, err := app.HSMConnector.SignTx(ctx, signTxInput)
			if err != nil {
				errs = append(errs, err)
			}
		}()
	}
	wg.Wait()
	require.Empty(b, errs)
}

func Benchmark_Concurrent_GenerateAddress(b *testing.B) {
	var wg sync.WaitGroup
	errs := make([]error, 0)
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			generateAddressInput := hsmconnector.GenerateAddressInput{
				SlotConnectionData: hsmconnector.SlotConnectionData{
					Slot:       slotID,
					Pin:        slotPin,
					ModuleKind: hsmconnector.SoftHSMModuleKind,
				},
			}
			_, err := app.HSMConnector.GenerateAddress(ctx, generateAddressInput)
			if err != nil {
				errs = append(errs, err)
			}
		}()
	}
	wg.Wait()
	require.Empty(b, errs)
}

func Benchmark_Concurrent_RemoveAddress(b *testing.B) {
	var wg sync.WaitGroup
	errs := make([]error, 0)
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			generateAddressInput := hsmconnector.GenerateAddressInput{
				SlotConnectionData: hsmconnector.SlotConnectionData{
					Slot:       slotID,
					Pin:        slotPin,
					ModuleKind: hsmconnector.SoftHSMModuleKind,
				},
			}
			generateAddressOutput, err := app.HSMConnector.GenerateAddress(ctx, generateAddressInput)
			if err != nil {
				errs = append(errs, err)
			}

			removeAddressInput := hsmconnector.RemoveAddressInput{
				SlotConnectionData: hsmconnector.SlotConnectionData{
					Slot:       slotID,
					Pin:        slotPin,
					ModuleKind: hsmconnector.SoftHSMModuleKind,
				},
				Address: generateAddressOutput.Address,
			}
			_, err = app.HSMConnector.RemoveAddress(ctx, removeAddressInput)
			if err != nil {
				errs = append(errs, err)
			}
		}()
	}
	wg.Wait()
	require.Empty(b, errs)
}

func Benchmark_Concurrent_ListAddresses(b *testing.B) {
	var wg sync.WaitGroup
	errs := make([]error, 0)
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			createAddressInput := hsmconnector.GenerateAddressInput{
				SlotConnectionData: hsmconnector.SlotConnectionData{
					Slot:       slotID,
					Pin:        slotPin,
					ModuleKind: hsmconnector.SoftHSMModuleKind,
				},
			}
			_, err := app.HSMConnector.GenerateAddress(ctx, createAddressInput)
			if err != nil {
				errs = append(errs, err)
			}

			_, err = app.HSMConnector.GenerateAddress(ctx, createAddressInput)
			if err != nil {
				errs = append(errs, err)
			}
			listAddressInput := hsmconnector.ListAddressesInput{
				SlotConnectionData: hsmconnector.SlotConnectionData{
					Slot:       slotID,
					Pin:        slotPin,
					ModuleKind: hsmconnector.SoftHSMModuleKind,
				},
			}

			_, err = app.HSMConnector.ListAddresses(ctx, listAddressInput)
			if err != nil {
				errs = append(errs, err)
			}
		}()
	}
	wg.Wait()
	require.Empty(b, errs)
}

func Benchmark_Concurrent_IsAlive(b *testing.B) {
	var wg sync.WaitGroup
	errs := make([]error, 0)
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			isAliveInput := hsmconnector.IsAliveInput{
				Slot:       slotID,
				Pin:        slotPin,
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			}
			_, err := app.HSMConnector.IsAlive(ctx, isAliveInput)
			if err != nil {
				errs = append(errs, err)
			}
		}()
	}
	wg.Wait()
	require.Empty(b, errs)
}

func Benchmark_Concurrent_Reset(b *testing.B) {
	var wg sync.WaitGroup
	errs := make([]error, 0)
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resetInput := hsmconnector.ResetInput{
				ModuleKind: hsmconnector.SoftHSMModuleKind,
			}
			_, err := app.HSMConnector.Reset(ctx, resetInput)
			if err != nil {
				errs = append(errs, err)
			}
		}()
	}
	wg.Wait()
	require.Empty(b, errs)
}
