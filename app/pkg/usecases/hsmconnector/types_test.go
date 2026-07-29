package hsmconnector_test

import (
	"math/big"
	"testing"

	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/hsmconnector"

	"github.com/stretchr/testify/require"
)

func TestTransactionHash(t *testing.T) {
	from, err := address.NewFromHexString("0xa2c16184fA76cD6D16685900292683dF905e4Bf2")
	require.NoError(t, err)
	to, err := address.NewFromHexString("0xA4F666f1860D2aCbe49b342C87867754a21dE850")
	require.NoError(t, err)
	gas, err := entities.NewHexUInt64FromString("0x3E8")
	require.NoError(t, err)
	gasPrice, err := entities.NewHexInt256FromString("0x0")
	require.NoError(t, err)
	value, err := entities.NewHexInt256FromString("0x3")
	require.NoError(t, err)
	data, err := entities.NewHexBytesFromString("0x1f170873")
	require.NoError(t, err)
	nonce, err := entities.NewHexUInt64FromString("0x1")
	require.NoError(t, err)
	chainID, err := entities.NewHexInt256FromString("0xAF2C")
	require.NoError(t, err)
	t.Run("regular transaction calling a contract function", func(t *testing.T) {
		// curl -X POST --data '{"jsonrpc":"2.0","method":"eth_signTransaction","params":[{"from": "0xa2c16184fA76cD6D16685900292683dF905e4Bf2","to": "0xA4F666f1860D2aCbe49b342C87867754a21dE850","gas": "0x3E8","gasPrice": "0x0","value": "", "nonce":"0x1", "data": "0x1f170873"}], "id":1}' http://127.0.0.1:4545
		expectedResult := "0xb447535e3c128c431d67aa9f554eb1aeea75966c443adc8c1e7cf64c66be0930"
		tx := hsmconnector.EthereumTransaction{
			From:     from,
			To:       &to,
			Gas:      gas,
			GasPrice: *gasPrice,
			Value:    nil,
			Data:     data,
			Nonce:    nonce,
			ChainID:  *chainID,
		}
		hash, errHash := tx.Hash()
		require.NoError(t, errHash)
		require.Equal(t, expectedResult, hash.Encode())
	})
	t.Run("eth transfer", func(t *testing.T) {
		// curl -X POST --data '{"jsonrpc":"2.0","method":"eth_signTransaction","params":[{"from": "0xa2c16184fA76cD6D16685900292683dF905e4Bf2","to": "0xA4F666f1860D2aCbe49b342C87867754a21dE850","gas": "0x3E8","gasPrice": "0x0","value": "0x3", "nonce":"0x1", "data": ""}], "id":1}' http://127.0.0.1:4545
		// curl -X POST --data '{"jsonrpc":"2.0","method":"eth_signTransaction","params":[{"from": "0xa2c16184fA76cD6D16685900292683dF905e4Bf2","to": "0xA4F666f1860D2aCbe49b342C87867754a21dE850","gas": "0x3E8","gasPrice": "0x0","value": "0x3", "nonce":"0x1", "data": "0x"}], "id":1}' http://127.0.0.1:4545
		expectedResult := "0xf92595a8b712d60156fcbba4be91bfc2ba37bd619e309251dca9992c4214a9f3"
		ethTransferData, errEthTransferData := entities.NewHexBytesFromString("0x")
		require.NoError(t, errEthTransferData)
		tx := hsmconnector.EthereumTransaction{
			From:     from,
			To:       &to,
			Gas:      gas,
			GasPrice: *gasPrice,
			Value:    value,
			Data:     ethTransferData,
			Nonce:    nonce,
			ChainID:  *chainID,
		}
		hash, errHash := tx.Hash()
		require.NoError(t, errHash)
		require.Equal(t, expectedResult, hash.Encode())
	})
	t.Run("smart contract deployment", func(t *testing.T) {
		// curl -X POST --data '{"jsonrpc":"2.0","method":"eth_signTransaction","params":[{"from": "0xa2c16184fA76cD6D16685900292683dF905e4Bf2","to": "","gas": "0x3E8","gasPrice": "0x0","value": "", "nonce":"0x1", "data": "0x1234"}], "id":1}' http://127.0.0.1:4545
		expectedResult := "0x70b0321049331e2bfcdea08da7d72d1fb42554004af1d68bb0ebea221ccbfa89"
		smartContractDeploymentData, errSmartContractDeploymentData := entities.NewHexBytesFromString("0x1234") // this data does not represent a real contract code, but it doesn't matter for the test
		require.NoError(t, errSmartContractDeploymentData)
		tx := hsmconnector.EthereumTransaction{
			From:     from,
			To:       nil,
			Gas:      gas,
			GasPrice: *gasPrice,
			Value:    nil,
			Data:     smartContractDeploymentData,
			Nonce:    nonce,
			ChainID:  *chainID,
		}
		hash, errHash := tx.Hash()
		require.NoError(t, errHash)
		require.Equal(t, expectedResult, hash.Encode())
	})
}

func TestTransactionRLPEncode(t *testing.T) {
	from, err := address.NewFromHexString("0xa2c16184fA76cD6D16685900292683dF905e4Bf2")
	require.NoError(t, err)
	to, err := address.NewFromHexString("0xA4F666f1860D2aCbe49b342C87867754a21dE850")
	require.NoError(t, err)
	gas, err := entities.NewHexUInt64FromString("0x3E8")
	require.NoError(t, err)
	gasPrice, err := entities.NewHexInt256FromString("0x0")
	require.NoError(t, err)
	value, err := entities.NewHexInt256FromString("0x3")
	require.NoError(t, err)
	data, err := entities.NewHexBytesFromString("0x1f170873")
	require.NoError(t, err)
	nonce, err := entities.NewHexUInt64FromString("0x1")
	require.NoError(t, err)
	chainID, err := entities.NewHexInt256FromString("0xAF2C")
	require.NoError(t, err)
	t.Run("regular transaction calling a contract function", func(t *testing.T) {
		// curl -X POST --data '{"jsonrpc":"2.0","method":"eth_signTransaction","params":[{"from": "0xa2c16184fA76cD6D16685900292683dF905e4Bf2","to": "0xA4F666f1860D2aCbe49b342C87867754a21dE850","gas": "0x3E8","gasPrice": "0x0","value": "", "nonce":"0x1", "data": "0x1f170873"}], "id":1}' http://127.0.0.1:4545
		v, err := entities.NewInt256FromString("89723")
		require.NoError(t, err)
		r, err := entities.NewInt256FromString("79512477079584882106035111633848404116979416950828735213289685078694358949790")
		require.NoError(t, err)
		s, err := entities.NewInt256FromString("45246168264644141260702019545370209847284505515724991470579189893676218274159")
		require.NoError(t, err)
		expectedResult := "0xf86601808203e894a4f666f1860d2acbe49b342c87867754a21de85080841f17087383015e7ba0afca779a665f19a43db7d0a2fe00216d17c13b6b222d1a2d26f4fcdcae781f9ea064086c7838f9bb42f1e9a1decbb7fe7352eb91b0c48933fd6a371d404c01516f"
		tx := hsmconnector.EthereumTransaction{
			From:     from,
			To:       &to,
			Gas:      gas,
			GasPrice: *gasPrice,
			Value:    nil,
			Data:     data,
			Nonce:    nonce,
			ChainID:  *chainID,
			Signature: &hsmconnector.EthereumSignature{
				V: *v,
				R: *r,
				S: *s,
			},
		}
		encode, errHash := tx.RLPEncode()
		require.NoError(t, errHash)
		require.Equal(t, expectedResult, encode.Encode())
	})
	t.Run("eth transfer", func(t *testing.T) {
		// curl -X POST --data '{"jsonrpc":"2.0","method":"eth_signTransaction","params":[{"from": "0xa2c16184fA76cD6D16685900292683dF905e4Bf2","to": "0xA4F666f1860D2aCbe49b342C87867754a21dE850","gas": "0x3E8","gasPrice": "0x0","value": "0x3", "nonce":"0x1", "data": ""}], "id":1}' http://127.0.0.1:4545
		// curl -X POST --data '{"jsonrpc":"2.0","method":"eth_signTransaction","params":[{"from": "0xa2c16184fA76cD6D16685900292683dF905e4Bf2","to": "0xA4F666f1860D2aCbe49b342C87867754a21dE850","gas": "0x3E8","gasPrice": "0x0","value": "0x3", "nonce":"0x1", "data": "0x"}], "id":1}' http://127.0.0.1:4545
		v, err := entities.NewInt256FromString("89724")
		require.NoError(t, err)
		r, err := entities.NewInt256FromString("94774623916482581422959855278872599055724170727672632482471005182156164253372")
		require.NoError(t, err)
		s, err := entities.NewInt256FromString("31799423547405788621083374933419361458375000145893750676197899377898211640539")
		require.NoError(t, err)
		expectedResult := "0xf86201808203e894a4f666f1860d2acbe49b342c87867754a21de850038083015e7ca0d188894399de01c5f604e1662176120979e8abdedd22a91524234a611b9346bca0464dd5fe1a80449e636aa970489fb861e250d0ed1daa0790a9f34defd23204db"
		ethTransferData, errEthTransferData := entities.NewHexBytesFromString("0x")
		require.NoError(t, errEthTransferData)
		tx := hsmconnector.EthereumTransaction{
			From:     from,
			To:       &to,
			Gas:      gas,
			GasPrice: *gasPrice,
			Value:    value,
			Data:     ethTransferData,
			Nonce:    nonce,
			ChainID:  *chainID,
			Signature: &hsmconnector.EthereumSignature{
				V: *v,
				R: *r,
				S: *s,
			},
		}
		rlpEncode, errHash := tx.RLPEncode()
		require.NoError(t, errHash)
		require.Equal(t, expectedResult, rlpEncode.Encode())
	})
	t.Run("smart contract deployment", func(t *testing.T) {
		// curl -X POST --data '{"jsonrpc":"2.0","method":"eth_signTransaction","params":[{"from": "0xa2c16184fA76cD6D16685900292683dF905e4Bf2","to": "","gas": "0x3E8","gasPrice": "0x0","value": "", "nonce":"0x1", "data": "0x1234"}], "id":1}' http://127.0.0.1:4545
		expectedResult := "0xf85001808203e8808082123483015e7ca0703a952afe11a318119e6404c73e095ad958c66d388bd4e022d6962e090f8cd7a039c7bd799b7abc0c16f9494f70e8aa049039ad027e7115f7b7c0d01b8cded98b"
		smartContractDeploymentData, errSmartContractDeploymentData := entities.NewHexBytesFromString("0x1234") // this data does not represent a real contract code, but it doesn't matter for the test
		require.NoError(t, errSmartContractDeploymentData)
		v, err := entities.NewInt256FromString("89724")
		require.NoError(t, err)
		r, err := entities.NewInt256FromString("50762545690362991163425142364634718480807891730254839665076114412326832016599")
		require.NoError(t, err)
		s, err := entities.NewInt256FromString("26134742643724068038515311215215637173145069662566716976314116108516983757195")
		require.NoError(t, err)
		tx := hsmconnector.EthereumTransaction{
			From:     from,
			To:       nil,
			Gas:      gas,
			GasPrice: *gasPrice,
			Value:    nil,
			Data:     smartContractDeploymentData,
			Nonce:    nonce,
			ChainID:  *chainID,
			Signature: &hsmconnector.EthereumSignature{
				V: *v,
				R: *r,
				S: *s,
			},
		}
		rlpEncode, errHash := tx.RLPEncode()
		require.NoError(t, errHash)
		require.Equal(t, expectedResult, rlpEncode.Encode())
	})
}

func TestEIP1559TransactionHash(t *testing.T) {
	chainID, err := entities.NewHexInt256FromString("0x1")
	require.NoError(t, err)
	maxPriority, err := entities.NewHexInt256FromString("0x3B9ACA00") // 1 gwei
	require.NoError(t, err)
	maxFee, err := entities.NewHexInt256FromString("0x77359400") // 2 gwei
	require.NoError(t, err)
	gas, err := entities.NewHexUInt64FromString("0x5208") // 21000
	require.NoError(t, err)
	to, err := address.NewFromHexString("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	require.NoError(t, err)
	data, err := entities.NewHexBytesFromString("0x")
	require.NoError(t, err)
	nonce, err := entities.NewHexUInt64FromString("0x0")
	require.NoError(t, err)

	t.Run("ETH transfer produces correct hash", func(t *testing.T) {
		// Expected value computed from keccak256(0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value, data, accessList]))
		const wantHash = "0xca5eec6680fc5e961cd00fd49af7d6c0c3c3bf3e2fb92b297251a6f09eb122a5"
		tx := hsmconnector.EIP1559Transaction{
			ChainID:              *chainID,
			Nonce:                nonce,
			MaxPriorityFeePerGas: *maxPriority,
			MaxFeePerGas:         *maxFee,
			Gas:                  gas,
			To:                   &to,
			Data:                 data,
		}
		hash, errHash := tx.Hash()
		require.NoError(t, errHash)
		require.Equal(t, wantHash, hash.Encode())
	})

	t.Run("contract deployment (nil To) produces hash of correct length", func(t *testing.T) {
		tx := hsmconnector.EIP1559Transaction{
			ChainID:              *chainID,
			Nonce:                nonce,
			MaxPriorityFeePerGas: *maxPriority,
			MaxFeePerGas:         *maxFee,
			Gas:                  gas,
			To:                   nil,
			Data:                 data,
		}
		hash, errHash := tx.Hash()
		require.NoError(t, errHash)
		require.Equal(t, 32, len(hash.Bytes()))
	})
}

func TestEIP1559TransactionRLPEncode(t *testing.T) {
	chainID, err := entities.NewHexInt256FromString("0x1")
	require.NoError(t, err)
	maxPriority, err := entities.NewHexInt256FromString("0x3B9ACA00") // 1 gwei
	require.NoError(t, err)
	maxFee, err := entities.NewHexInt256FromString("0x77359400") // 2 gwei
	require.NoError(t, err)
	gas, err := entities.NewHexUInt64FromString("0x5208") // 21000
	require.NoError(t, err)
	to, err := address.NewFromHexString("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	require.NoError(t, err)
	data, err := entities.NewHexBytesFromString("0x")
	require.NoError(t, err)
	nonce, err := entities.NewHexUInt64FromString("0x0")
	require.NoError(t, err)

	t.Run("signed ETH transfer encodes to expected bytes", func(t *testing.T) {
		// Expected value: 0x02 || rlp([chainId, nonce, maxPriority, maxFee, gas, to, value, data, [], yParity, R, S])
		// Computed via independent reference implementation.
		const wantEncoded = "0x02ea0180843b9aca00847735940082520894cccccccccccccccccccccccccccccccccccccccc8080c0800102"

		yParity := entities.NewInt256(big.NewInt(0))
		r := entities.NewInt256(big.NewInt(1))
		s := entities.NewInt256(big.NewInt(2))

		tx := hsmconnector.EIP1559Transaction{
			ChainID:              *chainID,
			Nonce:                nonce,
			MaxPriorityFeePerGas: *maxPriority,
			MaxFeePerGas:         *maxFee,
			Gas:                  gas,
			To:                   &to,
			Data:                 data,
			Signature: &hsmconnector.EIP1559TransactionSignature{
				YParity: *yParity,
				R:       *r,
				S:       *s,
			},
		}
		encoded, errEncode := tx.RLPEncode()
		require.NoError(t, errEncode)
		require.Equal(t, wantEncoded, encoded.Encode())
	})

	t.Run("RLPEncode without signature returns error", func(t *testing.T) {
		tx := hsmconnector.EIP1559Transaction{
			ChainID:              *chainID,
			Nonce:                nonce,
			MaxPriorityFeePerGas: *maxPriority,
			MaxFeePerGas:         *maxFee,
			Gas:                  gas,
			To:                   &to,
			Data:                 data,
		}
		_, err := tx.RLPEncode()
		require.Error(t, err)
	})
}
