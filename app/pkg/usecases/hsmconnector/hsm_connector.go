package hsmconnector

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/asaskevich/govalidator"
	btcececdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"

	"github.com/lfdt-smoot/signare/app/pkg/commons/logger"
	"github.com/lfdt-smoot/signare/app/pkg/commons/metricrecorder"
	"github.com/lfdt-smoot/signare/app/pkg/entities"
	"github.com/lfdt-smoot/signare/app/pkg/entities/address"
	"github.com/lfdt-smoot/signare/app/pkg/internal/errors"
	"github.com/lfdt-smoot/signare/app/pkg/signaturemanager"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/eip191"
	"github.com/lfdt-smoot/signare/app/pkg/usecases/eip712"
)

// HSMConnector connects with the HSM and operates with it.
type HSMConnector interface {
	// GenerateAddress generates a key pair in the underlying signature manager and returns the Ethereum address or an error if it fails.
	GenerateAddress(ctx context.Context, input GenerateAddressInput) (*GenerateAddressOutput, error)
	// DeriveAddressFromPrivateKey generates an address from an ethereum private key and returns an Ethereum address or an error if it fails.
	DeriveAddressFromPrivateKey(ctx context.Context, input DeriveAddressFromPrivateKeyInput) (*DeriveAddressFromPrivateKeyOutput, error)
	// RemoveAddress removes the key pair associated with the given Ethereum address.
	RemoveAddress(ctx context.Context, input RemoveAddressInput) (*RemoveAddressOutput, error)
	// ListAddresses lists the addresses associated with their corresponding key pairs that exist in all the slots of an application.
	ListAddresses(ctx context.Context, input ListAddressesInput) (*ListAddressesOutput, error)
	// SignTx signs an Ethereum transaction using the private key associated with the address specific in the "From" input attribute.
	SignTx(ctx context.Context, input SignTxInput) (*SignTxOutput, error)
	// CloseAll closes all signature manager resources.
	CloseAll(ctx context.Context, input CloseAllInput) (*CloseAllOutput, error)
	// IsAlive checks the availability of a given slot.
	IsAlive(ctx context.Context, input IsAliveInput) (*IsAliveOutput, error)
	// Reset updates the state of the snapshot taken by the HSM library.
	Reset(ctx context.Context, input ResetInput) (*ResetOutput, error)
	// SignTypedData signs EIP-712 structured typed data and returns the signature.
	SignTypedData(ctx context.Context, input SignTypedDataInput) (*SignTypedDataOutput, error)
	// PersonalSign signs an arbitrary message under the EIP-191 personal message prefix and returns the signature.
	PersonalSign(ctx context.Context, input PersonalSignInput) (*PersonalSignOutput, error)
}

const (
	signatureLength        = 65
	backendSignatureLength = 64 // raw r||s returned by the signing backend, before the recovery V byte is prepended
	// signatureVMin and signatureVMax are the two valid Ethereum recovery V bytes: the secp256k1
	// recovery ID (0 or 1) encoded as 27 or 28. They bound the recoverV search; they are unrelated
	// to the EIP-155 v = recoveryID + 35 + 2*chainID transform applied later.
	signatureVMin = 27
	signatureVMax = 28
)

func (d *DefaultUseCase) GenerateAddress(ctx context.Context, input GenerateAddressInput) (*GenerateAddressOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("slot", input.Slot)
	tracer.AddProperty("moduleKind", input.ModuleKind)
	tracer.AddProperty("operation", "GenerateAddress")

	pin, err := d.pinFor(ctx, input.ModuleKind, input.Slot, input.PinSource)
	if err != nil {
		return nil, err
	}

	createInput := CreateInput{
		ModuleKind: input.ModuleKind,
	}
	digitalSignatureManager, err := d.digitalSignatureManagerFactory.Create(ctx, createInput)
	if err != nil {
		return nil, err
	}

	generateKeyInput := signaturemanager.GenerateKeyInput{
		Slot:   input.Slot,
		Pin:    pin.value,
		Tracer: tracer,
	}
	generateKeyOutput, err := digitalSignatureManager.GenerateKey(ctx, generateKeyInput)
	d.recordLoginOutcome(pin, err)
	if err != nil {
		if signaturemanager.IsInvalidSlotError(err) {
			msg := fmt.Sprintf("the slot '%s' is not reachable in the HSM module", input.Slot)
			return nil, errors.BadGatewayFromErr(err).WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
		}
		if signaturemanager.IsPinIncorrectError(err) {
			return nil, pinIncorrectError(err, input.Slot)
		}
		return nil, errors.InternalFromErr(err)
	}

	tracer.Debugf("generated address: '%s'", generateKeyOutput.Address.String())

	return &GenerateAddressOutput{
		Address: generateKeyOutput.Address,
	}, nil
}

func (d *DefaultUseCase) DeriveAddressFromPrivateKey(ctx context.Context, input DeriveAddressFromPrivateKeyInput) (*DeriveAddressFromPrivateKeyOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("moduleKind", input.ModuleKind)
	tracer.AddProperty("operation", "DeriveAddressFromPrivateKey")

	createInput := CreateInput{
		ModuleKind: input.ModuleKind,
	}
	digitalSignatureManager, err := d.digitalSignatureManagerFactory.Create(ctx, createInput)
	if err != nil {
		return nil, errors.InternalFromErr(err).WithMessage("error creating digital signature manager")
	}

	deriveAddressInput := signaturemanager.DeriveAddressFromPrivateKeyInput{
		PrivateKey: input.PrivateKey,
		Tracer:     tracer,
	}
	deriveAddressOutput, err := digitalSignatureManager.DeriveAddressFromPrivateKey(ctx, deriveAddressInput)
	if err != nil {
		if signaturemanager.IsInvalidArgumentError(err) {
			return nil, errors.InvalidArgumentFromErr(err).WithMessage("error generating address from private key")
		}
		return nil, errors.InternalFromErr(err).WithMessage("error generating address from private key")
	}

	tracer.Trace(fmt.Sprintf("generated address from private key: '%s'", deriveAddressOutput.Address.String()))

	return &DeriveAddressFromPrivateKeyOutput{
		Address: deriveAddressOutput.Address,
	}, nil
}

func (d *DefaultUseCase) RemoveAddress(ctx context.Context, input RemoveAddressInput) (*RemoveAddressOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("slot", input.Slot)
	tracer.AddProperty("moduleKind", input.ModuleKind)
	tracer.AddProperty("operation", "RemoveAddress")

	pin, err := d.pinFor(ctx, input.ModuleKind, input.Slot, input.PinSource)
	if err != nil {
		return nil, err
	}

	createInput := CreateInput{
		ModuleKind: input.ModuleKind,
	}
	digitalSignatureManager, err := d.digitalSignatureManagerFactory.Create(ctx, createInput)
	if err != nil {
		return nil, errors.InternalFromErr(err).WithMessage("error removing address: %v", err)
	}

	removeKeyInput := signaturemanager.RemoveKeyInput{
		Slot:    input.Slot,
		Pin:     pin.value,
		Tracer:  tracer,
		Address: input.Address,
	}
	_, err = digitalSignatureManager.RemoveKey(ctx, removeKeyInput)
	d.recordLoginOutcome(pin, err)
	if err != nil {
		if signaturemanager.IsInvalidSlotError(err) {
			msg := fmt.Sprintf("the slot '%s' is not reachable in the HSM module", input.Slot)
			return nil, errors.BadGatewayFromErr(err).WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
		}
		if signaturemanager.IsPinIncorrectError(err) {
			return nil, pinIncorrectError(err, input.Slot)
		}
		if signaturemanager.IsNotFoundError(err) {
			msg := fmt.Sprintf("key for address [%s] not found", input.Address.String())
			return nil, errors.NotFoundFromErr(err).WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
		}
		return nil, errors.InternalFromErr(err).WithMessage("error removing address: %v", err)
	}

	tracer.Trace(fmt.Sprintf("removed address: '%s'", removeKeyInput.Address.String()))

	return &RemoveAddressOutput{
		Address: input.Address,
	}, nil
}

func (d *DefaultUseCase) ListAddresses(ctx context.Context, input ListAddressesInput) (*ListAddressesOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("slot", input.Slot)
	tracer.AddProperty("moduleKind", input.ModuleKind)
	tracer.AddProperty("operation", "ListAddresses")

	pin, err := d.pinFor(ctx, input.ModuleKind, input.Slot, input.PinSource)
	if err != nil {
		return nil, err
	}

	createInput := CreateInput{
		ModuleKind: input.ModuleKind,
	}
	digitalSignatureManager, err := d.digitalSignatureManagerFactory.Create(ctx, createInput)
	if err != nil {
		return nil, errors.InternalFromErr(err).WithMessage("error connecting to the digital signature manager: %v", err)
	}

	listKeysInput := signaturemanager.ListKeysInput{
		Slot:   input.Slot,
		Pin:    pin.value,
		Tracer: tracer,
	}
	keys, err := digitalSignatureManager.ListKeys(ctx, listKeysInput)
	d.recordLoginOutcome(pin, err)
	if err != nil {
		if signaturemanager.IsInvalidSlotError(err) {
			logger.LogEntry(ctx).Warnf("could not obtain keys from the configured HSM slot '%s' because it does not exist in the HSM of type '%s'", input.Slot, input.ModuleKind)
		}
		if signaturemanager.IsPinIncorrectError(err) {
			return nil, pinIncorrectError(err, input.Slot)
		}
		return nil, errors.InternalFromErr(err).WithMessage("error listing addresses: %v", err)
	}

	return &ListAddressesOutput{
		Items: keys.Items,
	}, nil
}

func (d *DefaultUseCase) SignTx(ctx context.Context, input SignTxInput) (*SignTxOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	if input.From.IsEmpty() {
		return nil, errors.InvalidArgument().SetHumanReadableMessage("field 'from' cannot be empty")
	}

	// chainID must be a valid EIP-155 value. A non-positive chainID makes a legacy transaction's
	// signed hash (which always includes the EIP-155 suffix) inconsistent with its emitted v, so the
	// recovered sender is wrong. Reject it here for every transaction type and signing-chainID source.
	if input.ChainID.Sign() < 1 {
		return nil, errors.InvalidArgument().SetHumanReadableMessage("field 'chainId' must be a positive EIP-155 value (>= 1)")
	}

	txType, err := identifyTxType(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("Could not determine transaction type")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("slot", input.Slot)
	tracer.AddProperty("moduleKind", input.ModuleKind)
	tracer.AddProperty("operation", "SignTx")
	tracer.AddProperty("txType", txType)
	if input.To == nil {
		tracer.AddProperty("to", "null")
	} else {
		tracer.AddProperty("to", input.To.String())
	}

	var output *SignTxOutput
	switch txType {
	case entities.TransactionType0Legacy:
		output, err = d.signLegacyTx(ctx, input, tracer)
	case entities.TransactionType1EIP2930:
		output, err = d.signEIP2930Tx(ctx, input, tracer)
	case entities.TransactionType2EIP1559:
		output, err = d.signEIP1559Tx(ctx, input, tracer)
	default:
		return nil, errors.InvalidArgument().SetHumanReadableMessage("Not supported transaction type")
	}
	if err != nil {
		return nil, err
	}

	// Labelled here rather than in each signer so the reported type is by construction the one that
	// selected the signer.
	output.TxType = txType

	return output, nil
}

// gasOrDefault returns the requested gas limit, defaulting to the value eth_signTransaction defines
// when the request omits it: https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_signtransaction
func gasOrDefault(gas *entities.HexUInt64) entities.HexUInt64 {
	if gas != nil {
		return *gas
	}
	return entities.NewHexUInt64(90000)
}

func gasPriceOrZero(gasPrice *entities.HexInt256) entities.HexInt256 {
	if gasPrice != nil {
		return *gasPrice
	}
	return *entities.NewHexInt256(big.NewInt(0))
}

func (d *DefaultUseCase) signTypedTx(ctx context.Context, input SignTxInput, tracer logger.Tracer, envelope typedTxEnvelope) (string, *YParityTransactionSignature, error) {
	hashedTx, err := hashTypedTx(envelope)
	if err != nil {
		return "", nil, err
	}

	signatureWithV, err := d.signAndRecover(ctx, input, tracer, hashedTx)
	if err != nil {
		return "", nil, err
	}

	signature := generateYParityTransactionSignature(signatureWithV)
	tracer.Debugf("generated type %d transaction signature", envelope.prefix)

	encoded, err := encodeTypedTx(envelope, signature)
	if err != nil {
		return "", nil, err
	}

	return encoded.Encode(), signature, nil
}

func (d *DefaultUseCase) signLegacyTx(ctx context.Context, input SignTxInput, tracer logger.Tracer) (*SignTxOutput, error) {
	gas := gasOrDefault(input.Gas)
	gasPrice := gasPriceOrZero(input.GasPrice)
	chainID := entities.NewHexInt256(input.ChainID.BigInt())

	transaction := EthereumTransaction{
		From:     input.From,
		To:       input.To,
		Gas:      gas,
		GasPrice: gasPrice,
		Value:    input.Value,
		Data:     input.Data,
		Nonce:    input.Nonce,
		ChainID:  input.ChainID,
	}
	payload, err := transaction.Hash()
	if err != nil {
		return nil, err
	}

	signatureWithV, err := d.signAndRecover(ctx, input, tracer, payload)
	if err != nil {
		return nil, err
	}

	transactionSignature := generateEthereumSignature(signatureWithV, *chainID)
	transaction.Signature = transactionSignature

	tracer.Debug("generated legacy transaction signature")

	transactionRLPEncode, err := transaction.RLPEncode()
	if err != nil {
		return nil, errors.InternalFromErr(err).WithMessage("error signing transaction: failed to RLP encode transaction with '%v'", err.Error())
	}
	result := transactionRLPEncode.Encode()

	return &SignTxOutput{
		SignedTx:    result,
		Transaction: transaction,
	}, nil
}

func (d *DefaultUseCase) signEIP2930Tx(ctx context.Context, input SignTxInput, tracer logger.Tracer) (*SignTxOutput, error) {
	transaction := EIP2930Transaction{
		From:       input.From,
		To:         input.To,
		Gas:        gasOrDefault(input.Gas),
		GasPrice:   gasPriceOrZero(input.GasPrice),
		Value:      input.Value,
		Data:       input.Data,
		Nonce:      input.Nonce,
		ChainID:    *entities.NewHexInt256(input.ChainID.BigInt()),
		AccessList: input.AccessList,
	}

	envelope, err := transaction.envelope()
	if err != nil {
		return nil, err
	}

	signedTx, signature, err := d.signTypedTx(ctx, input, tracer, *envelope)
	if err != nil {
		return nil, err
	}
	transaction.Signature = signature

	return &SignTxOutput{
		SignedTx:    signedTx,
		Transaction: transaction,
	}, nil
}

func (d *DefaultUseCase) signEIP1559Tx(ctx context.Context, input SignTxInput, tracer logger.Tracer) (*SignTxOutput, error) {
	// MaxFeePerGas and MaxPriorityFeePerGas are both guaranteed non-nil: identifyTxType only selects this
	// type when they are set, and rejects the request otherwise.
	transaction := EIP1559Transaction{
		From:                 input.From,
		To:                   input.To,
		Gas:                  gasOrDefault(input.Gas),
		MaxFeePerGas:         *input.MaxFeePerGas,
		MaxPriorityFeePerGas: *input.MaxPriorityFeePerGas,
		Value:                input.Value,
		Data:                 input.Data,
		Nonce:                input.Nonce,
		ChainID:              *entities.NewHexInt256(input.ChainID.BigInt()),
		AccessList:           input.AccessList,
	}

	envelope, err := transaction.envelope()
	if err != nil {
		return nil, err
	}

	signedTx, signature, err := d.signTypedTx(ctx, input, tracer, *envelope)
	if err != nil {
		return nil, err
	}
	transaction.Signature = signature

	return &SignTxOutput{
		SignedTx:    signedTx,
		Transaction: transaction,
	}, nil
}

// recoverV iterates over the two possible secp256k1 recovery IDs (27, 28) and sets
// signatureWithV[0] to the value that recovers the expected address. Returns an error
// if neither value matches.
func recoverV(signatureWithV []byte, from address.Address, data []byte, tracer logger.Tracer) error {
	for i := signatureVMin; i <= signatureVMax; i++ {
		signatureWithV[0] = byte(i)
		recoveredPublicKey, _, recoverCompactErr := btcececdsa.RecoverCompact(signatureWithV, data)
		if recoverCompactErr != nil {
			tracer.Errorf("EC Recover failed. Error: %v", recoverCompactErr)
			continue
		}
		if recoveredPublicKey != nil {
			pubKey, unmarshalECDSAKeyErr := unmarshalECDSAKey(recoveredPublicKey.SerializeUncompressed())
			if unmarshalECDSAKeyErr != nil {
				tracer.Errorf("unable to unmarshal public key after signing for address '%s'. Error: %v", from.String(), unmarshalECDSAKeyErr)
				continue
			}
			recoveredAddr, deriveAddressFromPublicKeyErr := signaturemanager.DeriveAddressFromPublicKey(pubKey.SerializeUncompressed())
			if deriveAddressFromPublicKeyErr != nil {
				return deriveAddressFromPublicKeyErr
			}
			if recoveredAddr.String() == from.String() {
				return nil
			}
		}
	}
	return errors.Internal().WithMessage("unable to find EC recovery value for address '%s'", from.String())
}

// assembleRecoverableSignature validates the raw signature returned by the backend, normalises S to
// low-S form, and builds the 65-byte [V||R||S] buffer with the V value that recovers `from`.
func assembleRecoverableSignature(rawSig []byte, from address.Address, data []byte, tracer logger.Tracer) ([]byte, error) {
	if err := validateBackendSignature(rawSig); err != nil {
		return nil, err
	}
	signatureWithV := make([]byte, signatureLength)
	copy(signatureWithV[1:], signatureToLowS(rawSig))
	if err := recoverV(signatureWithV, from, data, tracer); err != nil {
		return nil, err
	}
	return signatureWithV, nil
}

// signAndRecover signs the payload via HSM and performs EC recovery to determine the V value.
func (d *DefaultUseCase) signAndRecover(ctx context.Context, input SignTxInput, tracer logger.Tracer, payload *entities.HexBytes) ([]byte, error) {
	pin, pinErr := d.pinFor(ctx, input.ModuleKind, input.Slot, input.PinSource)
	if pinErr != nil {
		return nil, pinErr
	}

	createInput := CreateInput{
		ModuleKind: input.ModuleKind,
	}
	digitalSignatureManager, createErr := d.digitalSignatureManagerFactory.Create(ctx, createInput)
	if createErr != nil {
		return nil, errors.InternalFromErr(createErr).WithMessage("error signing transaction: %s", createErr.Error())
	}

	signInput := signaturemanager.SignInput{
		Slot:   input.Slot,
		Pin:    pin.value,
		Tracer: tracer,
		From:   input.From,
		Data:   *payload,
	}

	signInput.Config.AKV = make([]signaturemanager.AKVConfig, len(input.Config.AKV))
	for i, configItem := range input.Config.AKV {
		signInput.Config.AKV[i] = signaturemanager.AKVConfig{
			KeyName:          configItem.KeyName,
			KeyVersion:       configItem.KeyVersion,
			KeyPublicAddress: configItem.KeyPublicAddress,
		}
	}

	if input.Config.LocalKeyVault != nil {
		signInput.Config.LocalKeyVault = &signaturemanager.LocalKeyVaultConfig{
			KeyStore: make(map[address.Address]string),
		}
		for addr, privateKey := range input.Config.LocalKeyVault.KeyStore {
			signInput.Config.LocalKeyVault.KeyStore[addr] = privateKey
		}
	}

	signOutput, err := digitalSignatureManager.Sign(ctx, signInput)
	d.recordLoginOutcome(pin, err)
	if err != nil {
		if signaturemanager.IsInvalidSlotError(err) {
			msg := fmt.Sprintf("the slot '%s' is not reachable in the HSM module", input.Slot)
			return nil, errors.BadGatewayFromErr(err).WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
		}
		if signaturemanager.IsPinIncorrectError(err) {
			return nil, pinIncorrectError(err, input.Slot)
		}
		return nil, errors.InternalFromErr(err)
	}

	signatureWithV, err := assembleRecoverableSignature(signOutput.Signature, input.From, *payload, tracer)
	if err != nil {
		return nil, err
	}
	return signatureWithV, nil
}

func (d *DefaultUseCase) SignTypedData(ctx context.Context, input SignTypedDataInput) (*SignTypedDataOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	if input.Address.IsEmpty() {
		return nil, errors.InvalidArgument().SetHumanReadableMessage("field 'address' cannot be empty")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("slot", input.Slot)
	tracer.AddProperty("moduleKind", input.ModuleKind)
	tracer.AddProperty("operation", "SignTypedData")

	if input.TypedData.Domain.ChainId != nil &&
		input.TypedData.Domain.ChainId.Cmp(input.ChainID.BigInt()) != 0 {
		return nil, errors.InvalidArgument().SetHumanReadableMessage(
			"chainId mismatch: domain specifies %s but request has %s",
			input.TypedData.Domain.ChainId.String(),
			input.ChainID.BigInt().String())
	}

	if validateErr := input.TypedData.Validate(); validateErr != nil {
		return nil, errors.InvalidArgumentFromErr(validateErr).SetHumanReadableMessage("invalid typed data")
	}

	typedDataHash, prefixedDataHash, err := eip712.HashTypedData(input.TypedData)
	if err != nil {
		// Every failure here is caused by the caller's own types or message: an unsupported or malformed
		// field type, a value of the wrong shape, or a type graph that exceeds the encoder's depth or work
		// limits. Classifying them as InvalidArgument returns InvalidParams to the client instead of a
		// generic internal error, which would otherwise report attacker-controlled input as a signer fault.
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("invalid typed data")
	}
	ethereumSignature, signErr := d.sign(ctx, input.SlotConnectionData, input.Address, prefixedDataHash, tracer)
	if signErr != nil {
		// Return sign's error as-is: it already carries the right type (bad gateway for a malformed
		// backend signature, precondition-failed for an unreachable slot) and message. Re-wrapping
		// as Internal here would flatten that classification.
		return nil, signErr
	}
	return &SignTypedDataOutput{
		SignedData: ethereumSignature.ToHex(),
		TypedHash:  hex.EncodeToString(typedDataHash),
	}, nil
}

// PersonalSign signs a message under the EIP-191 personal message prefix, the format Sign-In With
// Ethereum verifiers expect.
//
// Unlike SignTypedData there is no chain id: EIP-191 carries no chain binding, and the recovery byte
// the shared sign helper produces is plain 27/28 rather than the EIP-155 form. Binding a personal
// signature to a chain is the verifier's job, via the message text.
func (d *DefaultUseCase) PersonalSign(ctx context.Context, input PersonalSignInput) (*PersonalSignOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	if input.Address.IsEmpty() {
		return nil, errors.InvalidArgument().SetHumanReadableMessage("field 'address' cannot be empty")
	}
	if len(input.Message) == 0 {
		return nil, errors.InvalidArgument().SetHumanReadableMessage("field 'message' cannot be empty")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("slot", input.Slot)
	tracer.AddProperty("moduleKind", input.ModuleKind)
	tracer.AddProperty("operation", "PersonalSign")

	digest, digestErr := eip191.HashPersonalMessage(input.Message)
	if digestErr != nil {
		return nil, errors.InternalFromErr(digestErr).WithMessage("error hashing personal message: %s", digestErr.Error())
	}

	ethereumSignature, signErr := d.sign(ctx, input.SlotConnectionData, input.Address, digest, tracer)
	if signErr != nil {
		// Returned as-is for the same reason as SignTypedData: sign's error already carries the right
		// classification, and re-wrapping here would flatten it to Internal.
		return nil, signErr
	}
	return &PersonalSignOutput{
		SignedData: ethereumSignature.ToHex(),
		Digest:     hex.EncodeToString(digest),
	}, nil
}

func (d *DefaultUseCase) sign(ctx context.Context, slotData SlotConnectionData, from address.Address, data []byte, tracer logger.Tracer) (*EthereumSignature, error) {
	pin, pinErr := d.pinFor(ctx, slotData.ModuleKind, slotData.Slot, slotData.PinSource)
	if pinErr != nil {
		return nil, pinErr
	}

	createInput := CreateInput{
		ModuleKind: slotData.ModuleKind,
	}
	digitalSignatureManager, createErr := d.digitalSignatureManagerFactory.Create(ctx, createInput)
	if createErr != nil {
		return nil, errors.InternalFromErr(createErr).WithMessage("error creating the signature manager: %s", createErr.Error())
	}

	signInput := signaturemanager.SignInput{
		Slot:   slotData.Slot,
		Pin:    pin.value,
		Tracer: tracer,
		From:   from,
		Data:   data,
	}

	signInput.Config.AKV = make([]signaturemanager.AKVConfig, len(slotData.Config.AKV))
	for i, configItem := range slotData.Config.AKV {
		signInput.Config.AKV[i] = signaturemanager.AKVConfig{
			KeyName:          configItem.KeyName,
			KeyVersion:       configItem.KeyVersion,
			KeyPublicAddress: configItem.KeyPublicAddress,
		}
	}
	if slotData.Config.LocalKeyVault != nil {
		signInput.Config.LocalKeyVault = &signaturemanager.LocalKeyVaultConfig{
			KeyStore: make(map[address.Address]string),
		}
		for addr, privateKey := range slotData.Config.LocalKeyVault.KeyStore {
			signInput.Config.LocalKeyVault.KeyStore[addr] = privateKey
		}
	}

	signOutput, signErr := digitalSignatureManager.Sign(ctx, signInput)
	d.recordLoginOutcome(pin, signErr)
	if signErr != nil {
		if signaturemanager.IsInvalidSlotError(signErr) {
			msg := fmt.Sprintf("the slot '%s' is not reachable in the HSM module", slotData.Slot)
			return nil, errors.BadGatewayFromErr(signErr).WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
		}
		if signaturemanager.IsPinIncorrectError(signErr) {
			return nil, pinIncorrectError(signErr, slotData.Slot)
		}
		return nil, errors.InternalFromErr(signErr)
	}

	signatureWithV, err := assembleRecoverableSignature(signOutput.Signature, from, data, tracer)
	if err != nil {
		return nil, err
	}

	// Off-chain signatures, EIP-712 and EIP-191 alike, use V=27 or V=28, not the EIP-155 transaction
	// formula. This helper is shared by every caller that signs a digest rather than a transaction.
	tracer.Debug("generated signature")
	return &EthereumSignature{
		V: entities.Int256{Int: *new(big.Int).SetBytes(signatureWithV[0:1])},
		R: entities.Int256{Int: *new(big.Int).SetBytes(signatureWithV[1:33])},
		S: entities.Int256{Int: *new(big.Int).SetBytes(signatureWithV[33:signatureLength])},
	}, nil
}

func (d *DefaultUseCase) CloseAll(ctx context.Context, _ CloseAllInput) (*CloseAllOutput, error) {
	_, err := d.digitalSignatureManagerFactory.Close(ctx, CloseInput{})
	if err != nil {
		return nil, errors.InternalFromErr(err).WithMessage("error closing digital signature manager: %v", err)
	}

	logger.LogEntry(ctx).Debug("closed digital signature manager")

	return &CloseAllOutput{}, nil
}

func (d *DefaultUseCase) IsAlive(ctx context.Context, input IsAliveInput) (*IsAliveOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	tracer := logger.NewTracer(ctx)
	tracer.AddProperty("slot", input.Slot)
	tracer.AddProperty("moduleKind", input.ModuleKind)
	tracer.AddProperty("operation", "IsAlive")

	// Resolved unconditionally, bypassing the breaker: this is the operation an administrator uses to
	// establish that a source is right, so it is also what closes a breaker that is open.
	if validateErr := ValidatePinSource(input.PinSource); validateErr != nil {
		return nil, validateErr
	}
	pinValue, resolveErr := d.pinResolver.Resolve(ctx, input.PinSource)
	if resolveErr != nil {
		return nil, resolveErr
	}
	pin := &slotPin{
		value:   pinValue,
		key:     pinBreakerKey{moduleKind: input.ModuleKind, slot: input.Slot},
		guarded: true,
	}

	createInput := CreateInput{
		ModuleKind: input.ModuleKind,
	}
	digitalSignatureManager, err := d.digitalSignatureManagerFactory.Create(ctx, createInput)
	if err != nil {
		return nil, errors.InternalFromErr(err).WithMessage("error checking if digital signature manager is alive: %v", err)
	}

	isAliveInput := signaturemanager.IsAliveInput{
		Slot:   input.Slot,
		Pin:    pin.value,
		Tracer: tracer,
	}
	isAliveOutput, err := digitalSignatureManager.IsAlive(ctx, isAliveInput)
	d.recordLoginOutcome(pin, err)
	if err != nil {
		if signaturemanager.IsInvalidSlotError(err) {
			msg := fmt.Sprintf("the slot '%s' is not reachable in the HSM module", input.Slot)
			return nil, errors.BadGatewayFromErr(err).WithMessage("%s", msg).SetHumanReadableMessage("%s", msg)
		}
		if signaturemanager.IsPinIncorrectError(err) {
			return nil, pinIncorrectError(err, input.Slot)
		}
		return nil, errors.InternalFromErr(err)
	}

	tracer.Debugf("checked if slot '%s' is alive, with result: '%t'", input.Slot, isAliveOutput.IsAlive)

	return &IsAliveOutput{
		IsAlive: isAliveOutput.IsAlive,
	}, nil
}

func (d *DefaultUseCase) Reset(ctx context.Context, input ResetInput) (*ResetOutput, error) {
	_, err := govalidator.ValidateStruct(input)
	if err != nil {
		return nil, errors.InvalidArgumentFromErr(err).SetHumanReadableMessage("couldn't validate input data")
	}

	err = d.digitalSignatureManagerFactory.Reset(ctx, input.ModuleKind)
	if err != nil {
		return nil, errors.InternalFromErr(err).WithMessage("failed to reset digital signature manager: %v", err)
	}

	logger.LogEntry(ctx).Debug("reset digital signature manager")

	return &ResetOutput{}, nil
}

var _ HSMConnector = new(DefaultUseCase)

// DefaultUseCase implements the HSMConnector interface.
type DefaultUseCase struct {
	digitalSignatureManagerFactory DigitalSignatureManagerFactory
	pinResolver                    PinResolver
	breaker                        *pinBreaker
}

// DefaultUseCaseOptions options to create a new DefaultUseCase.
type DefaultUseCaseOptions struct {
	// DigitalSignatureManagerFactory defines the factory to create DigitalSignatureManager connections
	DigitalSignatureManagerFactory DigitalSignatureManagerFactory
	// PinResolver obtains the PIN named by a slot's source.
	PinResolver PinResolver
	// MetricRecorder records the open state of the per-slot PIN breaker. Optional.
	MetricRecorder metricrecorder.MetricRecorder
}

// ProvideDefaultHSMConnector creates a new DefaultUseCase instance, returning an error if it fails.
func ProvideDefaultHSMConnector(options DefaultUseCaseOptions) (*DefaultUseCase, error) {
	if options.DigitalSignatureManagerFactory == nil {
		return nil, errors.Internal().WithMessage("mandatory 'DigitalSignatureManagerFactory' was not provided")
	}
	if options.PinResolver == nil {
		return nil, errors.Internal().WithMessage("mandatory 'PinResolver' was not provided")
	}

	var gauge metricrecorder.GaugeVector
	if options.MetricRecorder != nil {
		g, err := options.MetricRecorder.NewGaugeVector("hsm_slot_pin_breaker_open", []string{"slot", "moduleKind"}, "1 while a slot is not being retried because its PIN was refused, 0 otherwise")
		if err != nil {
			return nil, errors.InternalFromErr(err)
		}
		gauge = g
	}

	return &DefaultUseCase{
		digitalSignatureManagerFactory: options.DigitalSignatureManagerFactory,
		pinResolver:                    options.PinResolver,
		breaker:                        newPinBreaker(gauge),
	}, nil
}

func identifyTxType(input SignTxInput) (string, error) {

	if input.AuthorizationList != nil {
		// Not supported transaction type
		return entities.TransactionType4EIP7702, nil
	}

	if input.MaxFeePerBlobGas != nil || input.BlobVersionedHashes != nil {
		// Not supported transaction type
		return entities.TransactionType3EIP4844, nil
	}

	if input.MaxFeePerGas != nil || input.MaxPriorityFeePerGas != nil {
		if input.GasPrice != nil {
			return "Unknown", errors.InvalidArgument().WithMessage("Ambiguous transaction type")
		}
		if input.MaxFeePerGas == nil || input.MaxPriorityFeePerGas == nil {
			return "Unknown", errors.InvalidArgument().WithMessage("Missing mandatory field")
		}

		return entities.TransactionType2EIP1559, nil
	}

	if input.AccessList != nil {
		return entities.TransactionType1EIP2930, nil
	}

	return entities.TransactionType0Legacy, nil
}
