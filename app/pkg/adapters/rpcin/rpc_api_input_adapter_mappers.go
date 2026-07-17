// Package rpcin defines the implementation of the input adapters for the JSON RPC infra.
package rpcin

import (
	"github.com/hyperledger-labs/signare/app/pkg/infra/rpcinfra/rpcerrors"
	"github.com/hyperledger-labs/signare/app/pkg/internal/errors"
)

func adaptError(err error) *rpcerrors.RPCError {
	if errors.IsInvalidArgument(err) {
		return rpcerrors.NewInvalidParamsFromErr(err)
	}
	if errors.IsNotFound(err) {
		return rpcerrors.NewNotFoundFromErr(err)
	}
	if errors.IsPreconditionFailed(err) {
		return rpcerrors.NewPreconditionFailedFromErr(err)
	}
	if errors.IsBadGateway(err) {
		return rpcerrors.NewBadGatewayFromErr(err)
	}
	if errors.IsAlreadyExists(err) {
		return rpcerrors.NewAlreadyExistsFromErr(err)
	}
	return rpcerrors.NewInternalFromErr(err)
}
