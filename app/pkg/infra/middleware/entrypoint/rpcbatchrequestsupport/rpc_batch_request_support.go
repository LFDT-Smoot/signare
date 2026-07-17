package rpcbatchrequestsupport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/hyperledger-labs/signare/app/pkg/infra/httpinfra"
	"github.com/hyperledger-labs/signare/app/pkg/infra/requestcontext"
	"github.com/hyperledger-labs/signare/app/pkg/infra/rpcinfra"
	"github.com/hyperledger-labs/signare/app/pkg/utils"

	"github.com/google/uuid"
)

// maxBatchElements caps the number of elements accepted in a single JSON-RPC batch request.
// Each element is fanned out into a full request, so an unbounded batch is a work-amplification
// vector independent of the body byte size.
const maxBatchElements = 100

// bodyTooLargeMessage is the client-facing message returned when the request body exceeds the
// entrypoint size limit (see httpinfra.MaxBytesMiddleware).
const bodyTooLargeMessage = "request body too large"

// FanOutRPCBatchRequest is a middleware function to fan-out RPC requests if a batch request is identified.
// Each of the requests is processed as if it were a single request.
// Before sending the request to be processed, the RPC RequestID will be injected into the context.
func (m *RPCBatchRequestSupportMiddleware) FanOutRPCBatchRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var singleRPCRequest RPCRequest
		err := utils.ReadAndResetCloser(&r.Body, &singleRPCRequest)
		if err == nil {
			ctx := context.WithValue(r.Context(), requestcontext.RPCRequestIDKey, ensureContextRequestID(singleRPCRequest.ID))
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		var batchRPCRequest []RPCRequest
		err = utils.ReadAndResetCloser(&r.Body, &batchRPCRequest)
		if err != nil {
			httpErr := httpinfra.NewHTTPErrorFromError(r.Context(), err, httpinfra.StatusInvalidArgument)
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				httpErr = httpErr.SetMessage(bodyTooLargeMessage)
			}
			m.responseHandler.HandleErrorResponse(r.Context(), w, httpErr)
			return
		}

		if len(batchRPCRequest) == 0 {
			emptyBatchErr := errors.New("batch request must contain at least one element")
			m.responseHandler.HandleErrorResponse(r.Context(), w, httpinfra.NewHTTPErrorFromError(r.Context(), emptyBatchErr, httpinfra.StatusInvalidArgument).SetMessage(emptyBatchErr.Error()))
			return
		}

		if len(batchRPCRequest) > maxBatchElements {
			tooManyElementsErr := fmt.Errorf("batch request exceeds the maximum of %d elements", maxBatchElements)
			m.responseHandler.HandleErrorResponse(r.Context(), w, httpinfra.NewHTTPErrorFromError(r.Context(), tooManyElementsErr, httpinfra.StatusInvalidArgument).SetMessage(tooManyElementsErr.Error()))
			return
		}

		for _, rpcRequest := range batchRPCRequest {
			ctx := context.WithValue(r.Context(), requestcontext.RPCRequestIDKey, ensureContextRequestID(rpcRequest.ID))
			requestBodyBytes, errMarshal := json.Marshal(rpcRequest)
			if errMarshal != nil {
				m.responseHandler.HandleErrorResponse(ctx, w, httpinfra.NewHTTPErrorFromError(ctx, errMarshal, httpinfra.StatusInvalidArgument))
				continue
			}
			reader := bytes.NewBuffer(requestBodyBytes)
			r.Body = io.NopCloser(reader)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	})
}

func ensureContextRequestID(reqID any) any {
	if reqID == nil {
		return uuid.NewString()
	}
	return reqID
}

// RPCBatchRequestSupportMiddleware enables support for batch requests as defined in https://www.jsonrpc.org/specification#batch
type RPCBatchRequestSupportMiddleware struct {
	responseHandler httpinfra.HTTPResponseHandler
	router          rpcinfra.RPCRouter
}

// RPCBatchRequestSupportMiddlewareOptions define the variables to handle the batch requests fan out
type RPCBatchRequestSupportMiddlewareOptions struct {
	// ResponseHandler exposes functionality to handle HTTP responses
	ResponseHandler httpinfra.HTTPResponseHandler
	// RPCRouter are a set of methods to set up an RPC RPCRouter
	RPCRouter rpcinfra.RPCRouter
}

// ProvideRPCBatchRequestSupportMiddleware provides an instance of an RPCBatchRequestSupportMiddleware
func ProvideRPCBatchRequestSupportMiddleware(options RPCBatchRequestSupportMiddlewareOptions) (*RPCBatchRequestSupportMiddleware, error) {
	if options.ResponseHandler == nil {
		return nil, errors.New("mandatory 'ResponseHandler' not provided")
	}
	if options.RPCRouter == nil {
		return nil, errors.New("mandatory 'RPCRouter' not provided")
	}

	return &RPCBatchRequestSupportMiddleware{
		responseHandler: options.ResponseHandler,
		router:          options.RPCRouter,
	}, nil
}
