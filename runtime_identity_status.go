package connectorruntime

import keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"

type IdentityStatusFailureError = keiruntime.IdentityStatusFailureError
type IdentityStatusRequest = keiruntime.IdentityStatusRequest
type IdentityStatusResponse = keiruntime.IdentityStatusResponse

const (
	IdentityStatusFailurePreTransport = keiruntime.IdentityStatusFailurePreTransport
	IdentityStatusFailureTransport    = keiruntime.IdentityStatusFailureTransport
	IdentityStatusFailureHTTP         = keiruntime.IdentityStatusFailureHTTP
	IdentityStatusFailureResponse     = keiruntime.IdentityStatusFailureResponse
)
