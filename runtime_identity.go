package connectorruntime

import (
	"context"
	"time"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

type RuntimeIdentity = keiruntime.RuntimeIdentity
type RuntimeAgent = keiruntime.RuntimeAgent
type WhoamiFailureCategory = keiruntime.WhoamiFailureCategory
type WhoamiFailure = keiruntime.WhoamiFailure
type RuntimeClient = keiruntime.RuntimeClient
type ToolSyncResponse = keiruntime.ToolSyncResponse
type ToolSyncError = keiruntime.ToolSyncError

const (
	WhoamiFailureTransport  = keiruntime.WhoamiFailureTransport
	WhoamiFailureHTTPStatus = keiruntime.WhoamiFailureHTTPStatus
	WhoamiFailureDecode     = keiruntime.WhoamiFailureDecode
	WhoamiFailureIncomplete = keiruntime.WhoamiFailureIncomplete
)

func DiagnoseWhoamiError(err error) WhoamiFailureCategory {
	return keiruntime.DiagnoseWhoamiError(err)
}

func NewRuntimeClient(baseURL string, timeout time.Duration) RuntimeClient {
	return keiruntime.NewRuntimeClient(baseURL, timeout)
}

// bootstrapRuntime proves the runtime credential resolves to an installation
// before normal proxy work begins and records a liveness heartbeat. It does
// not turn a pending installation active; only the verified deployment flow
// may perform that lifecycle transition.
func bootstrapRuntime(ctx context.Context, cfg Config, timeout time.Duration) (*RuntimeIdentity, error) {
	if !cfg.IsRuntime() {
		return nil, nil
	}
	return bootstrapRuntimeWithClient(ctx, cfg, timeout, NewRuntimeClient)
}
