package connectorruntime

import (
	"time"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

type ModelProfile = keiruntime.ModelProfile
type ControlPlaneModelProfileClient = keiruntime.ControlPlaneModelProfileClient

func NewControlPlaneModelProfileClient(baseURL, token string, timeout time.Duration) ControlPlaneModelProfileClient {
	return keiruntime.NewControlPlaneModelProfileClient(baseURL, token, timeout)
}
