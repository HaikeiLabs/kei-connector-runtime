package connectorruntime

import (
	"time"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

type ModelProfile = keiruntime.ModelProfile
type ModelProfileSummary = keiruntime.ModelProfileSummary
type ModelProfileList = keiruntime.ModelProfileList
type ControlPlaneModelProfileClient = keiruntime.ControlPlaneModelProfileClient

func NewControlPlaneModelProfileClient(baseURL, token string, timeout time.Duration) ControlPlaneModelProfileClient {
	return keiruntime.NewControlPlaneModelProfileClient(baseURL, token, timeout)
}
