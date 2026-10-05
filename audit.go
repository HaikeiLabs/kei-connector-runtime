package connectorruntime

import (
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

type LifecycleEvent = keiruntime.LifecycleEvent

func appendLifecycleEvent(path string, maxBytes int64, e LifecycleEvent) error {
	return keiruntime.AppendLifecycleEvent(path, maxBytes, e)
}
