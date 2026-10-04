package connectorruntime

import (
	"encoding/json"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// LifecycleEvent is a runtime lifecycle audit record written by the heartbeat
// loop. It is appended as a single JSON line to the same local JSONL spool as
// decisions, where the collector routes it to the lifecycle flush endpoint.
type LifecycleEvent = keiruntime.LifecycleEvent

// appendLifecycleEvent marshals e and appends it to the audit spool at path,
// capped by maxBytes. A lifecycle record is refused if the spool nears its cap
// (see lifecycleCeilingPercent). An empty path is a no-op.
func appendLifecycleEvent(path string, maxBytes int64, e LifecycleEvent) error {
	if path == "" {
		return nil
	}
	e.EventClass = keiruntime.EventClassLifecycle
	e.SchemaVersion = 1
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return keiruntime.NewAuditSpool(path, maxBytes).Append(keiruntime.EventClassLifecycle, data)
}
