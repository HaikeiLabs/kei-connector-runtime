package connectorruntime

import (
	"encoding/json"
	"time"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// LifecycleEvent is a runtime lifecycle audit record written by the heartbeat
// loop. It is appended as a single JSON line to the same local JSONL spool as
// decisions, where the collector routes it to the lifecycle flush endpoint.
type LifecycleEvent struct {
	EventClass     string            `json:"event_class"`
	SchemaVersion  int               `json:"schema_version"`
	EventType      string            `json:"event_type"`
	Outcome        HeartbeatOutcome  `json:"outcome"`
	ObservedAt     time.Time         `json:"observed_at"`
	RuntimeVersion string            `json:"runtime_version"`
	RunID          string            `json:"run_id"`
	Seq            uint64            `json:"seq"`
	Attrs          map[string]string `json:"attrs,omitempty"`
}

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
