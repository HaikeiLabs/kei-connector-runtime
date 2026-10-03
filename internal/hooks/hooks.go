package hooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/auditcrypto"
)

// ToolInput is the common subset of harness hook input used for reporting.
type ToolInput struct {
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	SessionID      string          `json:"session_id"`
	ToolUseID      string          `json:"tool_use_id"`
	EventName      string          `json:"hook_event_name"`
	Phase          string          `json:"phase"`
	NativeDecision string          `json:"native_decision"`
}

// Config carries the minimal runtime data hooks need. AppendAudit writes one
// record to the runtime's audit spool.
type Config struct {
	RuntimeStateDir string
	AppendAudit     func([]byte) error
	AuditCrypto     *auditcrypto.Provider
}

// ReadInput safely reads and decodes one harness hook payload.
func ReadInput(r io.Reader) (ToolInput, error) {
	data, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return ToolInput{}, err
	}
	var in ToolInput
	if err := json.Unmarshal(data, &in); err != nil || in.ToolName == "" {
		return ToolInput{}, errors.New("invalid harness hook input")
	}
	if len(in.ToolInput) == 0 {
		in.ToolInput = json.RawMessage(`{}`)
	}
	if CanonicalJSON(in.ToolInput) == nil {
		return ToolInput{}, errors.New("invalid harness tool input")
	}
	return in, nil
}

// CanonicalJSON decodes JSON and re-encodes it with deterministic object keys.
func CanonicalJSON(raw []byte) []byte {
	var value any
	if json.Unmarshal(bytes.TrimSpace(raw), &value) != nil {
		return nil
	}
	b, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return b
}

// WriteAudit sends a hook record to the runtime spool. Spool errors are
// deliberately ignored by reporting hooks so they always return success to
// the harness.
func WriteAudit(cfg Config, record []byte) {
	if cfg.AppendAudit != nil {
		_ = cfg.AppendAudit(record)
	}
}

func validHarnessKind(kind string) bool {
	return kind == "claude" || kind == "codex" || kind == "opencode"
}

func validNativeDecision(phase, decision string) bool {
	if phase == "post" {
		return decision == "executed"
	}
	switch decision {
	case "allow", "deny", "ask", "unknown", "approved", "denied":
		return true
	}
	return false
}
