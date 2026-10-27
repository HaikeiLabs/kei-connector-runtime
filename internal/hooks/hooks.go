package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/auditcrypto"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
)

// ToolInput is the common subset of harness hook input used for reporting.
type ToolInput struct {
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	SessionID      string          `json:"session_id"`
	ToolUseID      string          `json:"tool_use_id"`
	CWD            string          `json:"cwd"`
	EventName      string          `json:"hook_event_name"`
	Phase          string          `json:"phase"`
	NativeDecision string          `json:"native_decision"`
}

// Config carries the runtime data hooks need. AppendAudit writes one record
// to the runtime's audit spool. SubjectSource resolves the authenticated
// subject for the session and is used by the login nudge.
type Config struct {
	RuntimeStateDir string
	AppendAudit     func([]byte) error
	AuditCrypto     *auditcrypto.Provider
	SubjectSource   session.SubjectSource
	// CodexDecisionSource queries the native Codex rule evaluator for a
	// pre-tool event. It is optional so report-hook unit tests and other
	// harnesses never depend on a locally installed Codex binary.
	CodexDecisionSource func(context.Context, ToolInput) string
}

// sesionLevelEvent reports whether eventName is a harness event that carries
// no tool (Stop, SessionEnd, SessionStart). These events are valid hook
// invocations but have no tool_name, tool_input or tool_use_id.
func sessionLevelEvent(eventName string) bool {
	switch strings.ToLower(eventName) {
	case "stop", "sessionend", "sessionstart", "notification":
		return true
	}
	return false
}

// ReadInput safely reads and decodes one harness hook payload. It requires a
// tool_name for tool-level events; session-level events (Stop, SessionEnd,
// SessionStart, Notification) are accepted without one.
func ReadInput(r io.Reader) (ToolInput, error) {
	data, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return ToolInput{}, err
	}
	var in ToolInput
	if err := json.Unmarshal(data, &in); err != nil {
		return ToolInput{}, errors.New("invalid harness hook input")
	}
	if in.ToolName == "" && !sessionLevelEvent(in.EventName) {
		return ToolInput{}, errors.New("invalid harness hook input")
	}
	if len(in.ToolInput) == 0 {
		in.ToolInput = json.RawMessage(`{}`)
	}
	if in.ToolName != "" && CanonicalJSON(in.ToolInput) == nil {
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

// validHarnessKindIn is validHarnessKind plus the short names the persisted
// bundle's harness kind registry declares (HAI-622, CA-5), so a kind added to
// the registry needs no code change. A short name that is neither built in nor
// registered is still unknown.
func validHarnessKindIn(stateDir, kind string) bool {
	if validHarnessKind(kind) {
		return true
	}
	_, ok := registryKindForShortName(stateDir, kind)
	return ok
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
