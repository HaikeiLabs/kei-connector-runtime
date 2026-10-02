package harness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"time"
)

const maxHookInput = 64 << 10

func reportHook(ctx context.Context, rec Recorder, h Harness, stdin io.Reader, stdout io.Writer) error {
	// Hook protocols return an empty response: native harness permissions own
	// the decision. All malformed input and recorder failures are swallowed.
	_ = stdout // writing a decision would change native behavior.
	if rec == nil || stdin == nil {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(stdin, maxHookInput+1))
	if err != nil || len(b) > maxHookInput {
		return nil
	}
	var raw struct {
		ToolName           string          `json:"tool_name"`
		Tool               string          `json:"tool"`
		ToolInput          json.RawMessage `json:"tool_input"`
		Input              json.RawMessage `json:"input"`
		SessionID          string          `json:"session_id"`
		ToolUseID          string          `json:"tool_use_id"`
		Phase              string          `json:"phase"`
		NativeDecision     string          `json:"native_decision"`
		PermissionDecision string          `json:"permission_decision"`
	}
	if json.Unmarshal(b, &raw) != nil {
		return nil
	}
	name := raw.ToolName
	if name == "" {
		name = raw.Tool
	}
	if name == "" {
		return nil
	}
	phase := raw.Phase
	if phase != "pre" && phase != "post" && phase != "permission_reply" {
		phase = "pre"
	}
	decision := raw.NativeDecision
	if decision == "" {
		decision = raw.PermissionDecision
	}
	if decision != "allow" && decision != "deny" && decision != "ask" && decision != "unknown" && decision != "executed" {
		decision = "unknown"
	}
	if phase == "post" {
		decision = "executed"
	}
	args := raw.ToolInput
	if len(args) == 0 {
		args = raw.Input
	}
	event := HarnessToolEvent{Schema: "kei.harness-tool-event/v1", HarnessID: h.ID, HarnessKind: h.Kind, HarnessRegistered: h.ID != "", HarnessSessionID: raw.SessionID, ToolUseID: raw.ToolUseID, Phase: phase, NativeDecision: decision, ObservedAt: time.Now().UTC()}
	event.Tool, event.Registered, event.Selector = resolveToolName(h.Kind, name)
	if strings.EqualFold(name, "Skill") {
		var input map[string]any
		if json.Unmarshal(args, &input) == nil {
			if skill, ok := input["skill"].(string); ok && skill != "" {
				name = "skill:" + skill
			}
		}
	}
	if strings.EqualFold(name, "bash") || strings.EqualFold(name, "shell") || strings.EqualFold(name, "exec_command") {
		var input map[string]any
		if json.Unmarshal(args, &input) == nil {
			if command, ok := input["command"].(string); ok {
				fields := strings.Fields(command)
				if len(fields) > 0 {
					event.Argv0 = fields[0]
				}
			}
		}
	}
	if len(args) > 0 && json.Valid(args) {
		var normalized any
		if json.Unmarshal(args, &normalized) == nil {
			canonical, e := json.Marshal(normalized)
			if e == nil {
				sum := sha256.Sum256(canonical)
				event.ArgsDigest = "sha256:" + hex.EncodeToString(sum[:])
			}
		}
	}
	_ = rec.RecordHarnessEvent(ctx, event)
	return nil
}

func resolveToolName(kind Kind, raw string) (string, bool, string) {
	if strings.HasPrefix(raw, "skill:") {
		skill := strings.TrimPrefix(raw, "skill:")
		name, e := registryName(kind, "skill", skill)
		if e == nil {
			return name, true, raw
		}
	}
	lower := strings.ToLower(raw)
	switch lower {
	case "bash", "shell", "exec_command":
		return string(kind) + ".bash", true, ""
	case "read", "read_file":
		return string(kind) + ".read", true, ""
	case "edit", "edit_file":
		return string(kind) + ".edit", true, ""
	case "write", "write_file":
		return string(kind) + ".write", true, ""
	case "glob":
		return string(kind) + ".glob", true, ""
	case "grep", "search":
		return string(kind) + ".grep", true, ""
	case "webfetch", "web_fetch":
		return string(kind) + ".webfetch", true, ""
	}
	if strings.HasPrefix(raw, "mcp__") {
		p := strings.SplitN(strings.TrimPrefix(raw, "mcp__"), "__", 2)
		if len(p) == 2 {
			name, e := registryName(kind, "mcp", p[0], p[1])
			if e == nil {
				return name, true, "mcp:" + p[0] + "." + p[1]
			}
		}
	}
	return raw, false, ""
}
