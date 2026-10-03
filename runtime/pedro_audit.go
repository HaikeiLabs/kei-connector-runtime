package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// pedroAuditLine is the legacy audit event format from the pedro-agentware
// era. ParseAuditLine attempts to decode a line as DecisionEvent first; if
// that fails it falls back to this format for backward compatibility with
// pre-migration spool files.
type pedroAuditLine struct {
	SpanID          string          `json:"span_id"`
	InvokedAt       string          `json:"invoked_at"`
	Timestamp       string          `json:"timestamp"`
	UserID          string          `json:"user_id"`
	InvokingSubject string          `json:"invoking_subject"`
	ParentSpan      string          `json:"parent_span"`
	DelegationDepth int             `json:"delegation_depth"`
	AgentID         string          `json:"agent_id"`
	AgentVersion    string          `json:"agent_version"`
	Framework       string          `json:"framework"`
	Source          string          `json:"source"`
	ToolName        string          `json:"tool_name"`
	Args            json.RawMessage `json:"args"`
	ArgsDigest      string          `json:"tool_args_digest"`
	Resources       []string        `json:"resources_touched"`
	Decision        struct {
		Action    string `json:"action"`
		Rule      string `json:"rule"`
		Reason    string `json:"reason"`
		Timestamp string `json:"timestamp"`
	} `json:"decision"`
}

func ParseAuditLine(line string) (DecisionEvent, bool) {
	var event DecisionEvent
	if err := json.Unmarshal([]byte(line), &event); err == nil {
		return event, true
	}

	var old pedroAuditLine
	if err := json.Unmarshal([]byte(line), &old); err != nil || old.ToolName == "" || old.Decision.Action == "" {
		return DecisionEvent{}, false
	}

	when := old.InvokedAt
	if when == "" {
		when = old.Timestamp
	}
	if when == "" {
		when = old.Decision.Timestamp
	}
	invokedAt, err := parsePedroTimestamp(when)
	if err != nil {
		return DecisionEvent{}, false
	}

	spanID := old.SpanID
	if spanID == "" {
		digest := sha256.Sum256([]byte(line))
		spanID = "pedro-" + hex.EncodeToString(digest[:])
	}

	subject := old.InvokingSubject
	if subject == "" {
		subject = old.UserID
	}
	framework := old.Framework
	if framework == "" {
		framework = old.Source
	}
	if framework == "" {
		framework = "pedro-service"
	}

	var parent *string
	if old.ParentSpan != "" {
		parent = &old.ParentSpan
	}
	var agentVersion *string
	if old.AgentVersion != "" {
		agentVersion = &old.AgentVersion
	}
	var policyReason *string
	if reason := old.Decision.Reason; reason != "" {
		policyReason = &reason
	} else if old.Decision.Rule != "" {
		policyReason = &old.Decision.Rule
	}

	argsDigest := old.ArgsDigest
	if argsDigest == "" && len(old.Args) > 0 && string(old.Args) != "null" {
		digest := sha256.Sum256(old.Args)
		argsDigest = hex.EncodeToString(digest[:])
	}
	var toolArgsDigest *string
	if argsDigest != "" {
		toolArgsDigest = &argsDigest
	}

	resources := old.Resources
	if resources == nil {
		resources = []string{}
	}
	return DecisionEvent{
		SpanID:           spanID,
		InvokedAt:        invokedAt,
		InvokingSubject:  subject,
		ParentSpan:       parent,
		DelegationDepth:  old.DelegationDepth,
		AgentID:          old.AgentID,
		AgentVersion:     agentVersion,
		Framework:        framework,
		ToolName:         old.ToolName,
		ToolArgsDigest:   toolArgsDigest,
		ResourcesTouched: resources,
		Decision:         old.Decision.Action,
		PolicyReason:     policyReason,
	}, true
}

func parsePedroTimestamp(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, fmt.Errorf("timestamp is empty")
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC(), nil
	}
	for _, layout := range []string{"2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid timestamp %q", value)
}
