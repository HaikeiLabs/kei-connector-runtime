package connectorruntime

import (
	"bytes"
	"os"
	"testing"
)

func TestBuildDecisionEventPreservesCanonicalContext(t *testing.T) {
	workspaceID := "workspace-1"
	policyID := "policy-1"
	respWorkspaceID := "workspace-from-abac"

	event := buildDecisionEvent(authorizeParams{
		spanID:          "span-1",
		invokingSubject: "user-1",
		parentSpan:      "parent-1",
		delegationDepth: 2,
		agentID:         "agent-1",
		agentVersion:    "1.2.3",
		framework:       "agentware",
		tool:            "github.create_pr",
		toolArgsDigest:  "digest-1",
		resources:       []string{"repo:acme/widgets"},
		workspaceID:     workspaceID,
	}, &AuthorizeResponse{
		PolicyID:    policyID,
		WorkspaceID: &respWorkspaceID,
	}, AuthorizeOutput{Decision: "allow"}, "repo:acme/widgets")

	if event.WorkspaceID == nil || *event.WorkspaceID != respWorkspaceID {
		t.Fatalf("workspace_id = %v, want ABAC response value %q", event.WorkspaceID, respWorkspaceID)
	}
	if event.ParentSpan == nil || *event.ParentSpan != "parent-1" {
		t.Fatalf("parent_span = %v", event.ParentSpan)
	}
	if event.DelegationDepth != 2 || event.AgentID != "agent-1" || event.Framework != "agentware" {
		t.Fatalf("context not preserved: %+v", event)
	}
	if event.ToolArgsDigest == nil || *event.ToolArgsDigest != "digest-1" {
		t.Fatalf("tool_args_digest = %v", event.ToolArgsDigest)
	}
}

func TestAppendDecisionEventCreatesParentDirectories(t *testing.T) {
	event := buildDecisionEvent(authorizeParams{
		spanID: "span-1",
		tool:   "github.create_pr",
	}, &AuthorizeResponse{}, AuthorizeOutput{Decision: "allow"}, "repo:acme")

	root := t.TempDir()
	path := root + "/kei-proxy/audit/events.jsonl"

	if err := appendDecisionEvent(path, 0, event); err != nil {
		t.Fatalf("appendDecisionEvent: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read appended file: %v", err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatalf("expected a trailing newline, got %q", data)
	}

	if err := appendDecisionEvent(path, 0, event); err != nil {
		t.Fatalf("second append: %v", err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("reread file: %v", err)
	}
	if got := bytes.Count(data, []byte{'\n'}); got != 2 {
		t.Fatalf("line count = %d, want 2", got)
	}
}

func TestAppendDecisionEventEmptyPathIsNoop(t *testing.T) {
	if err := appendDecisionEvent("", 0, buildDecisionEvent(authorizeParams{}, &AuthorizeResponse{}, AuthorizeOutput{}, "")); err != nil {
		t.Fatalf("empty path should be a no-op, got: %v", err)
	}
}
