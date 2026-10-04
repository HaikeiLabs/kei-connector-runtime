package connectorruntime

import (
	"bytes"
	"os"
	"testing"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

func TestBuildDecisionEventPreservesCanonicalContext(t *testing.T) {
	workspaceID := "workspace-1"
	policyID := "policy-1"
	respWorkspaceID := "workspace-from-abac"

	event := keiruntime.BuildDecisionEvent(keiruntime.AuthorizeParams{
		SpanID:          "span-1",
		InvokingSubject: "user-1",
		ParentSpan:      "parent-1",
		DelegationDepth: 2,
		AgentID:         "agent-1",
		AgentVersion:    "1.2.3",
		Framework:       "agentware",
		Tool:            "search_wiki",
		ToolArgsDigest:  "digest-1",
		Resources:       []string{"repo:acme/widgets"},
		WorkspaceID:     workspaceID,
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
	if event.ToolName != "search_wiki" {
		t.Fatalf("tool_name = %q, want canonical tool name search_wiki", event.ToolName)
	}
	if event.ToolArgsDigest == nil || *event.ToolArgsDigest != "digest-1" {
		t.Fatalf("tool_args_digest = %v", event.ToolArgsDigest)
	}
}

func TestBuildDecisionEventInvokingSubjectFallback(t *testing.T) {
	for _, tc := range []struct {
		name, invokingSubject, user, want string
	}{
		{name: "explicit caller", invokingSubject: "human:42", user: "user:7", want: "human:42"},
		{name: "omitted caller", user: "user:7", want: "user:7"},
		{name: "empty caller", invokingSubject: "", user: "user:7", want: "user:7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := keiruntime.BuildDecisionEvent(keiruntime.AuthorizeParams{
				InvokingSubject: tc.invokingSubject,
				User:            tc.user,
			}, &AuthorizeResponse{}, AuthorizeOutput{Decision: "allow"}, "")
			if event.InvokingSubject != tc.want {
				t.Fatalf("invoking_subject=%q, want %q", event.InvokingSubject, tc.want)
			}
		})
	}
}

func TestAppendDecisionEventCreatesParentDirectories(t *testing.T) {
	event := keiruntime.BuildDecisionEvent(keiruntime.AuthorizeParams{
		SpanID: "span-1",
		Tool:   "github.create_pr",
	}, &AuthorizeResponse{}, AuthorizeOutput{Decision: "allow"}, "repo:acme")

	root := t.TempDir()
	path := root + "/kei-proxy/audit/events.jsonl"

	if err := keiruntime.AppendDecisionEvent(path, 0, event); err != nil {
		t.Fatalf("keiruntime.AppendDecisionEvent: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read appended file: %v", err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatalf("expected a trailing newline, got %q", data)
	}

	if err := keiruntime.AppendDecisionEvent(path, 0, event); err != nil {
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
	if err := keiruntime.AppendDecisionEvent("", 0, keiruntime.BuildDecisionEvent(keiruntime.AuthorizeParams{}, &AuthorizeResponse{}, AuthorizeOutput{}, "")); err != nil {
		t.Fatalf("empty path should be a no-op, got: %v", err)
	}
}
