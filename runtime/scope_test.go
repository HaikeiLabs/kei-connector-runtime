package runtime

import (
	"testing"
	"time"
)

func TestMintScope_PropagatesInvokingSubject(t *testing.T) {
	parent := &Scope{
		ID: "parent-scope",
		InvokingSubject: &InvokingSubject{
			Source:   "github",
			Value:    "user:123",
			AuthTime: time.Now().UTC(),
		},
		AgentID: "agent-1",
		Depth:   0,
	}

	child := MintScope(parent, "agent-2")

	if child.InvokingSubject == nil {
		t.Fatal("expected child scope to have InvokingSubject, got nil")
	}

	if child.InvokingSubject.Source != parent.InvokingSubject.Source {
		t.Errorf("expected Source=%q, got %q", parent.InvokingSubject.Source, child.InvokingSubject.Source)
	}

	if child.InvokingSubject.Value != parent.InvokingSubject.Value {
		t.Errorf("expected Value=%q, got %q", parent.InvokingSubject.Value, child.InvokingSubject.Value)
	}

	if child.ParentScopeID != parent.ID {
		t.Errorf("expected ParentScopeID=%q, got %q", parent.ID, child.ParentScopeID)
	}

	if child.Depth != parent.Depth+1 {
		t.Errorf("expected Depth=%d, got %d", parent.Depth+1, child.Depth)
	}

	if child.AgentID != "agent-2" {
		t.Errorf("expected AgentID=agent-2, got %q", child.AgentID)
	}
}

func TestMintScope_NilParent(t *testing.T) {
	child := MintScope(nil, "agent-1")

	if child.InvokingSubject != nil {
		t.Errorf("expected nil InvokingSubject for root scope, got %v", child.InvokingSubject)
	}

	if child.ParentScopeID != "" {
		t.Errorf("expected empty ParentScopeID, got %q", child.ParentScopeID)
	}

	if child.Depth != 0 {
		t.Errorf("expected Depth=0, got %d", child.Depth)
	}

	if child.AgentID != "agent-1" {
		t.Errorf("expected AgentID=agent-1, got %q", child.AgentID)
	}
}

func TestMintScope_GeneratesUniqueIDs(t *testing.T) {
	scope1 := MintScope(nil, "agent-1")
	scope2 := MintScope(nil, "agent-1")

	if scope1.ID == scope2.ID {
		t.Errorf("expected unique scope IDs, got %q == %q", scope1.ID, scope2.ID)
	}
}
