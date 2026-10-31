package runtime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAppendDecisionEventDefaultsEmptySubject pins the write-time subject
// default (HAI-928): the catalog's audit:flush rejects an empty
// invoking_subject, which would pin the oldest spool batch on that record
// forever. Every writer that funnels through AppendDecisionEvent must stamp
// the same default the socket path uses; a resolved subject passes through
// unchanged.
func TestAppendDecisionEventDefaultsEmptySubject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	empty := ev("s-empty")
	empty.InvokingSubject = ""
	if err := AppendDecisionEvent(path, 0, empty); err != nil {
		t.Fatalf("AppendDecisionEvent: %v", err)
	}
	resolved := ev("s-resolved")
	resolved.InvokingSubject = "user:alice"
	if err := AppendDecisionEvent(path, 0, resolved); err != nil {
		t.Fatalf("AppendDecisionEvent: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored []DecisionEvent
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e DecisionEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("stored record %q: %v", line, err)
		}
		stored = append(stored, e)
	}
	if len(stored) != 2 {
		t.Fatalf("stored %d records, want 2", len(stored))
	}
	if stored[0].InvokingSubject != UnauthenticatedSubject {
		t.Fatalf("empty subject stored as %q, want %q", stored[0].InvokingSubject, UnauthenticatedSubject)
	}
	if stored[1].InvokingSubject != "user:alice" {
		t.Fatalf("resolved subject stored as %q, want user:alice", stored[1].InvokingSubject)
	}
}

// TestEmitDecisionDefaultsEmptySubject covers the one-shot CLI writer path,
// which funnels through AppendDecisionEvent.
func TestEmitDecisionDefaultsEmptySubject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	e := ev("s-cli")
	e.InvokingSubject = ""
	EmitDecision(path, 0, e)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored DecisionEvent
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("stored record: %v", err)
	}
	if stored.InvokingSubject != UnauthenticatedSubject {
		t.Fatalf("invoking_subject = %q, want %q", stored.InvokingSubject, UnauthenticatedSubject)
	}
}
