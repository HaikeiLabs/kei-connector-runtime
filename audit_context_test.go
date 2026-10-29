package connectorruntime

import (
	"bytes"
	"os"
	"testing"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

func TestAppendDecisionEventCreatesParentDirectories(t *testing.T) {
	event := keiruntime.DecisionEvent{SpanID: "span-1", ToolName: "github.create_pr", Decision: "allow"}

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
	if err := keiruntime.AppendDecisionEvent("", 0, keiruntime.DecisionEvent{}); err != nil {
		t.Fatalf("empty path should be a no-op, got: %v", err)
	}
}
