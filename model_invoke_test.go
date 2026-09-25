package connectorruntime

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// TestLogModelInvokeEmitsStructuredJSON verifies the proxy diagnostic shape
// (KEI-108): a single JSON line with structured fields and no credential
// material.
func TestLogModelInvokeEmitsStructuredJSON(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	logModelInvoke(ModelInvokeLog{
		RequestID:  "req1",
		OrgID:      "org1",
		AgentID:    "agent1",
		UserID:     "user1",
		ProfileID:  "profile1",
		Outcome:    "success",
		DurationMs: 123,
	})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one log line, got %d: %s", len(lines), buf.String())
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &event); err != nil {
		t.Fatalf("log line is not valid JSON: %v\n%s", err, lines[0])
	}
	if event["request_id"] != "req1" || event["outcome"] != "success" || event["duration_ms"] != float64(123) {
		t.Errorf("unexpected fields: %v", event)
	}
}
