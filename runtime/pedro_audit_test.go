package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestParseAuditLineAcceptsLegacyDecisionEventFields(t *testing.T) {
	event, ok := ParseAuditLine(`{"span_id":"legacy-1","decision":"allow"}`)
	if !ok {
		t.Fatal("ParseAuditLine rejected a valid decision with optional fields omitted")
	}
	if event.SpanID != "legacy-1" || event.Decision != "allow" {
		t.Fatalf("event = %+v, want legacy-1 allow", event)
	}
}

func TestParseAuditLineConvertsPedroAuditRecord(t *testing.T) {
	line := `{"invoked_at":"2026-09-24T21:00:00Z","user_id":"user-1","source":"discord","tool_name":"github.list_prs","args":{"query":"private"},"decision":{"action":"allow","reason":"policy"}}`
	event, ok := ParseAuditLine(line)
	if !ok {
		t.Fatal("ParseAuditLine rejected a Pedro audit record")
	}
	if event.InvokingSubject != "user-1" || event.Framework != "discord" || event.Decision != "allow" {
		t.Fatalf("event identity and decision = %+v", event)
	}
	if event.SpanID == "" || event.PolicyReason == nil || *event.PolicyReason != "policy" {
		t.Fatalf("event correlation fields = %+v", event)
	}
	want := sha256.Sum256([]byte(`{"query":"private"}`))
	if event.ToolArgsDigest == nil || *event.ToolArgsDigest != hex.EncodeToString(want[:]) {
		t.Fatalf("tool args digest = %v, want %x", event.ToolArgsDigest, want)
	}
	var forwarded map[string]any
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal converted event: %v", err)
	}
	if err := json.Unmarshal(encoded, &forwarded); err != nil {
		t.Fatalf("unmarshal converted event: %v", err)
	}
	if _, hasRawArgs := forwarded["args"]; hasRawArgs {
		t.Fatal("converted event forwarded raw tool arguments")
	}
}
