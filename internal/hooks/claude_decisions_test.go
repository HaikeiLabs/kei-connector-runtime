package hooks

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// claudeScenario defines one ADR scenario row.
type claudeScenario struct {
	events []string            // JSON lines, one per hook invocation
	expect []expectedAuditStep // audit events in order
}

type expectedAuditStep struct {
	Phase          string `json:"phase"`
	NativeDecision string `json:"native_decision"`
	ToolUseID      string `json:"tool_use_id,omitempty"`
	Failed         bool   `json:"failed,omitempty"`
}

func TestClaudeDecisionsGoldenFixtures(t *testing.T) {
	dir := filepath.Join("testdata", "claude_decisions")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		t.Run(strings.TrimSuffix(entry.Name(), ".json"), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			scenario := parseScenarioFixture(t, data)
			runClaudeScenario(t, scenario)
		})
	}
}

// parseScenarioFixture reads a fixture file containing a JSON array of event
// input objects and optionally a top-level "expect" array.
func parseScenarioFixture(t *testing.T, data []byte) claudeScenario {
	t.Helper()

	// Try as a raw array of event objects.
	var rawEvents []json.RawMessage
	if json.Unmarshal(data, &rawEvents) == nil {
		var events []string
		for _, re := range rawEvents {
			b, _ := json.Marshal(re)
			events = append(events, string(b))
		}
		return claudeScenario{events: events}
	}

	// Try as {"events":[...],"expect":[...]}.
	var envelope struct {
		Events []json.RawMessage   `json:"events"`
		Expect []expectedAuditStep `json:"expect"`
	}
	if json.Unmarshal(data, &envelope) == nil && len(envelope.Events) > 0 {
		var events []string
		for _, re := range envelope.Events {
			b, _ := json.Marshal(re)
			events = append(events, string(b))
		}
		return claudeScenario{events: events, expect: envelope.Expect}
	}

	t.Fatalf("cannot parse fixture (len=%d)", len(data))
	return claudeScenario{}
}

// runClaudeScenario feeds each event through ReportPermissions in sequence
// and verifies the audit trail.
func runClaudeScenario(t *testing.T, s claudeScenario) {
	t.Helper()

	stateDir := t.TempDir()
	var spool bytes.Buffer
	cfg := Config{
		RuntimeStateDir: stateDir,
		AppendAudit: func(record []byte) error {
			spool.Write(record)
			spool.WriteByte('\n')
			return nil
		},
	}

	for i, eventJSON := range s.events {
		var stdout bytes.Buffer
		code := ReportPermissions(
			[]string{"claude", "--harness", "h-claude-test"},
			strings.NewReader(eventJSON),
			&stdout,
			cfg,
		)
		if code != 0 {
			t.Fatalf("step %d: exit code = %d, stdout=%q, input=%s", i, code, stdout.String(), eventJSON)
		}
		if stdout.Len() != 0 {
			t.Fatalf("step %d: hook wrote output: %q, input=%s", i, stdout.String(), eventJSON)
		}
	}

	// Collect audit lines.
	auditLines := strings.Split(strings.TrimSpace(spool.String()), "\n")
	if len(auditLines) == 0 || (len(auditLines) == 1 && auditLines[0] == "") {
		auditLines = nil
	}

	// If the fixture specifies expected steps, verify against them.
	if s.expect != nil {
		verifyAuditSteps(t, auditLines, s.expect)
		return
	}

	// Otherwise verify scenario-agnostic invariants.
	verifyInvariants(t, auditLines, filepath.Base(t.Name()))
}

func verifyAuditSteps(t *testing.T, lines []string, expect []expectedAuditStep) {
	t.Helper()
	if len(lines) != len(expect) {
		t.Fatalf("got %d audit lines, want %d\n  got:  %s\n  want: %+v",
			len(lines), len(expect), strings.Join(lines, "\n  "), expect)
	}
	for i, line := range lines {
		var ev permissionEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("line %d: bad json: %v", i, err)
		}
		if ev.Phase != expect[i].Phase {
			t.Errorf("line %d: phase = %q, want %q", i, ev.Phase, expect[i].Phase)
		}
		if ev.NativeDecision != expect[i].NativeDecision {
			t.Errorf("line %d: native_decision = %q, want %q", i, ev.NativeDecision, expect[i].NativeDecision)
		}
		if ev.ToolUseID != expect[i].ToolUseID {
			t.Errorf("line %d: tool_use_id = %q, want %q", i, ev.ToolUseID, expect[i].ToolUseID)
		}
		if ev.Failed != expect[i].Failed {
			t.Errorf("line %d: failed = %v, want %v", i, ev.Failed, expect[i].Failed)
		}
	}
}

// verifyInvariants checks basic properties of the audit trail when no explicit
// expected steps are provided (golden fixture mode).
func verifyInvariants(t *testing.T, lines []string, name string) {
	t.Helper()
	if len(lines) == 0 {
		t.Fatal("no audit events emitted")
	}
	var hasEvents bool
	for _, line := range lines {
		var ev permissionEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad json in audit: %v", err)
		}
		if ev.Schema != "kei.harness-tool-event/v1" {
			t.Errorf("schema = %q, want kei.harness-tool-event/v1", ev.Schema)
		}
		if ev.HarnessKind != "claude" {
			t.Errorf("harness_kind = %q", ev.HarnessKind)
		}
		if ev.HarnessID != "h-claude-test" {
			t.Errorf("harness_id = %q", ev.HarnessID)
		}
		hasEvents = true
	}
	if !hasEvents {
		t.Fatal("no valid audit events")
	}
	_ = name
}

// TestClaudeDecisionsParallelCalls verifies that interleaved tool calls in the
// same session are paired correctly (oldest-first for PermissionRequest).
func TestClaudeDecisionsParallelCalls(t *testing.T) {
	stateDir := t.TempDir()
	var spool bytes.Buffer
	cfg := Config{
		RuntimeStateDir: stateDir,
		AppendAudit: func(record []byte) error {
			spool.Write(record)
			spool.WriteByte('\n')
			return nil
		},
	}

	events := []string{
		`{"tool_name":"Bash","tool_input":{"command":"slow"},"session_id":"s-parallel","tool_use_id":"tu1","hook_event_name":"PreToolUse","native_decision":"ask"}`,
		`{"tool_name":"Bash","tool_input":{"command":"slow"},"session_id":"s-parallel","tool_use_id":"tu2","hook_event_name":"PreToolUse","native_decision":"ask"}`,
		`{"tool_name":"Bash","tool_input":{"command":"slow"},"session_id":"s-parallel","hook_event_name":"PermissionRequest"}`,
		`{"tool_name":"Bash","tool_input":{"command":"slow"},"session_id":"s-parallel","tool_use_id":"tu2","hook_event_name":"PostToolUse"}`,
		`{"session_id":"s-parallel","hook_event_name":"Stop"}`,
	}

	for _, ev := range events {
		var stdout bytes.Buffer
		if code := ReportPermissions([]string{"claude", "--harness", "h-test"}, strings.NewReader(ev), &stdout, cfg); code != 0 || stdout.Len() != 0 {
			t.Fatalf("exit=%d stdout=%q input=%s", code, stdout.String(), ev)
		}
	}

	lines := strings.Split(strings.TrimSpace(spool.String()), "\n")
	// Expected: pre:unknown(tu1), pre:unknown(tu2), decision:ask(tu1),
	//           permission_reply:approved(tu2), post:executed(tu2),
	//           permission_reply:denied(tu1)
	if len(lines) != 6 {
		t.Fatalf("got %d audit lines, want 6\n%s", len(lines), spool.String())
	}
	expect := []expectedAuditStep{
		{Phase: "pre", NativeDecision: "unknown", ToolUseID: "tu1"},
		{Phase: "pre", NativeDecision: "unknown", ToolUseID: "tu2"},
		{Phase: "decision", NativeDecision: "ask", ToolUseID: "tu1"},
		{Phase: "decision", NativeDecision: "allow", ToolUseID: "tu2"},
		{Phase: "post", NativeDecision: "executed", ToolUseID: "tu2"},
		{Phase: "permission_reply", NativeDecision: "denied", ToolUseID: "tu1"},
	}
	verifyAuditSteps(t, lines, expect)
}

// TestClaudeDecisionsSessionEnd verifies that SessionEnd closes pending calls
// and deletes the session so subsequent events start fresh.
func TestClaudeDecisionsSessionEnd(t *testing.T) {
	stateDir := t.TempDir()
	var spool bytes.Buffer
	cfg := Config{
		RuntimeStateDir: stateDir,
		AppendAudit: func(record []byte) error {
			spool.Write(record)
			spool.WriteByte('\n')
			return nil
		},
	}

	// First session: PreToolUse → SessionEnd (emits pre + decision:deny)
	events := []string{
		`{"tool_name":"Bash","tool_input":{"command":"x"},"session_id":"s-end","tool_use_id":"tu1","hook_event_name":"PreToolUse","native_decision":"ask"}`,
		`{"session_id":"s-end","hook_event_name":"SessionEnd"}`,
	}
	for _, ev := range events {
		var stdout bytes.Buffer
		if code := ReportPermissions([]string{"claude", "--harness", "h-test"}, strings.NewReader(ev), &stdout, cfg); code != 0 || stdout.Len() != 0 {
			t.Fatalf("exit=%d stdout=%q input=%s", code, stdout.String(), ev)
		}
	}

	lines := strings.Split(strings.TrimSpace(spool.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("first session: got %d lines, want 2\n%s", len(lines), spool.String())
	}
	expect := []expectedAuditStep{
		{Phase: "pre", NativeDecision: "unknown", ToolUseID: "tu1"},
		{Phase: "decision", NativeDecision: "deny", ToolUseID: "tu1"},
	}
	verifyAuditSteps(t, lines, expect)

	// Second session: fresh call with same session ID should work as new
	var stdout bytes.Buffer
	code := ReportPermissions(
		[]string{"claude", "--harness", "h-test"},
		strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"y"},"session_id":"s-end","tool_use_id":"tu2","hook_event_name":"PreToolUse","native_decision":"ask"}`),
		&stdout,
		cfg,
	)
	if code != 0 || stdout.Len() != 0 {
		t.Fatalf("second session: exit=%d stdout=%q", code, stdout.String())
	}

	lines = strings.Split(strings.TrimSpace(spool.String()), "\n")
	// Should now have 3 lines: pre:unknown(tu1), decision:deny(tu1), pre:unknown(tu2)
	if len(lines) != 3 {
		t.Fatalf("after second call: got %d lines, want 3\n%s", len(lines), spool.String())
	}
	var ev permissionEvent
	if err := json.Unmarshal([]byte(lines[2]), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Phase != "pre" || ev.NativeDecision != "unknown" || ev.ToolUseID != "tu2" {
		t.Fatalf("third event: %+v", ev)
	}
}

// TestClaudeDecisionsStaleCleanup verifies that stale sessions (>24h) are
// closed (emit deny/denied) and deleted, and that fresh sessions are untouched.
func TestClaudeDecisionsStaleCleanup(t *testing.T) {
	stateDir := t.TempDir()
	var spool bytes.Buffer
	cfg := Config{
		RuntimeStateDir: stateDir,
		AppendAudit: func(record []byte) error {
			spool.Write(record)
			spool.WriteByte('\n')
			return nil
		},
	}

	store, err := OpenClaudeDecisionStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	// Session A: stale, one unasked call → should emit decision:deny.
	if err := store.Add("s-stale-unasked", pendingCall{
		ToolUseID: "sa1", ToolName: "shell", ArgsDigest: "sha256:a",
		CreatedAt: time.Now().UTC().Add(-48 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// Session B: stale, one asked-but-undecided call → should emit permission_reply:denied.
	if err := store.Add("s-stale-asked", pendingCall{
		ToolUseID: "sb1", ToolName: "shell", ArgsDigest: "sha256:b",
		Asked: true, CreatedAt: time.Now().UTC().Add(-48 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// Session C: fresh, unasked call → left alone (not closed, not deleted).
	if err := store.Add("s-fresh", pendingCall{
		ToolUseID: "sc1", ToolName: "shell", ArgsDigest: "sha256:c",
		CreatedAt: time.Now().UTC().Add(-1 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// Trigger stale cleanup via a PreToolUse that also adds a new entry.
	var stdout bytes.Buffer
	code := ReportPermissions(
		[]string{"claude", "--harness", "h-test"},
		strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"trigger"},"session_id":"s-fresh","tool_use_id":"sc2","hook_event_name":"PreToolUse","native_decision":"ask"}`),
		&stdout,
		cfg,
	)
	if code != 0 || stdout.Len() != 0 {
		t.Fatalf("exit=%d stdout=%q", code, stdout.String())
	}

	lines := strings.Split(strings.TrimSpace(spool.String()), "\n")
	// Expected: close events for sa1 and sb1 (map order, non-deterministic),
	// then pre:unknown(sc2) from the triggering PreToolUse.
	if len(lines) != 3 {
		t.Fatalf("got %d audit lines, want 3\n%s", len(lines), spool.String())
	}

	// The last line should always be the current handler's pre event.
	var lastEv permissionEvent
	if err := json.Unmarshal([]byte(lines[2]), &lastEv); err != nil {
		t.Fatal(err)
	}
	if lastEv.Phase != "pre" || lastEv.NativeDecision != "unknown" || lastEv.ToolUseID != "sc2" {
		t.Fatalf("expected pre:unknown(sc2) last, got %s/%s/%s", lastEv.Phase, lastEv.NativeDecision, lastEv.ToolUseID)
	}

	// The first two lines are the close events in any order.
	closeEvents := make(map[string]expectedAuditStep)
	for _, line := range lines[:2] {
		var ev permissionEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatal(err)
		}
		closeEvents[ev.ToolUseID] = expectedAuditStep{Phase: ev.Phase, NativeDecision: ev.NativeDecision}
	}

	sa1, ok := closeEvents["sa1"]
	if !ok {
		t.Fatalf("missing close event for sa1; got keys: %v", keysOf(closeEvents))
	}
	if sa1.Phase != "decision" || sa1.NativeDecision != "deny" {
		t.Fatalf("sa1: expected decision:deny, got %s:%s", sa1.Phase, sa1.NativeDecision)
	}

	sb1, ok := closeEvents["sb1"]
	if !ok {
		t.Fatalf("missing close event for sb1; got keys: %v", keysOf(closeEvents))
	}
	if sb1.Phase != "permission_reply" || sb1.NativeDecision != "denied" {
		t.Fatalf("sb1: expected permission_reply:denied, got %s:%s", sb1.Phase, sb1.NativeDecision)
	}

	// Verify stale sessions were deleted and fresh session still exists.
	ids, err := store.AllSessionIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "s-fresh" {
		t.Fatalf("expected only s-fresh, got %v", ids)
	}

	// Verify s-fresh still has sc1 (unasked) and sc2 (the new pre entry).
	calls, err := store.UndecidedCalls("s-fresh")
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 undecided calls in s-fresh, got %d", len(calls))
	}
}

// keysOf returns the string keys of m for use in error messages.
func keysOf[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// TestClaudeDecisionsStopAfterDenied verifies that Stop does not double-emit
// for a call already closed by PermissionDenied.
func TestClaudeDecisionsStopAfterDenied(t *testing.T) {
	stateDir := t.TempDir()
	var spool bytes.Buffer
	cfg := Config{
		RuntimeStateDir: stateDir,
		AppendAudit: func(record []byte) error {
			spool.Write(record)
			spool.WriteByte('\n')
			return nil
		},
	}

	events := []string{
		`{"tool_name":"Bash","tool_input":{"command":"blocked"},"session_id":"s-deny-then-stop","tool_use_id":"tu1","hook_event_name":"PreToolUse","native_decision":"ask"}`,
		`{"tool_name":"Bash","tool_input":{"command":"blocked"},"session_id":"s-deny-then-stop","hook_event_name":"PermissionDenied"}`,
		`{"session_id":"s-deny-then-stop","hook_event_name":"Stop"}`,
	}
	for _, ev := range events {
		var stdout bytes.Buffer
		if code := ReportPermissions([]string{"claude", "--harness", "h-test"}, strings.NewReader(ev), &stdout, cfg); code != 0 || stdout.Len() != 0 {
			t.Fatalf("exit=%d stdout=%q input=%s", code, stdout.String(), ev)
		}
	}

	lines := strings.Split(strings.TrimSpace(spool.String()), "\n")
	// Expected: pre:unknown(tu1), decision:deny(tu1) - Stop should not add anything
	if len(lines) != 2 {
		t.Fatalf("got %d audit lines, want 2\n%s", len(lines), spool.String())
	}
	expect := []expectedAuditStep{
		{Phase: "pre", NativeDecision: "unknown", ToolUseID: "tu1"},
		{Phase: "decision", NativeDecision: "deny", ToolUseID: "tu1"},
	}
	verifyAuditSteps(t, lines, expect)
}

// TestClaudeDecisionsCloseCarriesPendingTool verifies that a decision closed
// by Stop describes the pending call, not the Stop event: Stop carries no
// tool_name or tool_input, so the closing record must take the tool and the
// args digest from the call it closes. An empty tool is rejected by the
// catalog's harness-tool-events:batchCreate and wedged the spool.
func TestClaudeDecisionsCloseCarriesPendingTool(t *testing.T) {
	stateDir := t.TempDir()
	var spool bytes.Buffer
	cfg := Config{
		RuntimeStateDir: stateDir,
		AppendAudit: func(record []byte) error {
			spool.Write(record)
			spool.WriteByte('\n')
			return nil
		},
	}
	events := []string{
		`{"tool_name":"Bash","tool_input":{"command":"ls -la"},"session_id":"s-close","tool_use_id":"tu1","hook_event_name":"PreToolUse"}`,
		`{"session_id":"s-close","hook_event_name":"Stop"}`,
	}
	for _, ev := range events {
		var stdout bytes.Buffer
		if code := ReportPermissions([]string{"claude", "--harness", "h-test"}, strings.NewReader(ev), &stdout, cfg); code != 0 {
			t.Fatalf("exit=%d input=%s", code, ev)
		}
	}
	lines := strings.Split(strings.TrimSpace(spool.String()), "\n")
	verifyAuditSteps(t, lines, []expectedAuditStep{
		{Phase: "pre", NativeDecision: "unknown", ToolUseID: "tu1"},
		{Phase: "decision", NativeDecision: "deny", ToolUseID: "tu1"},
	})
	var pre, closing permissionEvent
	if err := json.Unmarshal([]byte(lines[0]), &pre); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &closing); err != nil {
		t.Fatal(err)
	}
	if closing.Tool != "shell" {
		t.Fatalf("closing tool = %q, want shell", closing.Tool)
	}
	if closing.ArgsDigest != pre.ArgsDigest {
		t.Fatalf("closing args_digest = %q, want the pending call's %q", closing.ArgsDigest, pre.ArgsDigest)
	}
	if closing.ArgsCiphertext != "" || closing.Argv0 != "" {
		t.Fatalf("closing record carries the Stop event's args: ciphertext=%q argv0=%q", closing.ArgsCiphertext, closing.Argv0)
	}
}
