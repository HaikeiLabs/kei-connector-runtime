package mcproute

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// ADR-036 §4.9: each tools/list and tools/call writes exactly one audit
// record. It names the connector, the tool and the decision, and never holds
// an argument value, a token, a route key, a response body or a tool
// description. A failed audit write never changes the decision.

type recordingAuditor struct {
	mu      sync.Mutex
	records []AuditRecord
	err     error
}

func (a *recordingAuditor) Record(_ context.Context, rec AuditRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, rec)
	return a.err
}

func (a *recordingAuditor) only(t *testing.T) AuditRecord {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.records) != 1 {
		t.Fatalf("got %d audit records, want exactly 1: %+v", len(a.records), a.records)
	}
	return a.records[0]
}

// verdictAuthorizer permits every tool but "denied_tool", with a fixed verdict.
type verdictAuthorizer struct{}

func (verdictAuthorizer) Authorize(_ context.Context, d Decision) (Verdict, error) {
	v := Verdict{PolicyID: "pol-mcp-1", BundleVersion: 7, DenySource: "", Groups: []string{"analysts"}}
	if d.Tool == "denied_tool" {
		v.DenySource = "policy"
		return v, &PermissionError{Reason: "policy_denied", Tool: d.Tool}
	}
	return v, nil
}

const secretArgValue = "s3cret-argument-value-488"

func auditRig(t *testing.T, auditor Auditor) (*Handler, string, *listingUpstream, policybundle.MCPApprovedTool) {
	t.Helper()
	tool := map[string]any{"name": "search", "description": "the tool description text", "inputSchema": map[string]any{"type": "object"}}
	up := newListingUpstream(t, tool)
	approved := approvedTools(t, tool)
	cat := catalogFor(up.srv.URL, approved)
	h, _, key := catalogHandler(t, cat)
	h.config.Authorizer = verdictAuthorizer{}
	h.config.Auditor = auditor
	return h, key, up, approved[0]
}

func TestMCPAudit_PermittedCallRecord(t *testing.T) {
	aud := &recordingAuditor{}
	h, key, up, approved := auditRig(t, aud)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"q":"`+secretArgValue+`"}}}`))
	if up.calls.Load() != 1 {
		t.Fatalf("call not forwarded: %s", w.Body.Bytes())
	}

	rec := aud.only(t)
	want := AuditRecord{
		Event: "mcp.tools_call", Decision: "allow", PolicyID: "pol-mcp-1", BundleVersion: 7, BundleDigest: "bundle-1",
		SessionID: "test-session", AgentID: "test-agent", HarnessKind: "test-harness", UserID: "test-session", Groups: []string{"analysts"},
		ConnectorID: "conn-1", ConnectorSlug: "test-slug", Tool: "search", ToolHash: approved.ToolHash, ApprovedManifestHash: "sha256:approved",
		UpstreamHost: strings.TrimPrefix(up.srv.URL, "http://"), UpstreamStatus: 200,
	}
	if rec.DecisionID == "" || !uuidPattern.MatchString(rec.DecisionID) {
		t.Fatalf("decision_id = %q", rec.DecisionID)
	}
	if rec.ResponseBytes <= 0 || rec.DurationMS < 0 || rec.Forwarded != true {
		t.Fatalf("upstream metrics = bytes %d, ms %d, forwarded %v", rec.ResponseBytes, rec.DurationMS, rec.Forwarded)
	}
	if string(rec.Args) != `{"q":"`+secretArgValue+`"}` {
		t.Fatalf("Args = %s, want the call's arguments for the auditor to digest", rec.Args)
	}
	got := rec
	got.DecisionID, got.ResponseBytes, got.DurationMS, got.Forwarded, got.Args = "", 0, 0, false, nil
	if !equalRecords(got, want) {
		t.Fatalf("record\n got %+v\nwant %+v", got, want)
	}
}

func equalRecords(a, b AuditRecord) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

func TestMCPAudit_DenialRecordSharesTheDecisionID(t *testing.T) {
	for name, tc := range map[string]struct {
		body, reason string
	}{
		"policy":       {callBody("denied_tool"), "policy_denied"},
		"not approved": {callBody("unlisted_tool"), "mcp_tool_not_approved"},
		"arguments":    {`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":"x"}}`, "invalid_arguments"},
	} {
		t.Run(name, func(t *testing.T) {
			aud := &recordingAuditor{}
			h, key, up, _ := auditRig(t, aud)
			// "denied_tool" must be listed and approved to reach policy.
			denied := map[string]any{"name": "denied_tool", "description": "d", "inputSchema": map[string]any{"type": "object"}}
			search := map[string]any{"name": "search", "description": "the tool description text", "inputSchema": map[string]any{"type": "object"}}
			up.setTools(search, denied)
			cat := h.config.Catalog.(*fakeCatalog)
			cat.setApproval("test-slug", approvedTools(t, denied, search), "bundle-1")

			w := httptest.NewRecorder()
			h.ServeHTTP(w, routeRequest(key, tc.body))

			e := decodeRPCError(t, w.Body.Bytes())
			rec := aud.only(t)
			if rec.Decision != "deny" || rec.ReasonCode != tc.reason || rec.DecisionID != e.Data.DecisionID {
				t.Fatalf("record %+v, want deny %s with decision_id %s", rec, tc.reason, e.Data.DecisionID)
			}
			if rec.Forwarded || rec.UpstreamStatus != 0 || rec.ResponseBytes != 0 {
				t.Fatalf("a denied call carries upstream fields: %+v", rec)
			}
		})
	}
}

func TestMCPAudit_EveryDenialWritesOneRecord(t *testing.T) {
	aud := &recordingAuditor{}
	h, key, _, _ := auditRig(t, aud)
	req := routeRequest(key, callBody("search"))
	req.URL.Path = "/mcp/no_such_slug"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	rec := aud.only(t)
	if rec.ReasonCode != "connector_not_found" || rec.ConnectorSlug != "no_such_slug" || rec.Event != "mcp.tools_call" {
		t.Fatalf("record %+v", rec)
	}
}

func TestMCPAudit_ToolsListRecordCounts(t *testing.T) {
	aud := &recordingAuditor{}
	h, key, up, _ := auditRig(t, aud)
	denied := map[string]any{"name": "denied_tool", "description": "d", "inputSchema": map[string]any{"type": "object"}}
	search := map[string]any{"name": "search", "description": "the tool description text", "inputSchema": map[string]any{"type": "object"}}
	up.setTools(search, denied)
	h.config.Catalog.(*fakeCatalog).setApproval("test-slug", approvedTools(t, denied, search), "bundle-1")

	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, listBody))

	rec := aud.only(t)
	if rec.Event != "mcp.tools_list" || rec.Decision != "allow" || rec.Listed != 1 || rec.HiddenByPolicy != 1 || rec.Unapproved != 0 || rec.Tool != "" {
		t.Fatalf("tools_list record %+v, want listed 1 hidden 1 unapproved 0", rec)
	}
}

func TestMCPAudit_ToolsListDriftCountsUnapprovedTools(t *testing.T) {
	aud := &recordingAuditor{}
	h, key, up, _ := auditRig(t, aud)
	extra1 := map[string]any{"name": "extra_1", "description": "x", "inputSchema": map[string]any{}}
	extra2 := map[string]any{"name": "extra_2", "description": "y", "inputSchema": map[string]any{}}
	search := map[string]any{"name": "search", "description": "the tool description text", "inputSchema": map[string]any{"type": "object"}}
	up.setTools(search, extra1, extra2)

	h.ServeHTTP(httptest.NewRecorder(), routeRequest(key, listBody))

	rec := aud.only(t)
	if rec.Decision != "deny" || rec.ReasonCode != "mcp_manifest_drift" || rec.Listed != 0 || rec.Unapproved != 2 {
		t.Fatalf("drift record %+v, want deny mcp_manifest_drift listed 0 unapproved 2", rec)
	}
}

func TestMCPAudit_FailedWriteDoesNotChangeTheDecision(t *testing.T) {
	aud := &recordingAuditor{err: errors.New("spool full")}
	h, key, up, _ := auditRig(t, aud)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("search")))

	if up.calls.Load() != 1 || strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("the audit failure changed the call: %s", w.Body.Bytes())
	}
}

func TestMCPAudit_UnauthenticatedRequestsAreNotRecorded(t *testing.T) {
	aud := &recordingAuditor{}
	h, _, _, _ := auditRig(t, aud)
	h.ServeHTTP(httptest.NewRecorder(), routeRequest("kmr_unknown", callBody("search")))
	if len(aud.records) != 0 {
		t.Fatalf("recorded %+v for a request without a session", aud.records)
	}
}

// fakeSealer stands in for auditcrypto.Provider.
type fakeSealer struct {
	recipients []string
	sealed     [][]byte
}

func (s *fakeSealer) Digest(b []byte) (string, string) { return "hmac-sha256:digest-of-args", "dk-1" }
func (s *fakeSealer) Encrypt(b []byte) (string, []string) {
	s.sealed = append(s.sealed, append([]byte(nil), b...))
	if len(s.recipients) == 0 {
		return "", nil
	}
	return "age-ciphertext", s.recipients
}

func recordOnce(t *testing.T, sealer ArgsSealer) map[string]any {
	t.Helper()
	var lines [][]byte
	a := SpoolAuditor{
		Append: func(class string, record []byte) error {
			if class != "decision" {
				t.Fatalf("event class %q, want decision", class)
			}
			lines = append(lines, record)
			return nil
		},
		Sealer: sealer,
		Scope:  func() (string, string, string) { return "org-1", "ws-1", "inst-1" },
	}
	rec := AuditRecord{
		Event: "mcp.tools_call", DecisionID: "6f1c2b6e-1d2a-4c3b-9e8f-0a1b2c3d4e5f", Decision: "allow", PolicyID: "pol-1",
		BundleVersion: 7, BundleDigest: "sha256:bundle", SessionID: "ks_1", AgentID: "agent-1", HarnessKind: "claude_code",
		UserID: "user-1", Groups: []string{"analysts"}, ConnectorID: "conn-1", ConnectorSlug: "grafana_prod", Template: "grafana",
		Tool: "search", ToolHash: "sha256:tool", ApprovedManifestHash: "sha256:manifest", Args: json.RawMessage(`{"q":"` + secretArgValue + `"}`),
		Forwarded: true, UpstreamHost: "mcp.grafana.example", UpstreamStatus: 200, ResponseBytes: 42, DurationMS: 3,
	}
	if err := a.Record(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 {
		t.Fatalf("%d spool lines", len(lines))
	}
	if strings.Contains(string(lines[0]), secretArgValue) {
		t.Fatalf("spool record carries an argument value: %s", lines[0])
	}
	var out map[string]any
	if err := json.Unmarshal(lines[0], &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSpoolAuditor_WritesADecisionEventSuperset(t *testing.T) {
	out := recordOnce(t, &fakeSealer{})
	for k, want := range map[string]any{
		// DecisionEvent fields the existing collector ships.
		"span_id": "6f1c2b6e-1d2a-4c3b-9e8f-0a1b2c3d4e5f", "invoking_subject": "user:user-1", "agent_id": "agent-1", "framework": "claude_code",
		"tool_name": "mcp:grafana_prod.search", "decision": "allow", "policy_id": "pol-1", "org_id": "org-1", "workspace_id": "ws-1",
		"policy_bundle_version": float64(7), "policy_bundle_digest": "sha256:bundle", "tool_args_digest": "hmac-sha256:digest-of-args",
		// ADR-036 §4.9 fields.
		"event": "mcp.tools_call", "decision_id": "6f1c2b6e-1d2a-4c3b-9e8f-0a1b2c3d4e5f", "installation_id": "inst-1", "harness_kind": "claude_code",
		"connector_id": "conn-1", "connector_slug": "grafana_prod", "template": "grafana", "tool": "search", "tool_hash": "sha256:tool",
		"approved_manifest_hash": "sha256:manifest", "args_digest": "hmac-sha256:digest-of-args", "digest_key_id": "dk-1",
		"upstream_host": "mcp.grafana.example", "upstream_status": float64(200), "response_bytes": float64(42), "is_error": false,
	} {
		if out[k] != want {
			t.Errorf("%s = %#v, want %#v", k, out[k], want)
		}
	}
	if _, ok := out["args_ciphertext"]; ok {
		t.Fatal("args_ciphertext written without an audit encryption key")
	}
	subject, _ := out["subject"].(map[string]any)
	if subject["user_id"] != "user-1" {
		t.Fatalf("subject = %#v", out["subject"])
	}
}

func TestSpoolAuditor_EncryptsArgumentsOnlyWithACustomerKey(t *testing.T) {
	sealer := &fakeSealer{recipients: []string{"ak-customer-1"}}
	out := recordOnce(t, sealer)

	if out["args_ciphertext"] != "age-ciphertext" {
		t.Fatalf("args_ciphertext = %#v", out["args_ciphertext"])
	}
	ids, _ := out["recipient_key_ids"].([]any)
	if len(ids) != 1 || ids[0] != "ak-customer-1" {
		t.Fatalf("recipient_key_ids = %#v", out["recipient_key_ids"])
	}
	if len(sealer.sealed) != 1 || !strings.Contains(string(sealer.sealed[0]), secretArgValue) {
		t.Fatalf("sealer saw %q, want the arguments", sealer.sealed)
	}
}

func TestSpoolAuditor_ListRecordHasNoToolOrArgs(t *testing.T) {
	var line []byte
	a := SpoolAuditor{Append: func(_ string, r []byte) error { line = r; return nil }, Scope: func() (string, string, string) { return "o", "w", "i" }}
	if err := a.Record(context.Background(), AuditRecord{Event: "mcp.tools_list", DecisionID: "d", Decision: "allow", ConnectorSlug: "s", Listed: 3, HiddenByPolicy: 1}); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.Unmarshal(line, &out)
	if out["tool_name"] != "mcp:s" || out["listed"] != float64(3) || out["hidden_by_policy"] != float64(1) {
		t.Fatalf("list record %s", line)
	}
	for _, k := range []string{"tool", "tool_hash", "args_digest", "tool_args_digest", "upstream_host"} {
		if _, ok := out[k]; ok {
			t.Errorf("list record carries %s", k)
		}
	}
}
