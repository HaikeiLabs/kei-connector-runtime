package runtime

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
)

// flushBody sends records through the real audit:flush client and returns
// the record objects the catalog received.
func flushBody(t *testing.T, records []DecisionEvent) []map[string]json.RawMessage {
	t.Helper()
	var got []map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		var body struct {
			Records []map[string]json.RawMessage `json:"records"`
		}
		if err := json.Unmarshal(data, &body); err != nil {
			t.Errorf("flush body is not JSON: %v", err)
		}
		got = append(got, body.Records...)
		n := len(body.Records)
		_ = json.NewEncoder(w).Encode(map[string]int{"upserted": n, "received": n, "skipped": 0})
	}))
	defer srv.Close()
	client := &abacFlushClient{baseURL: srv.URL, path: "/api/v1/runtime/audit:flush", client: srv.Client()}
	if _, err := client.Flush(context.Background(), records); err != nil {
		t.Fatalf("flush: %v", err)
	}
	return got
}

func parseSpoolLine(t *testing.T, line []byte) DecisionEvent {
	t.Helper()
	e, ok := ParseAuditLine(string(line))
	if !ok {
		t.Fatalf("spool line did not parse: %s", line)
	}
	return e
}

func TestCollectorForwardsCredentialKind(t *testing.T) {
	l := &LocalPDP{Sessions: pdp.NewSessions()}
	release := l.decisionEventJSON(socketAuthorizeRequest{
		Schema: "kei.credential-release-request/v1", AgentID: "agent-1", OnBehalfOf: "user:u-2",
		Connector: &socketAuthorizeConnector{ConnectorID: "c-1", Capability: "lead.read"}, Resource: "leads/42",
	}, "sess-1", pdp.Decision{Allow: true}, CredentialKindOAuth)
	// The serve daemon's kei-proxy run access record (internal/run).
	runAccess := []byte(`{"span_id":"s-run","invoked_at":"2026-11-02T00:00:00Z","invoking_subject":"user:u-1","delegation_depth":0,"agent_id":"","framework":"kei-proxy-run","tool_name":"connector:c-2/credential","resources_touched":["kei://connectors/c-2/api_key"],"decision":"allow","credential_kind":"secret_store"}`)

	for name, tc := range map[string]struct {
		line []byte
		kind string
	}{
		"credential release": {release, `"oauth"`},
		"kei-proxy run use":  {runAccess, `"secret_store"`},
	} {
		recs := flushBody(t, []DecisionEvent{parseSpoolLine(t, tc.line)})
		if len(recs) != 1 {
			t.Fatalf("%s: flushed %d records", name, len(recs))
		}
		if got := string(recs[0]["credential_kind"]); got != tc.kind {
			t.Errorf("%s: flush body credential_kind = %s, want %s", name, got, tc.kind)
		}
		// Release status and session state stay in the runtime session.
		for _, k := range []string{"credential_released", "session_id", "on_behalf_of"} {
			if _, ok := recs[0][k]; ok {
				t.Errorf("%s: flush body carries %s", name, k)
			}
		}
	}
}

// catalogFieldsBeforeCredentialKind is the record field set the catalog's
// audit:flush accepted before credential_kind (kei-policy-catalog
// pkg/auditrecord AuditRecord, which decodes with DisallowUnknownFields).
var catalogFieldsBeforeCredentialKind = map[string]bool{
	"span_id": true, "invoked_at": true, "invoking_subject": true, "on_behalf_of": true,
	"parent_span": true, "delegation_depth": true, "agent_id": true, "agent_version": true,
	"framework": true, "tool_name": true, "tool_args_digest": true, "resources_touched": true,
	"decision": true, "policy_id": true, "policy_reason": true, "org_id": true, "workspace_id": true,
	"policy_bundle_version": true, "policy_bundle_digest": true, "policy_revision": true,
	"bundle_state": true, "deny_source": true, "reason_code": true,
	"caller_harness": true, "caller_origin": true, "caller_session_ref": true, "session_id": true,
}

// A decision that handed out no credential sends only fields an older
// catalog accepts, so this runtime keeps working against it for every record
// except a credential access.
func TestCollectorDecisionWithoutCredentialKeepsOlderCatalogFields(t *testing.T) {
	l := &LocalPDP{Sessions: pdp.NewSessions()}
	digest := "sha256:abc"
	authorize := l.decisionEventJSON(socketAuthorizeRequest{
		Schema: authorizeRequestSchema, Tool: "web_search", AgentID: "agent-1", Resource: "r-1",
		OnBehalfOf: "user:u-2", ParentSpan: "p-1", ToolArgsDigest: "d-1",
	}, "sess-1", pdp.Decision{Allow: true, PolicyID: "pol-1", Reason: "ok", BundleVersion: 3, BundleDigest: digest, PolicyRevision: 2}, "")
	deniedRelease := l.decisionEventJSON(socketAuthorizeRequest{
		Schema: "kei.credential-release-request/v1", Connector: &socketAuthorizeConnector{ConnectorID: "c-1", Capability: "lead.read"},
	}, "sess-1", pdp.Decision{ReasonCode: "credential_not_connected", DenySource: "runtime_state"}, "")
	legacy := DecisionEvent{SpanID: "legacy-1", InvokedAt: time.Unix(0, 0).UTC(), InvokingSubject: "user:u", ToolName: "t", Decision: "deny", ResourcesTouched: []string{}}

	for name, e := range map[string]DecisionEvent{
		"socket authorize": parseSpoolLine(t, authorize),
		"denied release":   parseSpoolLine(t, deniedRelease),
		"one-shot":         legacy,
	} {
		for k := range flushBody(t, []DecisionEvent{e})[0] {
			if !catalogFieldsBeforeCredentialKind[k] {
				t.Errorf("%s: flush body carries %s, which an older catalog rejects", name, k)
			}
		}
	}
}

func TestDecisionEventUsesCapturedSubjectAfterSessionEnds(t *testing.T) {
	sessions := pdp.NewSessions()
	sessionID, err := sessions.Create(pdp.Subject{UserID: "u-alice", Status: pdp.StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	local := &LocalPDP{Sessions: sessions}
	if !sessions.EndID(sessionID) {
		t.Fatal("session did not end")
	}

	d := pdp.Decision{AuditSubject: "user:u-alice"}
	event := parseSpoolLine(t, local.decisionEventJSON(socketAuthorizeRequest{Tool: "custom.read"}, sessionID, d, ""))
	if event.InvokingSubject != d.AuditSubject {
		t.Fatalf("invoking_subject=%q, want captured subject %q", event.InvokingSubject, d.AuditSubject)
	}
	var fields map[string]json.RawMessage
	encoded, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if _, exposed := fields["AuditSubject"]; exposed {
		t.Fatal("audit-only subject appeared in serialized decision")
	}
}
