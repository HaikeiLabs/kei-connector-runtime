package runtime

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/authorizerequest"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
)

// flushBodyRecords sends records through the real audit:flush client and
// returns the JSON objects the catalog received, keyed by field name.
func flushBodyRecords(t *testing.T, records []DecisionEvent) []map[string]json.RawMessage {
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

// spoolDecision runs a socket decision event through the spool line format and
// the collector's parser, the same path the daemon's audit takes.
func spoolDecision(t *testing.T, raw json.RawMessage) DecisionEvent {
	t.Helper()
	e, ok := ParseAuditLine(string(raw))
	if !ok {
		t.Fatalf("spool line did not parse: %s", raw)
	}
	return e
}

func TestCollectorForwardsCredentialReleaseFields(t *testing.T) {
	l := &LocalPDP{Sessions: pdp.NewSessions()}
	for _, released := range []bool{true, false} {
		req := socketAuthorizeRequest{
			Schema: "kei.credential-release-request/v1", AgentID: "agent-1",
			Connector: &socketAuthorizeConnector{ConnectorID: "c-1", Capability: "lead.read"},
			Resource:  "leads/42", OnBehalfOf: "user:u-2",
		}
		raw := l.decisionEventJSON(req, "sess-1", pdp.Decision{Allow: true}, &released)
		recs := flushBodyRecords(t, []DecisionEvent{spoolDecision(t, raw)})
		if len(recs) != 1 {
			t.Fatalf("flushed %d records, want 1", len(recs))
		}
		rec := recs[0]
		want := map[string]string{
			"credential_released": map[bool]string{true: "true", false: "false"}[released],
			"session_id":          `"sess-1"`,
			"on_behalf_of":        `"user:u-2"`,
		}
		for k, v := range want {
			if string(rec[k]) != v {
				t.Errorf("released=%v: flush body %s = %s, want %s", released, k, rec[k], v)
			}
		}
	}
}

// catalogFlushFieldsBeforeCredentialReleased is the record field set an
// audit:flush catalog accepted before credential_released was added
// (kei-policy-catalog pkg/auditrecord AuditRecord). The catalog decodes with
// DisallowUnknownFields, so any other field fails the whole batch there.
var catalogFlushFieldsBeforeCredentialReleased = map[string]bool{
	"span_id": true, "invoked_at": true, "invoking_subject": true, "on_behalf_of": true,
	"parent_span": true, "delegation_depth": true, "agent_id": true, "agent_version": true,
	"framework": true, "tool_name": true, "tool_args_digest": true, "resources_touched": true,
	"decision": true, "policy_id": true, "policy_reason": true, "org_id": true, "workspace_id": true,
	"policy_bundle_version": true, "policy_bundle_digest": true, "policy_revision": true,
	"bundle_state": true, "deny_source": true, "reason_code": true,
	"caller_harness": true, "caller_origin": true, "caller_session_ref": true, "session_id": true,
}

func TestCollectorDecisionWithoutReleaseKeepsOlderCatalogFields(t *testing.T) {
	l := &LocalPDP{Sessions: pdp.NewSessions()}
	digest, version := "sha256:abc", int64(3)
	harness, origin, ref := "openwebui", "interactive", "chat:1"
	full := socketAuthorizeRequest{
		Schema: authorizeRequestSchema, Tool: "web_search", AgentID: "agent-1", Resource: "r-1",
		OnBehalfOf: "user:u-2", ParentSpan: "p-1", ToolArgsDigest: "d-1",
		Caller: &authorizerequest.Caller{Harness: &harness, Origin: &origin, SessionRef: &ref},
	}
	authorize := l.decisionEventJSON(full, "sess-1", pdp.Decision{Allow: true, PolicyID: "pol-1", Reason: "ok", BundleVersion: version, BundleDigest: digest, PolicyRevision: 2}, nil)
	legacy := DecisionEvent{SpanID: "legacy-1", InvokedAt: time.Unix(0, 0).UTC(), InvokingSubject: "user:u", ToolName: "t", Decision: "deny", ResourcesTouched: []string{}}

	for name, e := range map[string]DecisionEvent{"socket authorize": spoolDecision(t, authorize), "one-shot": legacy} {
		recs := flushBodyRecords(t, []DecisionEvent{e})
		var unknown []string
		for k := range recs[0] {
			if !catalogFlushFieldsBeforeCredentialReleased[k] {
				unknown = append(unknown, k)
			}
		}
		sort.Strings(unknown)
		if len(unknown) > 0 {
			t.Errorf("%s: flush body carries fields an older catalog rejects: %v", name, unknown)
		}
	}
}

func TestCollectorDropsOnBehalfOfTheCatalogWouldReject(t *testing.T) {
	cases := map[string]bool{
		"user:u-2":                  true,
		"workspace:w-1":             true,
		"organization:o-1":          true,
		"remote_identity:slack:U12": true,
		"remote_identity:slack":     false,
		"agent:a-1":                 false,
		"service_principal:sp-1":    false,
	}
	l := &LocalPDP{Sessions: pdp.NewSessions()}
	for value, kept := range cases {
		raw := l.decisionEventJSON(socketAuthorizeRequest{Schema: authorizeRequestSchema, Tool: "t", OnBehalfOf: value}, "sess-1", pdp.Decision{}, nil)
		rec := flushBodyRecords(t, []DecisionEvent{spoolDecision(t, raw)})[0]
		_, present := rec["on_behalf_of"]
		if present != kept {
			t.Errorf("on_behalf_of %q forwarded = %v, want %v", value, present, kept)
		}
		if _, ok := rec["span_id"]; !ok {
			t.Errorf("on_behalf_of %q: record lost its span_id", value)
		}
	}
}
