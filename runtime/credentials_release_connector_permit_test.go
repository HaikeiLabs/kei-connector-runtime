package runtime_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credrelease"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// HAI-1070 (owner decision 2026-11-16, option d): a connector credential is
// released only when the permit that allowed the call has a selector naming
// that connector. A tool-only grant still permits the tool call; it never
// releases a credential.

// releaseBundleWithSelector is releaseBundle with its one tool policy's
// selector replaced.
func releaseBundleWithSelector(t *testing.T, selector map[string]any) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(releaseBundle(t), &doc); err != nil {
		t.Fatal(err)
	}
	set := doc["policy_set"].(map[string]any)
	policy := set["tool_policies"].([]any)[0].(map[string]any)
	policy["selector"] = selector
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type connectorPermitFixture struct {
	h      http.Handler
	mu     sync.Mutex
	events []map[string]json.RawMessage
}

func newConnectorPermitFixture(t *testing.T, selector map[string]any) *connectorPermitFixture {
	t.Helper()
	f := &connectorPermitFixture{}
	dir := t.TempDir()
	activateBundle(t, dir, releaseBundleWithSelector(t, selector))
	srv := httptest.NewServer(&releaseI11{})
	t.Cleanup(srv.Close)
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken: policyTestToken, RuntimeControlPlaneURL: "https://kei.example", RuntimeStateDir: dir,
	}, func(data json.RawMessage) {
		var e map[string]json.RawMessage
		if err := json.Unmarshal(data, &e); err != nil {
			t.Errorf("audit event is not JSON: %v", err)
		}
		f.mu.Lock()
		f.events = append(f.events, e)
		f.mu.Unlock()
	})
	t.Cleanup(l.Close)
	l.SetIdentity(&keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: "agent-fixture-0001"})
	l.SetCredentialStore(credrelease.NewStore(credrelease.NewClient(srv.URL, policyTestToken, 5*time.Second)))
	f.h = sessionHandler(t, l)
	return f
}

type releaseOutcome struct {
	Decision   string          `json:"decision"`
	ReasonCode string          `json:"reason_code"`
	Credential json.RawMessage `json:"credential"`
}

// release posts one release and returns the response and the one audit
// event it wrote.
func (f *connectorPermitFixture) release(t *testing.T, session string) (releaseOutcome, map[string]json.RawMessage) {
	t.Helper()
	f.mu.Lock()
	before := len(f.events)
	f.mu.Unlock()
	rec := sessionRequest(f.h, http.MethodPost, "/v1/credentials:release", session,
		fmt.Sprintf(`{"schema":"kei.credential-release-request/v1","tool":"github.get_issue","connector":{"connector_id":"%s","capability":"issue.get"},"resource":"%s"}`, releaseConnectorID, releaseResource))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "connector-fixture-token") && !strings.Contains(rec.Body.String(), `"allow"`) {
		t.Fatalf("a deny carries the credential: %s", rec.Body.String())
	}
	var out releaseOutcome
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.events) != before+1 {
		t.Fatalf("release emitted %d audit events, want 1", len(f.events)-before)
	}
	return out, f.events[before]
}

func auditField(e map[string]json.RawMessage, k string) string {
	var s string
	_ = json.Unmarshal(e[k], &s)
	return s
}

func assertReleaseDenied(t *testing.T, out releaseOutcome, e map[string]json.RawMessage, wantReason string) {
	t.Helper()
	if out.Decision != "deny" || len(out.Credential) != 0 && string(out.Credential) != "null" {
		t.Fatalf("decision/credential = %q/%s, want deny with no credential", out.Decision, out.Credential)
	}
	if wantReason != "" && out.ReasonCode != wantReason {
		t.Fatalf("reason_code = %q, want %q", out.ReasonCode, wantReason)
	}
	if auditField(e, "decision") != "deny" || auditField(e, "reason_code") != out.ReasonCode {
		t.Fatalf("audit decision/reason_code = %q/%q, want deny/%q", auditField(e, "decision"), auditField(e, "reason_code"), out.ReasonCode)
	}
	if _, ok := e["credential_kind"]; ok {
		t.Fatalf("deny audit row carries credential_kind: %v", e)
	}
	raw, _ := json.Marshal(e)
	if strings.Contains(string(raw), "connector-fixture-token") {
		t.Fatalf("audit row carries the credential: %s", raw)
	}
}

func TestCredentialReleaseRequiresConnectorNamedPermit(t *testing.T) {
	base := func(extra map[string]any) map[string]any {
		s := map[string]any{"source_principal": "user:u-alice", "source": "discord", "tool": "github.get_issue"}
		for k, v := range extra {
			s[k] = v
		}
		return s
	}

	t.Run("tool-only permit allows the call but never releases", func(t *testing.T) {
		f := newConnectorPermitFixture(t, base(nil))
		alice := createSession(t, f.h, "ext-alice")
		rec := sessionRequest(f.h, http.MethodPost, "/v1/authorize", alice, `{"schema":"kei.authorize-request/v1","tool":"github.get_issue"}`)
		var authz struct {
			Decision string `json:"decision"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &authz); err != nil || authz.Decision != "permit" {
			t.Fatalf("tool call decision = %q (%s), want permit", authz.Decision, rec.Body.String())
		}
		out, e := f.release(t, alice)
		assertReleaseDenied(t, out, e, "connector_not_named")
	})

	t.Run("connector-named permit releases", func(t *testing.T) {
		f := newConnectorPermitFixture(t, base(map[string]any{"connector_id": releaseConnectorID}))
		out, e := f.release(t, createSession(t, f.h, "ext-alice"))
		if out.Decision != "allow" || len(out.Credential) == 0 {
			t.Fatalf("decision/reason = %q/%q, want allow with a credential", out.Decision, out.ReasonCode)
		}
		if auditField(e, "decision") != "allow" {
			t.Fatalf("audit decision = %q, want allow", auditField(e, "decision"))
		}
	})

	t.Run("permit naming a different connector denies", func(t *testing.T) {
		f := newConnectorPermitFixture(t, base(map[string]any{"connector_id": "conn-other-0002"}))
		out, e := f.release(t, createSession(t, f.h, "ext-alice"))
		assertReleaseDenied(t, out, e, "")
	})
}
