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

// The release route's audit record (kei-connector-contracts
// docs/credential-passthrough.md, Audit): the decision the caller actually
// got, and credential_kind only when a credential was handed out. Release
// status is session state and is never on the record.
func TestCredentialsReleaseAuditRecord(t *testing.T) {
	dir := t.TempDir()
	activateBundle(t, dir, releaseBundle(t))
	i11 := &releaseI11{}
	srv := httptest.NewServer(i11)
	t.Cleanup(srv.Close)
	var mu sync.Mutex
	var events []map[string]json.RawMessage
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken: policyTestToken, RuntimeControlPlaneURL: "https://kei.example", RuntimeStateDir: dir,
	}, func(data json.RawMessage) {
		var e map[string]json.RawMessage
		if err := json.Unmarshal(data, &e); err != nil {
			t.Errorf("audit event is not JSON: %v", err)
		}
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})
	t.Cleanup(l.Close)
	l.SetIdentity(&keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: "agent-fixture-0001"})
	l.SetCredentialStore(credrelease.NewStore(credrelease.NewClient(srv.URL, policyTestToken, 5*time.Second)))
	h := sessionHandler(t, l)

	release := func(t *testing.T, sessionID, capability, resource string) (response, event map[string]json.RawMessage) {
		t.Helper()
		mu.Lock()
		before := len(events)
		mu.Unlock()
		rec := sessionRequest(h, http.MethodPost, "/v1/credentials:release", sessionID,
			fmt.Sprintf(`{"schema":"kei.credential-release-request/v1","tool":"github.get_issue","connector":{"connector_id":"%s","capability":"%s"},"resource":"%s"}`, releaseConnectorID, capability, resource))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(events) != before+1 {
			t.Fatalf("release emitted %d audit events, want 1", len(events)-before)
		}
		return response, events[before]
	}
	field := func(m map[string]json.RawMessage, k string) string {
		var s string
		_ = json.Unmarshal(m[k], &s)
		return s
	}
	assertNoReleaseStatus := func(t *testing.T, e map[string]json.RawMessage) {
		t.Helper()
		if _, ok := e["credential_released"]; ok {
			t.Errorf("audit event carries credential_released; release status stays in the session")
		}
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), "connector-fixture-token") || strings.Contains(string(raw), "gh-base-token") {
			t.Fatalf("audit event carries a credential: %s", raw)
		}
	}

	t.Run("handed out records an allow with the credential kind", func(t *testing.T) {
		alice := createSession(t, h, "ext-alice")
		resp, e := release(t, alice, "issue.get", releaseResource)
		if field(resp, "decision") != "allow" {
			t.Fatalf("response = %v", resp)
		}
		if field(e, "decision") != "allow" || field(e, "credential_kind") != "oauth" {
			t.Fatalf("event decision/credential_kind = %q/%q, want allow/oauth", field(e, "decision"), field(e, "credential_kind"))
		}
		assertNoReleaseStatus(t, e)
	})

	t.Run("policy deny records the deny without a credential kind", func(t *testing.T) {
		alice := createSession(t, h, "ext-alice")
		_, e := release(t, alice, "issue.create", releaseResource)
		if field(e, "decision") != "deny" {
			t.Fatalf("event decision = %q, want deny", field(e, "decision"))
		}
		if _, ok := e["credential_kind"]; ok {
			t.Fatalf("deny carries credential_kind: %v", e)
		}
		assertNoReleaseStatus(t, e)
	})

	t.Run("allow whose release fails records the deny the caller got", func(t *testing.T) {
		i11.notConnected.Store(true)
		defer i11.notConnected.Store(false)
		fresh := createSession(t, h, "ext-alice")
		resp, e := release(t, fresh, "issue.get", "repos/missing")
		if field(resp, "decision") != "deny" || field(resp, "reason_code") == "" {
			t.Fatalf("response = %v, want a typed deny", resp)
		}
		if field(e, "decision") != "deny" || field(e, "reason_code") != field(resp, "reason_code") {
			t.Fatalf("event decision/reason_code = %q/%q, want deny/%q (the caller's)", field(e, "decision"), field(e, "reason_code"), field(resp, "reason_code"))
		}
		if _, ok := e["credential_kind"]; ok {
			t.Fatalf("failed release carries credential_kind: %v", e)
		}
		assertNoReleaseStatus(t, e)
	})
}
