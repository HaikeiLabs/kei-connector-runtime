package runtime

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// v2GrantAuthorizationBundle is the v2 harness-authorization bundle with no
// rule covering the harness tool and the given access grants. The catalog
// projects the workspace's live grants into the v2 envelope (ADR-038,
// HAI-615), so a grant is what decides a call no rule covers.
func v2GrantAuthorizationBundle(t *testing.T, now time.Time, version int64, grants []any) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(v2HarnessAuthorizationBundle(t, now), &doc); err != nil {
		t.Fatal(err)
	}
	doc["bundle_version"] = version
	set := doc["policy_set"].(map[string]any)
	set["tool_policies"] = []any{}
	if grants != nil {
		doc["access_grants"] = grants
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestSocketAuthorizeCarriesAccessGrantDecisions proves the socket route
// surfaces an access grant the way it surfaces any other decision: a live
// grant permits the call it opens, an ended grant denies with
// access_grant_expired and a next-step hint, and a bundle without grants
// returns a deny response when no registered policy matches.
func TestSocketAuthorizeCarriesAccessGrantDecisions(t *testing.T) {
	policybundle.SetV2SchemaValidator(runtimeV2SchemaValidator(t))
	now := time.Now().UTC()
	cfg := testPolicyConfig{policyStateDir: t.TempDir(), token: "runtime-token"}
	local := NewLocalPDP(cfg, nil)
	defer local.Close()
	identity := &Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001")}
	local.SetIdentity(identity)
	store, err := policybundle.OpenStore(cfg.PolicyStateDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Activate(v2GrantAuthorizationBundle(t, now, 42, nil), identity.ID, identity.OrgID, *identity.WorkspaceID, now); err != nil {
		t.Fatal(err)
	}
	h := local.NewHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return true })
	put := httptest.NewRecorder()
	h.ServeHTTP(put, httptest.NewRequest(http.MethodPut, "/v1/session", strings.NewReader(`{"schema":"kei.session/v2","source":"discord","external_id":"discord-user-1"}`)))
	var sessionResponse socketSessionResponse
	if put.Code != http.StatusCreated || json.Unmarshal(put.Body.Bytes(), &sessionResponse) != nil || sessionResponse.SessionID == "" {
		t.Fatalf("session status=%d body=%s", put.Code, put.Body.String())
	}
	call := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(`{"schema":"kei.authorize-request/v1","tool":"github.read_repo","framework":"discord"}`))
		withSessionHeader(req, sessionResponse.SessionID)
		h.ServeHTTP(rec, req)
		return rec
	}
	var response socketAuthorizeResponse
	rec := call()
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Decision != "deny" || response.ReasonCode != "no_matching_policy" {
		t.Fatalf("bundle without grants response=%+v err=%v, want deny/no_matching_policy", response, err)
	}

	live := []any{map[string]any{"principal": "user:user-alice", "target": "tool:github.read_repo", "expire_time": now.Add(time.Hour).Format(time.RFC3339)}}
	if _, err = store.Activate(v2GrantAuthorizationBundle(t, now, 43, live), identity.ID, identity.OrgID, *identity.WorkspaceID, now); err != nil {
		t.Fatal(err)
	}
	rec = call()
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Decision != "permit" {
		t.Fatalf("live grant response=%+v err=%v", response, err)
	}
	if !strings.Contains(response.PolicyID, "grant:") {
		t.Fatalf("live grant response names no grant: %+v", response)
	}

	ended := []any{map[string]any{"principal": "user:user-alice", "target": "tool:github.read_repo", "expire_time": now.Add(-time.Minute).Format(time.RFC3339)}}
	if _, err = store.Activate(v2GrantAuthorizationBundle(t, now, 44, ended), identity.ID, identity.OrgID, *identity.WorkspaceID, now); err != nil {
		t.Fatal(err)
	}
	rec = call()
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Decision != "deny" || response.ReasonCode != "access_grant_expired" {
		t.Fatalf("ended grant response=%+v err=%v", response, err)
	}
	if response.Hint == "" {
		t.Fatalf("ended grant deny carries no hint: %+v", response)
	}
}
