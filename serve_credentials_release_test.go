package connectorruntime

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/credrelease"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// HAI-722: POST /v1/credentials:release is served by the daemon's real startup
// wiring (newServeLocalPDP + newServeHandlers) and releases the session-held
// connector credential over the owner-only socket after an allow. This test
// fails if the route or the credential store wiring is removed.

// releaseServeI11 serves the base session load and one connector's release,
// both carrying the credential canary.
type releaseServeI11 struct{}

func (releaseServeI11) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.URL.Path == credrelease.ResolvePath:
		_ = json.NewEncoder(w).Encode(map[string]any{
			"credentials": []map[string]string{{"provider": "github", "access_token": credentialCanary, "token_type": "Bearer"}},
		})
	case strings.HasPrefix(r.URL.Path, "/api/v1/connectorCredentials/"):
		var body struct {
			Resource string `json:"resource"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connector_id": "conn-github-0001", "issuer": "https://auth.example.com", "resource": body.Resource, "account_model": "per_user",
			"credential": map[string]any{"access_token": credentialCanary, "token_type": "Bearer", "expire_time": "2026-10-17T20:00:00Z"},
		})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// releaseServeBundle is a v1 bundle: a github connector with issue.get
// (permitted for the default agent), the agent binding, the connector tools,
// and one linked discord identity.
func releaseServeBundle(t *testing.T) []byte {
	t.Helper()
	now := time.Now().UTC()
	return []byte(`{
		"schema":"kei.policy-bundle/v1",
		"bundle_id":"release-serve-bundle",
		"bundle_version":1,
		"policy_revision":1,
		"issuer":"kei-policy-catalog",
		"audience":{"installation_id":"inst-fixture-0001","org_id":"org-fixture-0001","workspace_id":"ws-fixture-0001"},
		"issued_at":"` + now.Format(time.RFC3339) + `","not_after":"` + now.Add(12*time.Hour).Format(time.RFC3339) + `",
		"refresh":{"poll_interval_seconds":60,"stale_after_seconds":300},
		"subject_resolution":{"mode":"bundle","max_cache_seconds":0},
		"policy_set":{"schema":"kei.policy-set/v1","org_id":"org-fixture-0001","workspace_id":"ws-fixture-0001","match_semantics":"kei.match/v1","evaluation":{"order":"array_order_first_match","default":"deny"},"groups":[],"agents":[{"id":"agent-fixture-0001","is_default":true}],"tools":[{"name":"github.get_issue","service":"github","action":"github:read","connector_id":"conn-github-0001","capability":"issue.get"}],"policies":[
			{"id":"pol-connector-get-permit","name":"connector-get-permit","src_pattern":"agent:agent-fixture-0001","dst_pattern":"capability:issue.get","action":"permit","priority":100,"enabled":true,"approval_required":false,"scope":{"org_id":"org-fixture-0001","workspace_id":"ws-fixture-0001","agent_id":"agent-fixture-0001"}}
		],"connectors":[
			{"id":"conn-github-0001","provider":"github","capabilities":[{"name":"issue.get","mutating":false}]}
		]},
		"agent_connector_bindings":[{"agent_id":"agent-fixture-0001","connector_id":"conn-github-0001","capabilities":["issue.get"]}],
		"identities":[{"source":"discord","external_id":"ext-alice","user_id":"u-alice","status":"linked","subject_token":"es256-subject-alice"}]
	}`)
}

func TestServeCredentialsReleaseRoute(t *testing.T) {
	srv := httptest.NewServer(releaseServeI11{})
	t.Cleanup(srv.Close)
	cfg := identityServeConfig(t, srv.URL)
	store, err := policybundle.OpenStore(cfg.RuntimeStateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(releaseServeBundle(t), "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", time.Now().UTC()); err != nil {
		t.Fatalf("activate release bundle: %v", err)
	}
	local, _, err := newServeLocalPDP(cfg, serveSeams{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.Close)
	ws := "ws-fixture-0001"
	local.SetIdentity(&keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: &ws, AgentID: "agent-fixture-0001"})
	_, socketHandler := newServeHandlers(cfg, local)
	c, _ := serveSocketForTest(t, socketHandler)

	put := socketDo(t, c, http.MethodPut, "/v1/session", `{"schema":"kei.session/v2","source":"discord","external_id":"ext-alice"}`)
	if put.code != http.StatusCreated {
		t.Fatalf("PUT /v1/session = %s", put.dump)
	}
	var sess struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal([]byte(put.dump[strings.Index(put.dump, "{"):]), &sess); err != nil {
		t.Fatalf("decode session: %v (%s)", err, put.dump)
	}

	req, err := http.NewRequest(http.MethodPost, "http://unix/v1/credentials:release", strings.NewReader(
		`{"schema":"kei.credential-release-request/v1","connector":{"connector_id":"conn-github-0001","capability":"issue.get"},"resource":"repos/owner/name"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+credTestToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Kei-Session", sess.SessionID)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Schema     string `json:"schema"`
		Decision   string `json:"decision"`
		ReasonCode string `json:"reason_code"`
		Credential struct {
			AccessToken string `json:"access_token"`
			ExpiresAt   string `json:"expires_at"`
		} `json:"credential"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode release: %v", err)
	}
	if resp.StatusCode != http.StatusOK || out.Schema != "kei.credential-release-response/v1" || out.Decision != "allow" || out.Credential.AccessToken != credentialCanary || out.Credential.ExpiresAt == "" {
		t.Fatalf("release = %d schema=%q decision=%q reason=%q cred=%+v, want 200 allow with the canary and an expiry",
			resp.StatusCode, out.Schema, out.Decision, out.ReasonCode, out.Credential)
	}
}
