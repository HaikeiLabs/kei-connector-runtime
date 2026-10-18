package runtime_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credrelease"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// HAI-722 contract (kei-connector-contracts docs/credential-passthrough.md):
// POST /v1/credentials:release is a sibling of /v1/authorize on the owner-only
// socket. It re-runs the authorize decision and, only on allow, releases the
// session-held connector credential (value + expiry). On deny, or on an allow
// whose credential is missing/expired, it returns a typed reason_code and no
// credential — never a fallback.

const (
	releaseConnectorID = "conn-github-0001"
	releaseResource    = "repos/owner/name"
)

// releaseI11 serves the base session load (connectorCredentials:resolve) and
// one connector's release (connectorCredentials/{id}:resolve). A resource
// containing "missing" is answered NOT_CONNECTED so a held credential can be
// absent even when the policy allows.
type releaseI11 struct{}

func (releaseI11) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.URL.Path == credrelease.ResolvePath:
		_ = json.NewEncoder(w).Encode(map[string]any{
			"credentials": []map[string]string{{"provider": "github", "access_token": "gh-base-token", "token_type": "Bearer"}},
		})
	case strings.HasPrefix(r.URL.Path, "/api/v1/connectorCredentials/"):
		var body struct {
			Resource string `json:"resource"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if strings.Contains(body.Resource, "missing") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"connector_id": releaseConnectorID, "resource": body.Resource,
				"failure": map[string]any{"reason": "NOT_CONNECTED"},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connector_id": releaseConnectorID, "issuer": "https://auth.example.com", "resource": body.Resource, "account_model": "per_user",
			"credential": map[string]any{"access_token": "connector-fixture-token", "token_type": "Bearer", "expire_time": "2026-10-17T20:00:00Z"},
		})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// releaseBundle is a v1 bundle: a github connector with issue.get (permitted
// for the default agent) and issue.create (not permitted), the agent binding,
// and one linked discord identity.
func releaseBundle(t *testing.T) []byte {
	t.Helper()
	now := time.Now().UTC()
	return []byte(fmt.Sprintf(`{
		"schema":"kei.policy-bundle/v1",
		"bundle_id":"release-bundle",
		"bundle_version":1,
		"policy_revision":1,
		"issuer":"kei-policy-catalog",
		"audience":{"installation_id":"inst-fixture-0001","org_id":"org-fixture-0001","workspace_id":"ws-fixture-0001"},
		"issued_at":"%s","not_after":"%s",
		"refresh":{"poll_interval_seconds":60,"stale_after_seconds":300},
		"subject_resolution":{"mode":"bundle","max_cache_seconds":0},
		"policy_set":{"schema":"kei.policy-set/v1","org_id":"org-fixture-0001","workspace_id":"ws-fixture-0001","match_semantics":"kei.match/v1","evaluation":{"order":"array_order_first_match","default":"deny"},"groups":[],"agents":[{"id":"agent-fixture-0001","is_default":true}],"tools":[{"name":"github.get_issue","service":"github","action":"github:read","connector_id":"conn-github-0001","capability":"issue.get"},{"name":"github.create_issue","service":"github","action":"github:write","connector_id":"conn-github-0001","capability":"issue.create"}],"policies":[
			{"id":"pol-connector-get-permit","name":"connector-get-permit","src_pattern":"agent:agent-fixture-0001","dst_pattern":"capability:issue.get","action":"permit","priority":100,"enabled":true,"approval_required":false,"scope":{"org_id":"org-fixture-0001","workspace_id":"ws-fixture-0001","agent_id":"agent-fixture-0001"}}
		],"connectors":[
			{"id":"conn-github-0001","provider":"github","capabilities":[{"name":"issue.get","mutating":false},{"name":"issue.create","mutating":true}]}
		]},
		"agent_connector_bindings":[{"agent_id":"agent-fixture-0001","connector_id":"conn-github-0001","capabilities":["issue.get","issue.create"]}],
		"identities":[{"source":"discord","external_id":"ext-alice","user_id":"u-alice","status":"linked","subject_token":"es256-subject-alice"}]
	}`, now.Format(time.RFC3339), now.Add(12*time.Hour).Format(time.RFC3339)))
}

func releasePDP(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	activateBundle(t, dir, releaseBundle(t))
	srv := httptest.NewServer(releaseI11{})
	t.Cleanup(srv.Close)
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken: policyTestToken, RuntimeControlPlaneURL: "https://kei.example", RuntimeStateDir: dir,
	}, nil)
	t.Cleanup(l.Close)
	l.SetIdentity(&keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001")})
	l.SetCredentialStore(credrelease.NewStore(credrelease.NewClient(srv.URL, policyTestToken, 5*time.Second)))
	return sessionHandler(t, l)
}

// TestCredentialsReleaseRoute is the failing (red) test for the HAI-722
// credential pass-through route. It fails until POST /v1/credentials:release
// is implemented to match the contract.
func TestCredentialsReleaseRoute(t *testing.T) {
	h := releasePDP(t)
	alice := createSession(t, h, "ext-alice")

	release := func(capability, resource string) *httptest.ResponseRecorder {
		return sessionRequest(h, http.MethodPost, "/v1/credentials:release", alice,
			fmt.Sprintf(`{"schema":"kei.credential-release-request/v1","connector":{"connector_id":"%s","capability":"%s"},"resource":"%s"}`,
				releaseConnectorID, capability, resource))
	}

	t.Run("allow releases the credential with an expiry", func(t *testing.T) {
		rec := release("issue.get", releaseResource)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Schema     string `json:"schema"`
			Decision   string `json:"decision"`
			Credential struct {
				ConnectorID  string `json:"connector_id"`
				Issuer       string `json:"issuer"`
				Resource     string `json:"resource"`
				AccountModel string `json:"account_model"`
				AccessToken  string `json:"access_token"`
				ExpiresAt    string `json:"expires_at"`
			} `json:"credential"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, rec.Body.String())
		}
		if out.Schema != "kei.credential-release-response/v1" || out.Decision != "allow" {
			t.Fatalf("schema/decision = %q/%q, want kei.credential-release-response/v1/allow", out.Schema, out.Decision)
		}
		if out.Credential.AccessToken != "connector-fixture-token" || out.Credential.ConnectorID != releaseConnectorID || out.Credential.ExpiresAt == "" {
			t.Fatalf("credential = %+v, want the fixture token, the connector id and a non-empty expiry", out.Credential)
		}
	})

	t.Run("deny carries a typed reason and no credential", func(t *testing.T) {
		rec := release("issue.create", releaseResource)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Decision   string `json:"decision"`
			ReasonCode string `json:"reason_code"`
			Credential *struct {
				AccessToken string `json:"access_token"`
			} `json:"credential"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, rec.Body.String())
		}
		if out.Decision != "deny" || out.ReasonCode == "" || out.Credential != nil {
			t.Fatalf("decision/reason/credential = %q/%q/%+v, want deny with a typed reason and no credential", out.Decision, out.ReasonCode, out.Credential)
		}
	})

	t.Run("allow decision without a held credential denies with a typed reason", func(t *testing.T) {
		rec := release("issue.get", "repos/missing")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Decision   string `json:"decision"`
			ReasonCode string `json:"reason_code"`
			Credential *struct {
				AccessToken string `json:"access_token"`
			} `json:"credential"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, rec.Body.String())
		}
		if out.Decision != "deny" || out.ReasonCode == "" || out.Credential != nil {
			t.Fatalf("decision/reason/credential = %q/%q/%+v, want deny with a typed reason and no credential", out.Decision, out.ReasonCode, out.Credential)
		}
	})
}
