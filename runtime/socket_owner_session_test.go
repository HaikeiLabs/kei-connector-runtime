package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/credrelease"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func v2PreflightBundle(t *testing.T, now time.Time) []byte {
	t.Helper()
	check := map[string]any{
		"policy_id": "policy-review", "name": "review", "effect": "permit", "priority": 10,
		"scope":    map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": "agent-fixture-0001"},
		"selector": map[string]any{"source_principal": "user:user-alice", "source": "github", "connector_id": "conn-fixture-0001", "tool": "github.read_repo", "capability": "repository.read"},
	}
	plan := map[string]any{
		"args_schema":    map[string]any{"type": "object", "properties": map[string]any{}, "required": []any{}, "additionalProperties": false},
		"context_schema": map[string]any{"type": "object", "properties": map[string]any{"repository": map[string]any{"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"}}, "required": []any{"repository"}, "additionalProperties": false},
		"operations":     []any{map[string]any{"id": "read-repository", "capability": "repository.read", "resource": map[string]any{"type": "repository", "id": map[string]any{"from": "context", "field": "repository", "type": "string"}}, "provider_resource_template": "repos/{resource.id}", "provider_input": map[string]any{}}},
	}
	raw, err := json.Marshal(map[string]any{
		"schema": "kei.policy-bundle/v2", "bundle_id": "bundle-v2-runtime", "bundle_version": 42, "policy_revision": 7, "issuer": policybundle.Issuer,
		"audience":  map[string]any{"installation_id": "inst-fixture-0001", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001"},
		"issued_at": now.UTC().Format(time.RFC3339Nano), "not_after": now.Add(time.Hour).UTC().Format(time.RFC3339Nano),
		"refresh": map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300}, "subject_resolution": map[string]any{"mode": "bundle", "max_cache_seconds": 60},
		"policy_set":               map[string]any{"schema": "kei.policy-set/v2", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "match_semantics": "kei.match/v2", "evaluation": map[string]any{"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"}, "checks": "per_capability_first_match_and", "default": "deny"}, "tools": []any{map[string]any{"name": "github.read_repo", "source": "github", "operation_class": "read", "route": map[string]any{"connector_binding": map[string]any{"connector_id": "conn-fixture-0001"}}, "required_capabilities": []string{"repository.read"}, "resource_types": []any{map[string]any{"type": "repository"}}, "plan": plan}}, "checks": []any{check}, "tool_policies": []any{}, "harness_match_semantics": "kei.harness-match/v1", "harness_policies": []any{}},
		"agent_connector_bindings": []any{map[string]any{"agent_id": "agent-fixture-0001", "connector_id": "conn-fixture-0001", "capabilities": []string{"repository.read"}}},
		"identities":               []any{map[string]any{"source": "discord", "external_id": "discord-user-1", "user_id": "user-alice", "status": "linked", "groups": []string{"members"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func runtimeV2SchemaValidator(t *testing.T) func([]byte) error {
	t.Helper()
	load := func(name string) any {
		b, err := os.ReadFile("../docs/contracts/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("https://schemas.haikeilabs.com/kei/policy-set-v2.schema.json", load("policy-set-v2.schema.json")); err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("https://schemas.haikeilabs.com/kei/policy-bundle-v2.schema.json", load("policy-bundle-v2.schema.json")); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("https://schemas.haikeilabs.com/kei/policy-bundle-v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return func(raw []byte) error {
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return err
		}
		return schema.Validate(doc)
	}
}

func v2HarnessAuthorizationBundle(t *testing.T, now time.Time) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(v2PreflightBundle(t, now), &doc); err != nil {
		t.Fatal(err)
	}
	set := doc["policy_set"].(map[string]any)
	tools := set["tools"].([]any)
	tool := tools[0].(map[string]any)
	tool["source"] = "discord"
	tool["route"] = map[string]any{"harness_executor": map[string]any{"executor": "discord", "registration": "web_search"}}
	delete(tool, "required_capabilities")
	delete(tool, "resource_types")
	delete(tool, "plan")
	set["checks"] = []any{}
	set["tool_policies"] = []any{map[string]any{
		"policy_id": "web-search-policy", "name": "web search", "effect": "permit", "priority": 10,
		"scope":    map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": nil},
		"selector": map[string]any{"source_principal": "user:user-alice", "source": "discord", "tool": "github.read_repo"},
	}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func v2SharedCredentialReleaseBundle(t *testing.T, now time.Time, target string) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(v2HarnessAuthorizationBundle(t, now), &doc); err != nil {
		t.Fatal(err)
	}
	set := doc["policy_set"].(map[string]any)
	set["connectors"] = []any{map[string]any{
		"id": "conn-fixture-0001", "provider": "github", "credential_source": "oauth", "account_model": "shared",
		"capabilities": []any{map[string]any{"name": "repository.read", "mutating": false}},
	}}
	set["tool_policies"] = []any{map[string]any{
		"policy_id": "release-policy", "name": "release", "effect": "permit", "priority": 10,
		"scope":    map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": "agent-fixture-0001"},
		"selector": map[string]any{"source_principal": "user:user-alice", "source": "discord", "tool": "github.read_repo", "connector_id": "conn-fixture-0001", "capability": "repository.read", "resource_id": target},
	}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func v2CredentialReleaseBundle(t *testing.T, now time.Time, target, accountModel string) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(v2SharedCredentialReleaseBundle(t, now, target), &doc); err != nil {
		t.Fatal(err)
	}
	set := doc["policy_set"].(map[string]any)
	connector := set["connectors"].([]any)[0].(map[string]any)
	connector["account_model"] = accountModel
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func v2CredentialReleaseBundleWithMCPAudience(t *testing.T, now time.Time, target, audience string) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(v2CredentialReleaseBundle(t, now, target, "shared"), &doc); err != nil {
		t.Fatal(err)
	}
	set := doc["policy_set"].(map[string]any)
	connector := set["connectors"].([]any)[0].(map[string]any)
	connector["kind"] = "mcp"
	connector["slug"] = "drive_prod"
	connector["mcp"] = map[string]any{
		"url": audience, "transport": "streamable_http", "auth_method": "oauth",
		"approved_manifest_hash": "sha256:a94748f3bd7e1bc1e46ff952e802378a98249adfd5fcd2677ff48bd0df848dbb",
		"approved_tools":         []any{map[string]any{"name": "github.read_repo", "tool_hash": "sha256:9e84a27116887ce94c79f25184ee07da9b9dd0288847be9e0ee885fdc61ec537"}},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func principalV2CredentialBundle(t *testing.T, now time.Time, accountModel string) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(v2SharedCredentialReleaseBundle(t, now, "repos/owner/name"), &doc); err != nil {
		t.Fatal(err)
	}
	identities := []any{map[string]any{
		"subject_type": "service_principal", "service_principal_id": "sp-bug-intake",
		"agent_id": "agent-fixture-0001", "groups": []string{"bug-intake"},
		"subject_token": "principal-subject-token", "expire_time": now.Add(time.Hour).Format(time.RFC3339Nano),
	}}
	doc["identities"] = identities
	set := doc["policy_set"].(map[string]any)
	connector := set["connectors"].([]any)[0].(map[string]any)
	connector["account_model"] = accountModel
	policy := set["tool_policies"].([]any)[0].(map[string]any)
	policy["selector"].(map[string]any)["source_principal"] = "group:bug-intake"
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSocketPrincipalSessionReleasesOnlySharedToolCredential(t *testing.T) {
	validator := runtimeV2SchemaValidator(t)
	policybundle.SetV2SchemaValidator(validator)
	defer policybundle.SetV2SchemaValidator(validator)
	for _, tc := range []struct{ accountModel, want string }{{"shared", "allow"}, {"per_user", "deny"}} {
		t.Run(tc.accountModel, func(t *testing.T) {
			now := time.Now().UTC()
			dir := t.TempDir()
			store, err := policybundle.OpenStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Activate(principalV2CredentialBundle(t, now, tc.accountModel), "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", now); err != nil {
				t.Fatal(err)
			}
			bridge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == credrelease.ResolvePath {
					_ = json.NewEncoder(w).Encode(map[string]any{"credentials": []any{}})
					return
				}
				var body struct {
					Resource string `json:"resource"`
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				// The connector has no MCP server, so its credential has no
				// resource; the policy target must never reach the identity
				// service, which answers 400 for a non-URI resource.
				if body.Resource != "" {
					http.Error(w, "resource must be the connector's canonical resource URI", http.StatusBadRequest)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"connector_id": "conn-fixture-0001", "resource": body.Resource, "account_model": tc.accountModel, "credential": map[string]any{"access_token": "principal-shared-token", "token_type": "Bearer", "expire_time": now.Add(time.Hour).Format(time.RFC3339Nano)}})
			}))
			defer bridge.Close()
			local := NewLocalPDP(testPolicyConfig{policyStateDir: dir, token: "runtime-token"}, nil)
			defer local.Close()
			local.SetIdentity(&Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: "agent-fixture-0001"})
			local.SetCredentialStore(credrelease.NewStore(credrelease.NewClient(bridge.URL, "runtime-token", time.Second)))
			h := local.NewHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return true })
			start := httptest.NewRecorder()
			h.ServeHTTP(start, httptest.NewRequest(http.MethodPut, "/v1/session", strings.NewReader(`{"schema":"kei.session/v2","service_principal_id":"sp-bug-intake"}`)))
			if start.Code != http.StatusCreated {
				t.Fatalf("session start=%d %s", start.Code, start.Body.String())
			}
			var sessionBody struct {
				SessionID string `json:"session_id"`
			}
			if err := json.Unmarshal(start.Body.Bytes(), &sessionBody); err != nil {
				t.Fatal(err)
			}
			body := `{"schema":"kei.credential-release-request/v1","tool":"github.read_repo","agent_id":"agent-fixture-0001","connector":{"connector_id":"conn-fixture-0001","capability":"repository.read"},"resource":"repos/owner/name"}`
			req := httptest.NewRequest(http.MethodPost, "/v1/credentials:release", strings.NewReader(body))
			session.SetHeader(req, sessionBody.SessionID)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			var got struct {
				Decision   string `json:"decision"`
				Credential *struct {
					AccessToken string `json:"access_token"`
				} `json:"credential"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.Decision != tc.want || (tc.want == "allow" && (got.Credential == nil || got.Credential.AccessToken != "principal-shared-token")) || (tc.want == "deny" && got.Credential != nil) {
				t.Fatalf("release=%+v body=%s", got, rec.Body.String())
			}
		})
	}
}

func TestSocketCredentialReleaseV2HarnessToolBindsTarget(t *testing.T) {
	policybundle.SetV2SchemaValidator(runtimeV2SchemaValidator(t))
	defer policybundle.SetV2SchemaValidator(nil)
	const target = "repos/owner/name"
	const connectorAudience = "https://drive.example/mcp"
	for _, tc := range []struct {
		name, tool, connector, capability, resource string
		want                                        string
	}{
		{"allowed shared credential", "github.read_repo", "conn-fixture-0001", "repository.read", target, "allow"},
		{"credential audience distinct from policy target", "github.read_repo", "conn-fixture-0001", "repository.read", "drive/drive-123", "allow"},
		{"allowed per-user credential", "github.read_repo", "conn-fixture-0001", "repository.read", target, "allow"},
		{"credential subject isolation", "github.read_repo", "conn-fixture-0001", "repository.read", target, "deny"},
		{"mismatched tool", "github.write_repo", "conn-fixture-0001", "repository.read", target, "deny"},
		{"mismatched connector", "github.read_repo", "conn-other", "repository.read", target, "deny"},
		{"mismatched capability", "github.read_repo", "conn-fixture-0001", "repository.write", target, "deny"},
		{"mismatched resource", "github.read_repo", "conn-fixture-0001", "repository.read", "repos/other/name", "deny"},
		{"missing credential", "github.read_repo", "conn-fixture-0001", "repository.read", target, "deny"},
		{"credential audience mismatch", "github.read_repo", "conn-fixture-0001", "repository.read", target, "deny"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			dir := t.TempDir()
			storeBundle, err := policybundle.OpenStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			accountModel := "shared"
			if tc.name == "allowed per-user credential" {
				accountModel = "per_user"
			}
			bundleTarget := target
			if tc.name == "credential audience distinct from policy target" {
				bundleTarget = tc.resource
			}
			bundle := v2CredentialReleaseBundle(t, now, bundleTarget, accountModel)
			if tc.name == "credential audience distinct from policy target" {
				bundle = v2CredentialReleaseBundleWithMCPAudience(t, now, bundleTarget, connectorAudience)
			}
			if _, err := storeBundle.Activate(bundle, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", now); err != nil {
				t.Fatal(err)
			}
			credentialMissing := tc.name == "missing credential"
			credentialMismatch := tc.name == "credential audience mismatch"
			bridge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == credrelease.ResolvePath {
					_ = json.NewEncoder(w).Encode(map[string]any{"credentials": []any{}})
					return
				}
				var body struct {
					Resource string `json:"resource"`
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				expectedAudience := ""
				if tc.name == "credential audience distinct from policy target" {
					expectedAudience = connectorAudience
				}
				// Lookup must use the connector audience, not the policy target.
				if body.Resource != expectedAudience {
					http.Error(w, "resource must be the connector's canonical resource URI", http.StatusBadRequest)
					return
				}
				if credentialMissing {
					_ = json.NewEncoder(w).Encode(map[string]any{"connector_id": tc.connector, "resource": body.Resource, "account_model": "shared", "failure": map[string]any{"reason": "NOT_CONNECTED"}})
					return
				}
				connectorID := tc.connector
				if credentialMismatch {
					connectorID = "conn-other"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"connector_id": connectorID, "resource": body.Resource, "account_model": accountModel, "credential": map[string]any{"access_token": "shared-token", "token_type": "Bearer", "expire_time": "2026-10-17T20:00:00Z"}})
			}))
			defer bridge.Close()
			l := NewLocalPDP(testPolicyConfig{policyStateDir: dir, token: "runtime-token"}, nil)
			defer l.Close()
			l.SetIdentity(&Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: "agent-fixture-0001"})
			l.SetCredentialStore(credrelease.NewStore(credrelease.NewClient(bridge.URL, "runtime-token", time.Second)))
			h := l.NewHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return true })
			// Create a linked subject directly; the verified bundle corroborates it.
			sessionID, err := l.Sessions.Create(pdp.Subject{UserID: "user-alice", Status: pdp.StatusLinked, Source: "discord", ExternalID: "discord-user-1", Token: "subject-token"})
			if err != nil {
				t.Fatal(err)
			}
			store := credrelease.NewStore(credrelease.NewClient(bridge.URL, "runtime-token", time.Second))
			credentialSubject := "user-alice"
			if tc.name == "credential subject isolation" {
				credentialSubject = "user-bob"
			}
			if err := store.Load(context.Background(), credentialSubject, "subject-token"); err != nil {
				t.Fatal(err)
			}
			l.sessionCreds.Store(sessionID, store)
			body := fmt.Sprintf(`{"schema":"kei.credential-release-request/v1","tool":%q,"agent_id":"agent-fixture-0001","connector":{"connector_id":%q,"capability":%q},"resource":%q,"on_behalf_of":"user:trigger"}`, tc.tool, tc.connector, tc.capability, tc.resource)
			req, err := http.NewRequest(http.MethodPost, "/v1/credentials:release", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			session.SetHeader(req, sessionID)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			var got struct {
				Decision   string `json:"decision"`
				Credential *struct {
					AccessToken string `json:"access_token"`
					Resource    string `json:"resource"`
				} `json:"credential"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode %s: %v", rec.Body, err)
			}
			if got.Decision != tc.want || (tc.want == "deny" && got.Credential != nil) || (tc.want == "allow" && (got.Credential == nil || got.Credential.AccessToken != "shared-token")) {
				t.Fatalf("decision=%q credential=%+v body=%s", got.Decision, got.Credential, rec.Body)
			}
			if tc.name == "credential audience distinct from policy target" && got.Credential.Resource != connectorAudience {
				t.Fatalf("credential resource=%q, want connector audience %q", got.Credential.Resource, connectorAudience)
			}
		})
	}
}

func TestSocketAuthorizeV2HarnessToolBindsExactTarget(t *testing.T) {
	policybundle.SetV2SchemaValidator(runtimeV2SchemaValidator(t))
	defer policybundle.SetV2SchemaValidator(nil)
	now := time.Now().UTC()
	cfg := testPolicyConfig{policyStateDir: t.TempDir(), token: "runtime-token"}
	local := NewLocalPDP(cfg, nil)
	defer local.Close()
	local.SetIdentity(&Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: "agent-fixture-0001"})
	store, err := policybundle.OpenStore(cfg.PolicyStateDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(v2CredentialReleaseBundle(t, now, "repos/owner/name", "per_user"), "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", now); err != nil {
		t.Fatal(err)
	}
	h := local.NewHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return true })
	put := httptest.NewRecorder()
	h.ServeHTTP(put, httptest.NewRequest(http.MethodPut, "/v1/session", strings.NewReader(`{"schema":"kei.session/v2","source":"discord","external_id":"discord-user-1"}`)))
	var sessionResponse socketSessionResponse
	if put.Code != http.StatusCreated || json.Unmarshal(put.Body.Bytes(), &sessionResponse) != nil || sessionResponse.SessionID == "" {
		t.Fatalf("session status=%d body=%s", put.Code, put.Body.String())
	}
	cases := []struct {
		name, body, decision, reason string
	}{
		{"exact target allowed", `{"schema":"kei.authorize-request/v1","tool":"github.read_repo","connector":{"connector_id":"conn-fixture-0001","capability":"repository.read"},"resource":"repos/owner/name"}`, "permit", ""},
		{"different resource denied", `{"schema":"kei.authorize-request/v1","tool":"github.read_repo","connector":{"connector_id":"conn-fixture-0001","capability":"repository.read"},"resource":"repos/other/name"}`, "deny", "no_matching_policy"},
		{"missing target denied", `{"schema":"kei.authorize-request/v1","tool":"github.read_repo","connector":{"connector_id":"conn-fixture-0001","capability":"repository.read"}}`, "deny", "target_required"},
		{"unregistered connector denied", `{"schema":"kei.authorize-request/v1","tool":"github.read_repo","connector":{"connector_id":"conn-forged","capability":"repository.read"},"resource":"repos/owner/name"}`, "deny", "connector_not_registered"},
		{"unregistered capability denied", `{"schema":"kei.authorize-request/v1","tool":"github.read_repo","connector":{"connector_id":"conn-fixture-0001","capability":"admin.write"},"resource":"repos/owner/name"}`, "deny", "capability_not_registered"},
		{"forged agent denied", `{"schema":"kei.authorize-request/v1","tool":"github.read_repo","agent_id":"agent-forged","connector":{"connector_id":"conn-fixture-0001","capability":"repository.read"},"resource":"repos/owner/name"}`, "deny", "agent_mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := withSessionHeader(httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(tc.body)), sessionResponse.SessionID)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			var got socketAuthorizeResponse
			if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Decision != tc.decision || (tc.reason != "" && got.ReasonCode != tc.reason) {
				t.Fatalf("status=%d decision=%+v body=%s", rec.Code, got, rec.Body.String())
			}
		})
	}
}

func TestSocketAuthorizeConnectorBindingUsesValidatedCompletePlan(t *testing.T) {
	policybundle.SetV2SchemaValidator(runtimeV2SchemaValidator(t))
	now := time.Now().UTC()
	cfg := testPolicyConfig{policyStateDir: t.TempDir(), token: "runtime-token"}
	var auditEvent json.RawMessage
	local := NewLocalPDP(cfg, func(event json.RawMessage) { auditEvent = append(json.RawMessage(nil), event...) })
	defer local.Close()
	identity := &Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: "agent-fixture-0001"}
	local.SetIdentity(identity)
	store, err := policybundle.OpenStore(cfg.PolicyStateDir())
	if err != nil {
		t.Fatal(err)
	}
	bundle := v2PreflightBundle(t, now)
	var bundleDoc map[string]any
	if err := json.Unmarshal(bundle, &bundleDoc); err != nil {
		t.Fatal(err)
	}
	policySet := bundleDoc["policy_set"].(map[string]any)
	checks := policySet["checks"].([]any)
	checks[0].(map[string]any)["selector"].(map[string]any)["resource_id"] = "acme/kei"
	policySet["connectors"] = []any{map[string]any{
		"id": "conn-fixture-0001", "provider": "github", "credential_source": "oauth", "account_model": "shared",
		"capabilities": []any{map[string]any{"name": "repository.read", "mutating": false}},
	}}
	bundle, err = json.Marshal(bundleDoc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(bundle, identity.ID, identity.OrgID, *identity.WorkspaceID, now); err != nil {
		t.Fatal(err)
	}
	h := local.NewHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return true })
	put := httptest.NewRecorder()
	h.ServeHTTP(put, httptest.NewRequest(http.MethodPut, "/v1/session", strings.NewReader(`{"schema":"kei.session/v2","source":"discord","external_id":"discord-user-1"}`)))
	var sessionResponse socketSessionResponse
	if put.Code != http.StatusCreated || json.Unmarshal(put.Body.Bytes(), &sessionResponse) != nil || sessionResponse.SessionID == "" {
		t.Fatalf("session status=%d body=%s", put.Code, put.Body.String())
	}

	authorize := func(contextData string) socketAuthorizeResponse {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"schema": authorizeRequestSchema, "tool": "github.read_repo", "action": "read",
			"tool_args": json.RawMessage(`{}`), "tool_context": json.RawMessage(contextData),
		})
		req := withSessionHeader(httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(string(body))), sessionResponse.SessionID)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var response socketAuthorizeResponse
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &response) != nil {
			t.Fatalf("authorize status=%d body=%s", rec.Code, rec.Body.String())
		}
		return response
	}
	if got := authorize(`{"repository":"acme/kei"}`); got.Decision != "permit" {
		t.Fatalf("valid complete plan decision=%+v", got)
	}
	if strings.Contains(string(auditEvent), "acme/kei") {
		t.Fatalf("raw plan arguments leaked into audit event: %s", auditEvent)
	}
	if got := authorize(`{"repository":"acme/kei","extra":"value"}`); got.Decision != "deny" || got.ReasonCode != "operation_plan_invalid" {
		t.Fatalf("arguments outside the registered schema decision=%+v", got)
	}
	if got := authorize(`{"repository":"other/repo"}`); got.Decision != "deny" || got.ReasonCode != "no_matching_policy" {
		t.Fatalf("resource outside the policy decision=%+v", got)
	}
	sessionID, err := local.Sessions.Create(pdp.Subject{UserID: "user-alice", Status: pdp.StatusLinked, Source: "discord", ExternalID: "discord-user-1"})
	if err != nil {
		t.Fatal(err)
	}
	releaseRequest := socketAuthorizeRequest{
		Tool: "github.read_repo", AgentID: "agent-fixture-0001", Resource: "repos/acme/kei",
		Connector: &socketAuthorizeConnector{ConnectorID: "conn-fixture-0001", Capability: "repository.read"},
		ToolArgs:  json.RawMessage(`{}`), ToolContext: json.RawMessage(`{"repository":"acme/kei"}`),
	}
	releaseDecision, _ := local.decideCredentialReleaseV2(context.Background(), sessionID, releaseRequest)
	if !releaseDecision.Allow {
		t.Fatalf("matching credential release target denied: %+v", releaseDecision)
	}
	releaseRequest.Resource = "repos/other/repo"
	mismatchedRelease, _ := local.decideCredentialReleaseV2(context.Background(), sessionID, releaseRequest)
	if mismatchedRelease.Allow || mismatchedRelease.ReasonCode != "operation_plan_invalid" {
		t.Fatalf("credential resource mismatch decision=%+v", mismatchedRelease)
	}
}

func TestSocketAuthorizeV2RouteDenialsExplainTheirRegistrationInKeiAudit(t *testing.T) {
	policybundle.SetV2SchemaValidator(runtimeV2SchemaValidator(t))
	now := time.Now().UTC()
	cfg := testPolicyConfig{policyStateDir: t.TempDir(), token: "runtime-token"}
	var auditEvent json.RawMessage
	local := NewLocalPDP(cfg, func(event json.RawMessage) {
		auditEvent = append(json.RawMessage(nil), event...)
	})
	identity := &Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: "agent-fixture-0001"}
	local.SetIdentity(identity)
	store, err := policybundle.OpenStore(cfg.PolicyStateDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(v2PreflightBundle(t, now), identity.ID, identity.OrgID, *identity.WorkspaceID, now); err != nil {
		t.Fatal(err)
	}
	h := local.NewHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return true })
	put := httptest.NewRecorder()
	h.ServeHTTP(put, httptest.NewRequest(http.MethodPut, "/v1/session", strings.NewReader(`{"schema":"kei.session/v2","source":"discord","external_id":"discord-user-1"}`)))
	var sessionResponse socketSessionResponse
	if put.Code != http.StatusCreated || json.Unmarshal(put.Body.Bytes(), &sessionResponse) != nil || sessionResponse.SessionID == "" {
		t.Fatalf("session status=%d body=%s", put.Code, put.Body.String())
	}

	call := func(tool string) socketAuthorizeResponse {
		t.Helper()
		body, _ := json.Marshal(socketAuthorizeRequest{Schema: authorizeRequestSchema, Tool: tool})
		req := withSessionHeader(httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(string(body))), sessionResponse.SessionID)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var response socketAuthorizeResponse
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &response) != nil {
			t.Fatalf("authorize %s status=%d body=%s", tool, rec.Code, rec.Body.String())
		}
		return response
	}
	checkAudit := func(wantCode, wantReason string) {
		t.Helper()
		var event struct {
			ReasonCode   string  `json:"reason_code"`
			PolicyReason *string `json:"policy_reason"`
		}
		if err := json.Unmarshal(auditEvent, &event); err != nil {
			t.Fatal(err)
		}
		if event.ReasonCode != wantCode || event.PolicyReason == nil || *event.PolicyReason != wantReason {
			t.Fatalf("audit reason=%q policy_reason=%v, want %q / %q", event.ReasonCode, event.PolicyReason, wantCode, wantReason)
		}
	}

	connector := call("github.read_repo")
	if connector.Decision != "deny" || connector.ReasonCode != "preflight_required" || !strings.Contains(connector.Reason, "connector_binding") {
		t.Fatalf("connector decision=%+v", connector)
	}
	checkAudit(connector.ReasonCode, connector.Reason)

	// Supplying target dimensions must not turn a connector_binding tool into
	// a decision-only harness_executor call.
	targetBody := `{"schema":"kei.authorize-request/v1","tool":"github.read_repo","connector":{"connector_id":"conn-fixture-0001","capability":"repository.read"},"resource":"repos/owner/name"}`
	targetReq := withSessionHeader(httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(targetBody)), sessionResponse.SessionID)
	targetRec := httptest.NewRecorder()
	h.ServeHTTP(targetRec, targetReq)
	var targetResponse socketAuthorizeResponse
	if targetRec.Code != http.StatusOK || json.Unmarshal(targetRec.Body.Bytes(), &targetResponse) != nil || targetResponse.Decision == "permit" {
		t.Fatalf("connector_binding target decision=%+v body=%s", targetResponse, targetRec.Body.String())
	}

	unknown := call("utilities.oms.list_triage")
	if unknown.Decision != "deny" || unknown.ReasonCode != "tool_not_registered" || !strings.Contains(unknown.Reason, "harness_executor") || !strings.Contains(unknown.Reason, "re-sync") {
		t.Fatalf("unregistered harness tool decision=%+v", unknown)
	}
	checkAudit(unknown.ReasonCode, unknown.Reason)
}

func TestSocketAuthorizeV2HarnessToolRequiresNamedSessionAndUsesToolPolicies(t *testing.T) {
	policybundle.SetV2SchemaValidator(runtimeV2SchemaValidator(t))
	now := time.Now().UTC()
	cfg := testPolicyConfig{policyStateDir: t.TempDir(), token: "runtime-token"}
	local := NewLocalPDP(cfg, nil)
	identity := &Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: "agent-fixture-0001"}
	local.SetIdentity(identity)
	store, err := policybundle.OpenStore(cfg.PolicyStateDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Activate(v2HarnessAuthorizationBundle(t, now), identity.ID, identity.OrgID, *identity.WorkspaceID, now); err != nil {
		t.Fatal(err)
	}
	h := local.NewHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return true })
	status := httptest.NewRecorder()
	h.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/v1/policy-bundle/status", nil))
	var bundleStatus socketPolicyBundleStatus
	if status.Code != http.StatusOK || json.Unmarshal(status.Body.Bytes(), &bundleStatus) != nil || bundleStatus.Schema != bundleStatusSchema || bundleStatus.BundleSchema != "kei.policy-bundle/v2" || bundleStatus.BundleVersion != 42 {
		t.Fatalf("bundle status=%d body=%s", status.Code, status.Body.String())
	}
	put := httptest.NewRecorder()
	h.ServeHTTP(put, httptest.NewRequest(http.MethodPut, "/v1/session", strings.NewReader(`{"schema":"kei.session/v2","source":"discord","external_id":"discord-user-1"}`)))
	var sessionResponse socketSessionResponse
	if put.Code != http.StatusCreated || json.Unmarshal(put.Body.Bytes(), &sessionResponse) != nil || sessionResponse.SessionID == "" {
		t.Fatalf("session status=%d body=%s", put.Code, put.Body.String())
	}
	body := `{"schema":"kei.authorize-request/v1","tool":"github.read_repo","framework":"discord"}`
	call := func(sessionID string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(body))
		if sessionID != "" {
			withSessionHeader(req, sessionID)
		}
		h.ServeHTTP(rec, req)
		return rec
	}
	var response socketAuthorizeResponse
	if err := json.Unmarshal(call("").Body.Bytes(), &response); err != nil || response.Decision != "deny" || response.ReasonCode != "session_required" {
		t.Fatalf("default-session response=%+v err=%v", response, err)
	}
	rec := call(sessionResponse.SessionID)
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || rec.Code != http.StatusOK || response.Decision != "permit" || response.PolicyID != "web-search-policy" || response.PolicyBundleVersion == nil || *response.PolicyBundleVersion != 42 {
		t.Fatalf("named-session status=%d response=%+v err=%v", rec.Code, response, err)
	}
}

func TestTokenlessOwnerSocketBindsVerifiedBundleSubjectAndKeepsSessionRoutesTokenOnly(t *testing.T) {
	policybundle.SetV2SchemaValidator(runtimeV2SchemaValidator(t))
	now := time.Now().UTC()
	cfg := testPolicyConfig{policyStateDir: t.TempDir(), token: "runtime-token"}
	local := NewLocalPDP(cfg, nil)
	defer local.Close()
	local.SetTokenlessOwnerSession(true)
	identity := &Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: "agent-fixture-0001"}
	local.SetIdentity(identity)
	var doc map[string]any
	if err := json.Unmarshal(v2HarnessAuthorizationBundle(t, now), &doc); err != nil {
		t.Fatal(err)
	}
	doc["subject"] = map[string]any{"user_id": "user-alice", "email": "alice@example.test", "groups": []string{"members"}}
	bundle, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	store, err := policybundle.OpenStore(cfg.PolicyStateDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Activate(bundle, identity.ID, identity.OrgID, *identity.WorkspaceID, now); err != nil {
		t.Fatal(err)
	}
	local.AfterSync(nil)
	local.SetCommandRunner(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	h := local.NewSocketHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return false })
	call := func(path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
		return rec
	}
	var response socketAuthorizeResponse
	allowed := call("/v1/authorize", `{"schema":"kei.authorize-request/v1","tool":"github.read_repo"}`)
	if err := json.Unmarshal(allowed.Body.Bytes(), &response); err != nil || allowed.Code != http.StatusOK || response.Decision != "permit" || response.PolicyID != "web-search-policy" {
		t.Fatalf("owner authorization=%d %+v err=%v", allowed.Code, response, err)
	}
	denied := call("/v1/authorize", `{"schema":"kei.authorize-request/v1","tool":"unknown.tool"}`)
	if err := json.Unmarshal(denied.Body.Bytes(), &response); err != nil || response.Decision != "unmatched" {
		t.Fatalf("owner denied call=%d %+v err=%v", denied.Code, response, err)
	}
	for _, route := range []struct{ path, body string }{
		{"/v1/session", `{"schema":"kei.session/v2","source":"cli"}`},
		{"/v1/commands:run", `{}`},
	} {
		req := httptest.NewRequest(http.MethodPut, route.path, strings.NewReader(route.body))
		if route.path != "/v1/session" {
			req.Method = http.MethodPost
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("tokenless %s status=%d body=%s", route.path, rec.Code, rec.Body.String())
		}
	}
	previousOwnerSession := local.ownerID
	delete(doc, "subject")
	doc["bundle_version"] = 43
	missingSubjectBundle, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(missingSubjectBundle, identity.ID, identity.OrgID, *identity.WorkspaceID, now); err != nil {
		t.Fatal(err)
	}
	local.AfterSync(nil)
	if local.ownerID != "" || local.Sessions.Exists(previousOwnerSession) {
		t.Fatal("owner session survived bundle refresh without a subject")
	}
	unavailable := call("/v1/authorize", `{"schema":"kei.authorize-request/v1","tool":"github.read_repo"}`)
	var unavailableBody struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(unavailable.Body.Bytes(), &unavailableBody) != nil || unavailable.Code != http.StatusForbidden || unavailableBody.Error.Code != "owner_subject_unavailable" {
		t.Fatalf("missing owner subject response=%d %s", unavailable.Code, unavailable.Body.String())
	}
	local.SetTokenlessOwnerSession(false)
	disabled := call("/v1/authorize", `{"schema":"kei.authorize-request/v1","tool":"github.read_repo"}`)
	if disabled.Code != http.StatusUnauthorized {
		t.Fatalf("disabled tokenless status=%d", disabled.Code)
	}
}

func TestTokenlessOwnerSocketReturnsGenericUnmatchedDecision(t *testing.T) {
	policybundle.SetV2SchemaValidator(runtimeV2SchemaValidator(t))
	now := time.Now().UTC()
	tests := []struct {
		name         string
		effect       string
		tool         string
		shell        string
		shellEffect  string
		shellDst     string // shell policy destination command; defaults to "git log"
		wireTool      string // tool name sent with shell_command; defaults to "shell"
		wantDecision  string
		wantReason    string
		wantSyntaxCode string
		wantPolicyID  string
	}{
		{name: "group permit", effect: "permit", tool: "custom.read", wantDecision: "permit", wantPolicyID: "tool-policy"},
		{name: "group deny", effect: "deny", tool: "custom.write", wantDecision: "deny", wantReason: "policy_deny", wantPolicyID: "tool-policy"},
		{name: "unmatched tool is neutral on the socket", tool: "custom.unmatched", wantDecision: "unmatched", wantReason: "no_matching_policy"},
		{name: "unmatched shell command is neutral on the socket", tool: "shell", shell: "git log", wantDecision: "unmatched", wantReason: "no_matching_policy"},
		{name: "matching shell permit", tool: "shell", shell: "git log", shellEffect: "permit", wantDecision: "permit", wantReason: "policy_permit", wantPolicyID: "shell-policy"},
		{name: "matching shell deny", tool: "shell", shell: "git log", shellEffect: "deny", wantDecision: "deny", wantReason: "policy_deny", wantPolicyID: "shell-policy"},
		{name: "compound shell command with no policies is unmatched", tool: "shell", shell: "git status && whoami", wantDecision: "unmatched", wantReason: "no_matching_policy"},
		{name: "compound shell command is denied by an explicit deny on one stage", tool: "shell", shell: "git status && whoami", shellEffect: "deny", shellDst: "whoami", wantDecision: "deny", wantReason: "policy_deny", wantPolicyID: "shell-policy"},
		{name: "unsupported shell syntax remains denied", tool: "shell", shell: "git status > out", wantDecision: "deny", wantReason: "unsupported_shell_syntax", wantSyntaxCode: "unsupported_redirection"},
		{name: "command substitution remains denied", tool: "shell", shell: "git status $(whoami)", wantDecision: "deny", wantReason: "unsupported_shell_syntax", wantSyntaxCode: "command_substitution"},
		{name: "legacy pi.bash tool name is not a shell tool", tool: "shell", wireTool: "pi.bash", shell: "git log", wantDecision: "deny", wantReason: "invalid_shell_request"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testPolicyConfig{policyStateDir: t.TempDir()}
			var audit json.RawMessage
			local := NewLocalPDP(cfg, func(event json.RawMessage) { audit = append(json.RawMessage(nil), event...) })
			defer local.Close()
			local.SetTokenlessOwnerSession(true)
			identity := &Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: "agent-fixture-0001"}
			local.SetIdentity(identity)
			var doc map[string]any
			if err := json.Unmarshal(v2PreflightBundle(t, now), &doc); err != nil {
				t.Fatal(err)
			}
			doc["subject"] = map[string]any{"user_id": "user-alice", "email": "alice@example.test", "groups": []string{"members"}}
			if tc.tool != "shell" {
				doc["identities"] = []any{}
			}
			set := doc["policy_set"].(map[string]any)
			if tc.effect != "" {
				set["tool_policies"] = []any{map[string]any{
					"policy_id": "tool-policy", "name": "unregistered tool policy", "effect": tc.effect, "priority": 10,
					"scope":    map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": nil},
					"selector": map[string]any{"source_principal": "group:members", "tool": tc.tool},
				}}
			}
			if tc.shellEffect != "" {
				shellDst := tc.shellDst
				if shellDst == "" {
					shellDst = "git log"
				}
				set["harness_policies"] = []any{map[string]any{
					"policy_id": "shell-policy", "name": "Pi shell policy", "src_pattern": "group:members", "dst_pattern": "shell:" + shellDst, "action": tc.shellEffect, "priority": 10,
					"scope": map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": nil},
				}}
			}
			bundle, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			store, err := policybundle.OpenStore(cfg.PolicyStateDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = store.Activate(bundle, identity.ID, identity.OrgID, *identity.WorkspaceID, now); err != nil {
				t.Fatal(err)
			}
			local.AfterSync(nil)
			h := local.NewSocketHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return false })
			rec := httptest.NewRecorder()
			tool := tc.tool
			if tool == "" {
				tool = "custom.unmatched"
			}
			body := `{"schema":"kei.authorize-request/v1","tool":"` + tool + `"}`
			if tc.shell != "" {
				wireTool := tc.wireTool
				if wireTool == "" {
					wireTool = "shell"
				}
				body = `{"schema":"kei.authorize-request/v1","tool":"` + wireTool + `","shell_command":"` + tc.shell + `","tool_args_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(body))
			h.ServeHTTP(rec, req)
			var response socketAuthorizeResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || rec.Code != http.StatusOK || response.Decision != tc.wantDecision || response.ReasonCode != tc.wantReason || response.SyntaxCode != tc.wantSyntaxCode || response.PolicyID != tc.wantPolicyID {
				t.Fatalf("tool authorization status=%d response=%+v err=%v", rec.Code, response, err)
			}
			if tc.wantSyntaxCode != "" {
				var event struct {
					Decision   string `json:"decision"`
					ReasonCode string `json:"reason_code"`
					SyntaxCode string `json:"syntax_code"`
				}
				if err := json.Unmarshal(audit, &event); err != nil || event.Decision != "deny" || event.ReasonCode != "unsupported_shell_syntax" || event.SyntaxCode != tc.wantSyntaxCode {
					t.Fatalf("syntax audit event=%s err=%v; want deny/unsupported_shell_syntax/%s", audit, err, tc.wantSyntaxCode)
				}
				if response.Hint == "" {
					t.Fatalf("syntax denial response lacks actionable hint: %+v", response)
				}
			}
			if tc.wantDecision == "unmatched" {
				var event struct {
					Decision   string `json:"decision"`
					ReasonCode string `json:"reason_code"`
				}
				if err := json.Unmarshal(audit, &event); err != nil || event.Decision != "unmatched" || event.ReasonCode != "no_matching_policy" {
					t.Fatalf("audit event=%s err=%v, want unmatched/no_matching_policy", audit, err)
				}
			}
		})
	}
}

func TestTokenlessOwnerSessionLoadsCredentialsFromMatchingLinkedIdentity(t *testing.T) {
	policybundle.SetV2SchemaValidator(runtimeV2SchemaValidator(t))
	now := time.Now().UTC()
	cfg := testPolicyConfig{policyStateDir: t.TempDir(), token: "runtime-token"}
	var gotSubjectToken string
	i11 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != credrelease.ResolvePath || r.Header.Get("Authorization") != "Bearer runtime-token" {
			t.Errorf("credential release request path=%q authorization=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		gotSubjectToken = r.Header.Get("X-Kei-Subject-Token")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"credentials": []map[string]string{{"provider": "github", "access_token": "github-fixture-token", "token_type": "Bearer"}},
		})
	}))
	defer i11.Close()

	local := NewLocalPDP(cfg, nil)
	defer local.Close()
	local.SetTokenlessOwnerSession(true)
	local.SetCredentialStore(credrelease.NewStore(credrelease.NewClient(i11.URL, "runtime-token", time.Second)))
	identity := &Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001")}
	local.SetIdentity(identity)
	var doc map[string]any
	if err := json.Unmarshal(v2PreflightBundle(t, now), &doc); err != nil {
		t.Fatal(err)
	}
	doc["subject"] = map[string]any{"user_id": "user-alice", "email": "alice@example.test", "groups": []string{"members"}}
	doc["identities"] = []any{map[string]any{
		"source": "discord", "external_id": "discord-alice", "user_id": "user-alice", "status": "linked", "subject_token": "alice-linked-subject-token",
	}}
	bundle, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	store, err := policybundle.OpenStore(cfg.PolicyStateDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(bundle, identity.ID, identity.OrgID, *identity.WorkspaceID, now); err != nil {
		t.Fatal(err)
	}
	local.AfterSync(nil)
	if gotSubjectToken != "alice-linked-subject-token" {
		t.Fatalf("I11 subject token = %q, want the owner's linked identity token", gotSubjectToken)
	}
	var gotCredential string
	ownerSession := local.ownerID
	if err := local.UseCredential(context.Background(), ownerSession, "user-alice", "github", func(token string) error {
		gotCredential = token
		return nil
	}); err != nil || gotCredential != "github-fixture-token" {
		t.Fatalf("owner credential = %q, err=%v", gotCredential, err)
	}

	// A refresh without a linked identity ends the old owner session, flushes
	// its credentials, and leaves the new owner session without credentials.
	doc["bundle_version"] = 43
	doc["identities"] = []any{}
	refreshed, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(refreshed, identity.ID, identity.OrgID, *identity.WorkspaceID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	local.AfterSync(nil)
	if local.ownerID == ownerSession || local.Sessions.Exists(ownerSession) {
		t.Fatal("owner session survived credential refresh")
	}
	if err := local.UseCredential(context.Background(), local.ownerID, "user-alice", "github", func(string) error {
		t.Fatal("credential was available without a linked identity")
		return nil
	}); err == nil {
		t.Fatal("credential use without linked identity unexpectedly succeeded")
	}
}

func withSessionHeader(r *http.Request, id string) *http.Request { session.SetHeader(r, id); return r }

// v2AgentBoundHarnessBundle permits github.read_repo for the trusted agent
// (agent-bound, priority 20) and, below it, for the person user-alice.
func v2AgentBoundHarnessBundle(t *testing.T, now time.Time) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(v2HarnessAuthorizationBundle(t, now), &doc); err != nil {
		t.Fatal(err)
	}
	set := doc["policy_set"].(map[string]any)
	set["tool_policies"] = []any{
		map[string]any{
			"policy_id": "agent-bound-policy", "name": "trusted agent", "effect": "permit", "priority": 20,
			"scope":    map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": "agent-fixture-0001"},
			"selector": map[string]any{"source_principal": "agent:agent-fixture-0001", "source": "discord", "tool": "github.read_repo"},
		},
		map[string]any{
			"policy_id": "person-policy", "name": "person", "effect": "permit", "priority": 10,
			"scope":    map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": nil},
			"selector": map[string]any{"source_principal": "user:user-alice", "source": "discord", "tool": "github.read_repo"},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The daemon's trusted identity carries one agent: the installation's default
// (whoami agent_id, or the single is_default assignment). A v2 harness tool is
// decided for that agent. The request's agent_id is only checked against it:
// any other agent, including another agent assigned to the installation, is
// denied as agent_mismatch rather than trusted.
func TestSocketAuthorizeV2HarnessToolResolvesAgentFromTrustedIdentity(t *testing.T) {
	policybundle.SetV2SchemaValidator(runtimeV2SchemaValidator(t))
	tests := []struct {
		name           string
		defaultAgent   string
		requestAgent   string
		wantDecision   string
		wantPolicy     string
		wantReason     string
		wantAuditAgent string
	}{
		{name: "agent-bound permit allows with no request agent", defaultAgent: "agent-fixture-0001", wantDecision: "permit", wantPolicy: "agent-bound-policy", wantAuditAgent: "agent-fixture-0001"},
		{name: "request agent equal to trusted default is accepted", defaultAgent: "agent-fixture-0001", requestAgent: "agent-fixture-0001", wantDecision: "permit", wantPolicy: "agent-bound-policy", wantAuditAgent: "agent-fixture-0001"},
		{name: "request agent other than trusted default is denied as agent mismatch", defaultAgent: "agent-fixture-0001", requestAgent: "agent-other-0002", wantDecision: "deny", wantReason: "agent_mismatch", wantAuditAgent: "agent-fixture-0001"},
		{name: "request agent with no trusted default is denied as agent not assigned", requestAgent: "agent-fixture-0001", wantDecision: "deny", wantReason: "agent_not_assigned"},
		{name: "person-sourced permit is denied when no trusted default agent", wantDecision: "deny", wantReason: "agent_not_assigned"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now().UTC()
			cfg := testPolicyConfig{policyStateDir: t.TempDir(), token: "runtime-token"}
			var auditEvent json.RawMessage
			local := NewLocalPDP(cfg, func(event json.RawMessage) { auditEvent = append(json.RawMessage(nil), event...) })
			identity := &Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: tt.defaultAgent}
			local.SetIdentity(identity)
			store, err := policybundle.OpenStore(cfg.PolicyStateDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = store.Activate(v2AgentBoundHarnessBundle(t, now), identity.ID, identity.OrgID, *identity.WorkspaceID, now); err != nil {
				t.Fatal(err)
			}
			h := local.NewHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return true })
			put := httptest.NewRecorder()
			h.ServeHTTP(put, httptest.NewRequest(http.MethodPut, "/v1/session", strings.NewReader(`{"schema":"kei.session/v2","source":"discord","external_id":"discord-user-1"}`)))
			var sessionResponse socketSessionResponse
			if put.Code != http.StatusCreated || json.Unmarshal(put.Body.Bytes(), &sessionResponse) != nil {
				t.Fatalf("session status=%d body=%s", put.Code, put.Body.String())
			}
			body := `{"schema":"kei.authorize-request/v1","tool":"github.read_repo","framework":"discord"}`
			if tt.requestAgent != "" {
				body = `{"schema":"kei.authorize-request/v1","tool":"github.read_repo","framework":"discord","agent_id":"` + tt.requestAgent + `"}`
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(body))
			withSessionHeader(req, sessionResponse.SessionID)
			h.ServeHTTP(rec, req)
			var response socketAuthorizeResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || rec.Code != http.StatusOK || response.Decision != tt.wantDecision || response.PolicyID != tt.wantPolicy || (tt.wantReason != "" && response.ReasonCode != tt.wantReason) {
				t.Fatalf("status=%d response=%+v err=%v", rec.Code, response, err)
			}
			var audit struct {
				AgentID string `json:"agent_id"`
			}
			if err := json.Unmarshal(auditEvent, &audit); err != nil || audit.AgentID != tt.wantAuditAgent {
				t.Fatalf("audit agent_id=%q want %q event=%s", audit.AgentID, tt.wantAuditAgent, auditEvent)
			}
		})
	}
}

// The shell tool the socket decides is the bundle's, not a constant: a kind the
// registry says decides via the local PDP has its shell command line evaluated
// like pi.bash, attributed to that kind; a kind that decides natively, or a
// tool the registry does not list, is not a shell tool (HAI-622, D-13).
func TestSocketAuthorizeDecidesTheShellToolTheBundleRegistryNames(t *testing.T) {
	policybundle.SetV2SchemaValidator(runtimeV2SchemaValidator(t))
	now := time.Now().UTC()
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, tc := range []struct {
		name, tool   string
		wantDecision string
		wantReason   string
		wantPolicyID string
	}{
		{"registry shell tool of a pdp kind", "viapdp.shell", "permit", "policy_permit", "viapdp-shell"},
		{"pi.bash is pi, so a harness:viapdp policy does not match", "pi.bash", "unmatched", "no_matching_policy", ""},
		{"a native kind's shell tool is not decided here", "claude_code.bash", "deny", "invalid_shell_request", ""},
		{"a tool no kind names is not a shell tool", "nokind.shell", "deny", "invalid_shell_request", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testPolicyConfig{policyStateDir: t.TempDir()}
			local := NewLocalPDP(cfg, nil)
			defer local.Close()
			local.SetTokenlessOwnerSession(true)
			identity := &Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: "agent-fixture-0001"}
			local.SetIdentity(identity)
			var doc map[string]any
			if err := json.Unmarshal(v2PreflightBundle(t, now), &doc); err != nil {
				t.Fatal(err)
			}
			doc["subject"] = map[string]any{"user_id": "user-alice", "email": "alice@example.test", "groups": []string{"members"}}
			doc["harness_kinds"] = []any{
				map[string]any{"kind": "pi", "tool_prefix": "pi.", "shell_tool": "pi.bash", "gateable": true, "decides_via": "pdp"},
				map[string]any{"kind": "viapdp", "tool_prefix": "viapdp.", "shell_tool": "viapdp.shell", "gateable": true, "decides_via": "pdp"},
				map[string]any{"kind": "claude_code", "tool_prefix": "claude_code.", "shell_tool": "claude_code.bash", "gateable": true, "decides_via": "native"},
			}
			set := doc["policy_set"].(map[string]any)
			set["harness_policies"] = []any{map[string]any{
				"policy_id": "viapdp-shell", "name": "viapdp shell", "src_pattern": "harness:viapdp", "dst_pattern": "shell:git log", "action": "permit", "priority": 10,
				"scope": map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": nil},
			}}
			bundle, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			store, err := policybundle.OpenStore(cfg.PolicyStateDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = store.Activate(bundle, identity.ID, identity.OrgID, *identity.WorkspaceID, now); err != nil {
				t.Fatal(err)
			}
			local.AfterSync(nil)
			h := local.NewSocketHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return false })
			rec := httptest.NewRecorder()
			body := `{"schema":"kei.authorize-request/v1","tool":"` + tc.tool + `","shell_command":"git log","tool_args_digest":"` + digest + `"}`
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(body)))
			var response socketAuthorizeResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || rec.Code != http.StatusOK ||
				response.Decision != tc.wantDecision || response.ReasonCode != tc.wantReason || response.PolicyID != tc.wantPolicyID {
				t.Fatalf("%s: status=%d response=%+v err=%v; want %s/%s/%s", tc.tool, rec.Code, response, err, tc.wantDecision, tc.wantReason, tc.wantPolicyID)
			}
		})
	}
}
