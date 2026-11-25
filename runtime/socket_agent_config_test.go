package runtime_test

import (
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// GET /v1/agent-config (plan 2026-11-25, option C): the trusted agent's model
// profile and bound connectors, built from the verified bundle in memory.
// Metadata only: it never carries a credential, a secret reference or a
// backend path.

var updateGolden = flag.Bool("update-golden", false, "rewrite runtime/testdata golden files")

const (
	acAgent      = "agent-fixture-0001"
	acGitHub     = "00000000-0000-4000-8000-00000000a001"
	acGrafana    = "00000000-0000-4000-8000-00000000a002"
	acOtherAgent = "00000000-0000-4000-8000-00000000a003"
	acProfile    = "00000000-0000-4000-8000-00000000b001"
	acSecretRef  = "kei://connectors/" + acGitHub + "/token"
)

func agentConfigBundle(t *testing.T) []byte {
	t.Helper()
	policybundle.SetV2SchemaValidator(runtimeV2SchemaValidator(t))
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	plan := func(opID, capability string) map[string]any {
		return map[string]any{
			"args_schema":    map[string]any{"type": "object", "properties": map[string]any{}, "required": []any{}, "additionalProperties": false},
			"context_schema": map[string]any{"type": "object", "properties": map[string]any{"repository": map[string]any{"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"}}, "required": []any{"repository"}, "additionalProperties": false},
			"operations":     []any{map[string]any{"id": opID, "capability": capability, "resource": map[string]any{"type": "repository", "id": map[string]any{"from": "context", "field": "repository", "type": "string"}}, "provider_resource_template": "repos/{resource.id}", "provider_input": map[string]any{}}},
		}
	}
	tool := func(name, connectorID string, binding map[string]any, opID, capability string) map[string]any {
		binding["connector_id"] = connectorID
		return map[string]any{
			"name": name, "source": "github", "operation_class": "read",
			"route":                 map[string]any{"connector_binding": binding},
			"required_capabilities": []string{capability}, "resource_types": []any{map[string]any{"type": "repository"}}, "plan": plan(opID, capability),
		}
	}
	descriptor := func(id, name, provider, kind string, extra map[string]any) map[string]any {
		d := map[string]any{
			"id": id, "name": name, "provider": provider, "kind": kind,
			"credential_source": "opaque_ref", "account_model": "shared",
			"credential_ref": "kei://connectors/" + id + "/token", "credential_backend": "aws-secrets-manager",
			"capabilities": []any{map[string]any{"name": "repository.read", "mutating": false}},
		}
		for k, v := range extra {
			d[k] = v
		}
		return d
	}
	raw, err := json.Marshal(map[string]any{
		"schema": "kei.policy-bundle/v2", "bundle_id": "agent-config-bundle", "bundle_version": 3, "policy_revision": 2, "issuer": policybundle.Issuer,
		"audience":  map[string]any{"installation_id": "inst-fixture-0001", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001"},
		"issued_at": now.Format(time.RFC3339Nano), "not_after": now.Add(time.Hour).Format(time.RFC3339Nano),
		"refresh": map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300}, "subject_resolution": map[string]any{"mode": "bundle", "max_cache_seconds": 0},
		"policy_set": map[string]any{
			"schema": "kei.policy-set/v2", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "match_semantics": "kei.match/v2",
			"evaluation": map[string]any{"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"}, "checks": "per_capability_first_match_and", "default": "deny"},
			"tools": []any{
				tool("github.read_repo", acGitHub, map[string]any{"version": "v0.19.0", "resource_template": "repos/{owner}/{repository}"}, "read-repository", "repository.read"),
				tool("github.list_commits", acGitHub, map[string]any{}, "list-commits", "repository.read"),
				tool("grafana.read_repo", acGrafana, map[string]any{}, "grafana-read", "repository.read"),
				tool("other.read_repo", acOtherAgent, map[string]any{}, "other-read", "repository.read"),
			},
			"checks": []any{}, "tool_policies": []any{},
			"harness_match_semantics": "kei.harness-match/v1", "harness_policies": []any{},
			"connectors": []any{
				descriptor(acGitHub, "acme-github", "github", "native", nil),
				descriptor(acGrafana, "acme-grafana", "grafana", "native", map[string]any{"grafana": map[string]any{"base_url": "https://grafana.acme.example"}}),
				descriptor(acOtherAgent, "other-agents-connector", "github", "native", nil),
			},
		},
		"agent_connector_bindings": []any{
			map[string]any{"agent_id": acAgent, "connector_id": acGitHub, "capabilities": []string{"repository.read"}},
			map[string]any{"agent_id": acAgent, "connector_id": acGrafana, "capabilities": []string{"repository.read"}},
			map[string]any{"agent_id": "agent-fixture-0002", "connector_id": acOtherAgent, "capabilities": []string{"repository.read"}},
		},
		"agent_model_profiles": []any{
			map[string]any{"agent_id": acAgent, "profile_id": acProfile, "status": "active"},
			map[string]any{"agent_id": "agent-fixture-0002", "profile_id": "00000000-0000-4000-8000-00000000b002", "status": "active"},
		},
		"identities": []any{map[string]any{"source": "discord", "external_id": "ext-alice", "user_id": "u-alice", "status": "linked"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type agentConfigRig struct {
	l   *keiruntime.LocalPDP
	h   http.Handler
	tcp http.Handler
}

func newAgentConfigRig(t *testing.T, bundle []byte, identity *keiruntime.Identity) agentConfigRig {
	t.Helper()
	dir := t.TempDir()
	if bundle != nil {
		activateBundle(t, dir, bundle)
	}
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken: policyTestToken, RuntimeControlPlaneURL: "https://kei.example", RuntimeStateDir: dir,
	}, nil)
	t.Cleanup(l.Close)
	if identity != nil {
		l.SetIdentity(identity)
	}
	auth := func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer "+policyTestToken }
	return agentConfigRig{
		l:   l,
		h:   l.NewSocketHandler(http.NotFoundHandler(), func() error { return nil }, auth),
		tcp: l.NewHandler(http.NotFoundHandler(), func() error { return nil }, auth),
	}
}

func trustedIdentity() *keiruntime.Identity {
	return &keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: acAgent}
}

func getAgentConfig(h http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSocketAgentConfigGolden(t *testing.T) {
	rig := newAgentConfigRig(t, agentConfigBundle(t), trustedIdentity())
	rig.l.SetModelProfileMetadata(&keiruntime.ModelProfileMetadata{
		ProfileID: acProfile, Model: "glm-5.3-flash", Endpoint: "https://models.acme.example/v1", IsDefault: true,
	})
	rec := getAgentConfig(rig.h, policyTestToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
	var got any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	pretty, _ := json.MarshalIndent(got, "", "  ")
	pretty = append(pretty, '\n')
	golden := filepath.Join("testdata", "agent_config.golden.json")
	if *updateGolden {
		if err := os.WriteFile(golden, pretty, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(pretty) {
		t.Fatalf("agent-config differs from %s:\n%s", golden, pretty)
	}
	assertNoSecretKeys(t, got, "")
	for _, needle := range []string{acSecretRef, "kei://", "aws-secrets-manager", "opaque_ref", acOtherAgent, "agent-fixture-0002", "other.read_repo"} {
		if strings.Contains(rec.Body.String(), needle) {
			t.Fatalf("agent-config contains %q: %s", needle, rec.Body.String())
		}
	}
}

// assertNoSecretKeys fails on any object key that looks like a secret field.
func assertNoSecretKeys(t *testing.T, v any, path string) {
	t.Helper()
	deny := []string{"credential", "secret", "token", "api_key", "apikey", "password", "private", "access_key", "authorization", "_ref", "backend"}
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			lower := strings.ToLower(k)
			for _, d := range deny {
				if strings.Contains(lower, d) {
					t.Fatalf("agent-config has secret-ish key %s.%s", path, k)
				}
			}
			assertNoSecretKeys(t, child, path+"."+k)
		}
	case []any:
		for _, child := range x {
			assertNoSecretKeys(t, child, path+"[]")
		}
	}
}

func TestSocketAgentConfigModelMetadataOnlyForAssignedProfile(t *testing.T) {
	rig := newAgentConfigRig(t, agentConfigBundle(t), trustedIdentity())
	// A snapshot for a profile the bundle no longer assigns is not served.
	rig.l.SetModelProfileMetadata(&keiruntime.ModelProfileMetadata{ProfileID: "00000000-0000-4000-8000-00000000b009", Model: "stale-model", Endpoint: "https://stale.example"})
	rec := getAgentConfig(rig.h, policyTestToken)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "stale") {
		t.Fatalf("status=%d body=%s, want the stale snapshot dropped", rec.Code, rec.Body.String())
	}
	var out struct {
		ModelProfile map[string]any `json:"model_profile"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.ModelProfile["profile_id"] != acProfile || out.ModelProfile["status"] != "active" {
		t.Fatalf("model_profile = %v (err %v), want the bundle assignment", out.ModelProfile, err)
	}
	if !rig.l.ModelProfileMetadataDue(time.Now()) {
		t.Fatal("a snapshot for another profile must be due for refresh")
	}
}

func TestSocketAgentConfigUnavailableIs503(t *testing.T) {
	for name, rig := range map[string]agentConfigRig{
		"no identity": newAgentConfigRig(t, agentConfigBundle(t), nil),
		"no bundle":   newAgentConfigRig(t, nil, trustedIdentity()),
		"no agent":    newAgentConfigRig(t, agentConfigBundle(t), &keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001")}),
	} {
		t.Run(name, func(t *testing.T) {
			rec := getAgentConfig(rig.h, policyTestToken)
			if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "agent_config_unavailable") {
				t.Fatalf("status=%d body=%s, want 503 agent_config_unavailable", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestSocketAgentConfigRequiresTokenAndSocket(t *testing.T) {
	rig := newAgentConfigRig(t, agentConfigBundle(t), trustedIdentity())
	rig.l.SetTokenlessOwnerSession(true)
	if rec := getAgentConfig(rig.h, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status=%d body=%s, want 401", rec.Code, rec.Body.String())
	}
	if rec := getAgentConfig(rig.tcp, policyTestToken); rec.Code != http.StatusNotFound {
		t.Fatalf("TCP handler: status=%d body=%s, want 404 (socket-only route)", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/agent-config", nil)
	req.Header.Set("Authorization", "Bearer "+policyTestToken)
	rec := httptest.NewRecorder()
	rig.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST: status=%d, want 404", rec.Code)
	}
}
