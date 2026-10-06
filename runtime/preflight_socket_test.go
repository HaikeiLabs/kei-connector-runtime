package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func v2PreflightBundle(t *testing.T, now time.Time) []byte {
	t.Helper()
	check := map[string]any{
		"policy_id": "policy-review", "name": "review", "effect": "permit", "priority": 10,
		"scope":    map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": "agent-fixture-0001"},
		"selector": map[string]any{"source_principal": "user:user-alice", "source": "github", "connector_id": "conn-fixture-0001", "tool": "github.read_repo", "capability": "repository.read"},
	}
	raw, err := json.Marshal(map[string]any{
		"schema": "kei.policy-bundle/v2", "bundle_id": "bundle-v2-runtime", "bundle_version": 42, "policy_revision": 7, "issuer": policybundle.Issuer,
		"audience":  map[string]any{"installation_id": "inst-fixture-0001", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001"},
		"issued_at": now.UTC().Format(time.RFC3339Nano), "not_after": now.Add(time.Hour).UTC().Format(time.RFC3339Nano),
		"refresh":                  map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300},
		"subject_resolution":       map[string]any{"mode": "bundle", "max_cache_seconds": 60},
		"policy_set":               map[string]any{"schema": "kei.policy-set/v2", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "match_semantics": "kei.match/v2", "evaluation": map[string]any{"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"}, "checks": "per_capability_first_match_and", "default": "deny"}, "tools": []any{map[string]any{"name": "github.read_repo", "source": "github", "operation_class": "read", "route": map[string]any{"connector_binding": map[string]any{"connector_id": "conn-fixture-0001"}}, "required_capabilities": []string{"repository.read"}, "resource_types": []any{map[string]any{"type": "repository"}}}}, "checks": []any{check}, "tool_policies": []any{}},
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

func TestSocketV2PreflightConsumesAndInvalidatesLocalPlan(t *testing.T) {
	policybundle.SetV2SchemaValidator(runtimeV2SchemaValidator(t))
	now := time.Now().UTC()
	cfg := testPolicyConfig{policyStateDir: t.TempDir(), token: "runtime-token"}
	local := NewLocalPDP(cfg, nil)
	identity := &Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001")}
	local.SetIdentity(identity)
	store, err := policybundle.OpenStore(cfg.PolicyStateDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Activate(v2PreflightBundle(t, now), identity.ID, identity.OrgID, *identity.WorkspaceID, now); err != nil {
		t.Fatal(err)
	}
	definition := ToolDefinition{Name: "github.read_repo", Service: "github", Source: "github", OperationClass: "read", RequiredCapabilities: []string{"repository.read"}, ResourceTypes: []KeiResourceType{{Type: "repository"}}, Route: &ToolRoute{ConnectorBinding: &ConnectorBindingRoute{AgentID: "agent-fixture-0001", ConnectorID: "conn-fixture-0001"}}}
	planner := plannerFunc(func(args []byte, _ BindingContext) ([]Operation, error) {
		sum := sha256.Sum256(args)
		return []Operation{{ConnectorID: "conn-fixture-0001", Capability: "repository.read", Action: "read", Resource: "repos/acme/kei", ResourceType: "repository", ResourceID: "acme/kei", InputDigest: "sha256:" + hex.EncodeToString(sum[:])}}, nil
	})
	if err := local.RegisterOperationPlanner(definition, planner); err != nil {
		t.Fatal(err)
	}
	h := local.NewHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return true })
	put := httptest.NewRecorder()
	h.ServeHTTP(put, httptest.NewRequest(http.MethodPut, "/v1/session", strings.NewReader(`{"schema":"kei.session/v1","source":"discord","external_id":"discord-user-1"}`)))
	if put.Code != http.StatusNoContent {
		t.Fatalf("session status=%d body=%s", put.Code, put.Body.String())
	}
	preflightBody := `{"schema":"kei.preflight-request/v1","tool":"github.read_repo","arguments":{}}`
	pre := httptest.NewRecorder()
	h.ServeHTTP(pre, httptest.NewRequest(http.MethodPost, "/v1/preflight", strings.NewReader(preflightBody)))
	if pre.Code != http.StatusOK {
		t.Fatalf("preflight status=%d body=%s", pre.Code, pre.Body.String())
	}
	var grant socketPreflightResponse
	if err := json.Unmarshal(pre.Body.Bytes(), &grant); err != nil || grant.Handle == "" {
		t.Fatalf("preflight response=%s err=%v", pre.Body.String(), err)
	}
	inputHash := sha256.Sum256([]byte(`{}`))
	op := socketConsumeOperation{ConnectorID: "conn-fixture-0001", Capability: "repository.read", Action: "read", Resource: "repos/acme/kei", ResourceType: "repository", ResourceID: "acme/kei", ResourceParent: "", ResourceParentType: "", InputDigest: "sha256:" + hex.EncodeToString(inputHash[:])}
	consume := func(handle string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(socketConsumeRequest{Schema: "kei.consume-request/v1", Handle: handle, Tool: "github.read_repo", Operation: op})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/consume", strings.NewReader(string(body))))
		return rec
	}
	binding, _, bindErr := local.preflightBinding("github.read_repo", "", "", 0)
	if bindErr != nil {
		t.Fatalf("preflight binding unavailable: %v", bindErr)
	}
	ops, planErr := planner.Plan([]byte(`{}`), binding)
	if planErr != nil {
		t.Fatal(planErr)
	}
	gotDigest, gotVersion, allowed, authErr := local.AuthorizePlan(binding, ops)
	if authErr != nil || !allowed || gotDigest != binding.BundleDigest || gotVersion != binding.BundleVersion {
		t.Fatalf("plan authorizer failed: allowed=%v version=%d authErr=%v", allowed, gotVersion, authErr)
	}
	if rec := consume(grant.Handle); rec.Code != http.StatusNoContent {
		t.Fatalf("consume status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := consume(grant.Handle); rec.Code != http.StatusForbidden {
		t.Fatalf("replay status=%d", rec.Code)
	}
	pre = httptest.NewRecorder()
	h.ServeHTTP(pre, httptest.NewRequest(http.MethodPost, "/v1/preflight", strings.NewReader(preflightBody)))
	if pre.Code != http.StatusOK {
		t.Fatalf("second preflight status=%d", pre.Code)
	}
	if _, err := local.PreflightV2(context.Background(), "github.read_repo", "agent-fixture-0001", []byte(`{}`), "", 0, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	var second socketPreflightResponse
	if err := json.Unmarshal(pre.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	local.AfterSync(nil)
	if rec := consume(second.Handle); rec.Code != http.StatusForbidden {
		t.Fatalf("post-refresh consume status=%d", rec.Code)
	}
	var stale map[string]any
	if err := json.Unmarshal(v2PreflightBundle(t, now), &stale); err != nil {
		t.Fatal(err)
	}
	stale["bundle_version"] = 43
	stale["issued_at"] = now.Add(-61 * time.Second).Format(time.RFC3339Nano)
	staleBundle, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(staleBundle, identity.ID, identity.OrgID, *identity.WorkspaceID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	local.AfterSync(nil)
	if _, err := local.PreflightV2(context.Background(), "github.read_repo", "agent-fixture-0001", []byte(`{}`), "", 0, 10*time.Second); err == nil {
		t.Fatal("stale snapshot passed preflight")
	}
}
