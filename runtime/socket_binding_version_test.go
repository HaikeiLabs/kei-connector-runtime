package runtime_test

import (
	"encoding/json"
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

// TestSocketAuthorizeAcceptsBindingVersion proves /v1/authorize accepts the
// optional binding_version field (contracts #124 mirrored locally, G3) and
// that a pinned version mismatch denies with binding_stale instead of being
// unreachable over the socket (opsproof Run 2, 4d).
func TestSocketAuthorizeAcceptsBindingVersion(t *testing.T) {
	policybundle.SetV2SchemaValidator(subjectV2SchemaValidator(t))
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	raw, err := os.ReadFile(filepath.Join("..", "pkg", "policybundle", "testdata", "catalog-v2-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["issued_at"] = now.Format(time.RFC3339Nano)
	doc["not_after"] = now.Add(time.Hour).Format(time.RFC3339Nano)
	audience := doc["audience"].(map[string]any)
	audience["installation_id"], audience["org_id"], audience["workspace_id"] = "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001"
	set := doc["policy_set"].(map[string]any)
	set["org_id"], set["workspace_id"] = "org-fixture-0001", "ws-fixture-0001"
	set["tool_policies"], set["harness_policies"] = []any{}, []any{}
	set["tools"] = []any{
		map[string]any{
			"name": "github.get_issue", "source": "github", "operation_class": "read",
			"route":                 map[string]any{"connector_binding": map[string]any{"connector_id": "conn-a", "version": "v0.19.0"}},
			"required_capabilities": []string{"issue.read"},
			"resource_types":        []any{map[string]any{"type": "issue", "parent_type": "repository"}},
			"plan": map[string]any{
				"args_schema":    map[string]any{"type": "object", "properties": map[string]any{"number": map[string]any{"type": "integer"}}, "required": []any{"number"}, "additionalProperties": false},
				"context_schema": map[string]any{"type": "object", "properties": map[string]any{"repository": map[string]any{"type": "string"}}, "required": []any{"repository"}, "additionalProperties": false},
				"operations": []any{
					map[string]any{"id": "get-issue", "capability": "issue.read", "resource": map[string]any{"type": "issue", "id": map[string]any{"from": "args", "pointer": "/number", "type": "integer"}, "parent": map[string]any{"type": "repository", "id": map[string]any{"from": "context", "field": "repository", "type": "string"}}}, "provider_resource_template": "repos/{parent.id}/issues/{resource.id}", "provider_input": map[string]any{}},
				},
			},
		},
	}
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	activateBundle(t, dir, raw)
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken: policyTestToken, RuntimeControlPlaneURL: "https://kei.example", RuntimeStateDir: dir,
	}, nil)
	t.Cleanup(l.Close)
	l.SetTokenlessOwnerSession(true)
	l.SetIdentity(&keiruntime.Identity{
		ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: "trusted-default",
	})
	l.AfterSync(nil)
	h := l.NewSocketHandler(http.NotFoundHandler(), func() error { return nil }, func(*http.Request) bool { return false })

	post := func(body string) (int, string, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var response struct {
			Decision   string `json:"decision"`
			ReasonCode string `json:"reason_code"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &response)
		return rec.Code, response.Decision, response.ReasonCode
	}

	// A request that pins the bundle's own binding version is accepted (200
	// with a policy decision, never a 400 unknown-field error).
	code, _, _ := post(`{"schema":"kei.authorize-request/v1","tool":"github.get_issue","resource":"repos/acme/project/issues/42","framework":"pi","span_id":"0193f5ef-5522-7c2a-a650-ae62e8bc4319","tool_args_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tool_args":{"number":42},"tool_context":{"repository":"acme/project"},"binding_version":"v0.19.0"}`)
	if code != http.StatusOK {
		t.Fatalf("binding_version matching the bundle = %d, want 200: binding_version must be accepted on /v1/authorize", code)
	}
	// A pinned version that is not the bundle's denies with binding_stale.
	code, decision, reason := post(`{"schema":"kei.authorize-request/v1","tool":"github.get_issue","resource":"repos/acme/project/issues/42","framework":"pi","span_id":"0193f5ef-5522-7c2a-a650-ae62e8bc4319","tool_args_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tool_args":{"number":42},"tool_context":{"repository":"acme/project"},"binding_version":"v0.18.0"}`)
	if code != http.StatusOK || decision != "deny" || reason != "binding_stale" {
		t.Fatalf("stale binding_version = %d %s/%s, want 200 deny/binding_stale", code, decision, reason)
	}
}
