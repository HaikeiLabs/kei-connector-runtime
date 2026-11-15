package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validV4ToolManifest = `{"schema":"kei.tool-manifest/v4","sync_mode":"merge","tools":[{"name":"github.get_issue","source":"github","operation_class":"read","service":"github","route":{"connector_binding":{"agent_id":"00000000-0000-0000-0000-000000000001","connector_id":"00000000-0000-0000-0000-000000000002"}},"required_capabilities":["issue.read"],"resource_types":[{"type":"issue","parent_type":"repository"}],"plan":{"args_schema":{"type":"object","properties":{"issue_number":{"type":"integer"}},"required":["issue_number"],"additionalProperties":false},"context_schema":{"type":"object","properties":{"repository":{"type":"string","minLength":1,"maxLength":256,"pattern":"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"}},"required":["repository"],"additionalProperties":false},"operations":[{"id":"get-issue","capability":"issue.read","resource":{"type":"issue","id":{"from":"args","pointer":"/issue_number","type":"integer"},"parent":{"type":"repository","id":{"from":"context","field":"repository","type":"string"}}},"provider_resource_template":"repos/{parent.id}/issues/{resource.id}","provider_input":{}}]}}]}`

func TestLoadToolManifestV3AndV4(t *testing.T) {
	v3 := `{"schema":"kei.tool-manifest/v3","tools":[{"name":"local.echo","service":"harness","source":"local","operation_class":"write","route":{"harness_executor":{"executor":"harness","registration":"echo"}}}]}`
	cases := []struct {
		name, raw, wantSchema string
		wantErr               bool
	}{
		{"v3 valid", v3, ToolManifestSchemaV3, false},
		{"v4 valid merge plan", validV4ToolManifest, ToolManifestSchemaV4, false},
		{"v3 unknown field closed", `{"schema":"kei.tool-manifest/v3","other":"value","tools":[]}`, "", true},
		{"v3 rejects v4 sync mode", strings.Replace(v3, `"schema":"kei.tool-manifest/v3",`, `"schema":"kei.tool-manifest/v3","sync_mode":"merge",`, 1), "", true},
		{"v3 rejects v4 plan field", strings.Replace(v3, `"registration":"echo"}}}`, `"registration":"echo"}},"plan":{}}`, 1), "", true},
		{"v4 unknown field closed", strings.Replace(validV4ToolManifest, `"sync_mode":"merge"`, `"unknown":true,"sync_mode":"merge"`, 1), "", true},
		{"v4 requires tools", `{"schema":"kei.tool-manifest/v4"}`, "", true},
		{"v4 rejects invalid sync mode", strings.Replace(validV4ToolManifest, `"sync_mode":"merge"`, `"sync_mode":"append"`, 1), "", true},
		{"v4 rejects invalid plan", strings.Replace(validV4ToolManifest, `"capability":"issue.read"`, `"capability":"issue.write"`, 1), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, []byte(tc.raw), 0600); err != nil {
				t.Fatal(err)
			}
			manifest, err := LoadToolManifest(path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("manifest=%+v err=%v wantErr=%v", manifest, err, tc.wantErr)
			}
			if err == nil && manifest.Schema != tc.wantSchema {
				t.Fatalf("schema=%q, want %q", manifest.Schema, tc.wantSchema)
			}
			if err == nil && tc.wantSchema == ToolManifestSchemaV4 && string(manifest.SyncMode) != `"merge"` {
				t.Fatalf("sync_mode=%s, want merge", manifest.SyncMode)
			}
		})
	}
}

func TestValidateToolManifestV3TypedRoutes(t *testing.T) {
	m := &ToolManifest{Schema: ToolManifestSchemaV3, Tools: []ToolDefinition{
		{Name: "github.get_issue", Service: "github", Source: "github", OperationClass: "read", RequiredCapabilities: []string{"issue.read"}, ResourceTypes: []KeiResourceType{{Type: "issue", ParentType: "repository"}}, Route: &ToolRoute{ConnectorBinding: &ConnectorBindingRoute{AgentID: "agent-1", ConnectorID: "binding-1"}}},
		{Name: "codex.shell", Service: "codex", Source: "codex", OperationClass: "write", Route: &ToolRoute{HarnessExecutor: &HarnessExecutorRoute{Executor: "codex", Registration: "codex.shell"}}},
	}}
	if err := validateToolManifest(m); err != nil {
		t.Fatalf("valid v3 manifest: %v", err)
	}
	m.Tools[0].Route.HarnessExecutor = &HarnessExecutorRoute{Executor: "codex", Registration: "codex.shell"}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "exactly one branch") {
		t.Fatalf("expected ambiguous-route failure, got %v", err)
	}
	m.Tools[0].Route = &ToolRoute{ConnectorBinding: &ConnectorBindingRoute{AgentID: "agent-1", ConnectorID: "binding-1"}}
	m.Tools[0].RequiredCapabilities = nil
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "connector_binding") {
		t.Fatalf("expected missing-capability failure, got %v", err)
	}
}

func TestValidateToolManifestV3MissingService(t *testing.T) {
	m := &ToolManifest{Schema: ToolManifestSchemaV3, Tools: []ToolDefinition{{Name: "codex.shell", Source: "codex", OperationClass: "write", Route: &ToolRoute{HarnessExecutor: &HarnessExecutorRoute{Executor: "codex", Registration: "codex.shell"}}}}}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "service") {
		t.Fatalf("expected required service error, got %v", err)
	}
}

func TestValidateToolManifestDuplicateNames(t *testing.T) {
	m := &ToolManifest{Schema: ToolManifestSchemaV3,
		Tools: []ToolDefinition{
			{Name: "foo.bar", Service: "foo", Source: "foo", OperationClass: "read", Route: &ToolRoute{HarnessExecutor: &HarnessExecutorRoute{Executor: "foo", Registration: "foo.bar"}}, Description: "first"},
			{Name: "foo.bar", Service: "foo", Source: "foo", OperationClass: "read", Route: &ToolRoute{HarnessExecutor: &HarnessExecutorRoute{Executor: "foo", Registration: "foo.bar"}}, Description: "second"},
		},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "duplicate name") {
		t.Fatalf("expected duplicate-name error, got %v", err)
	}
}

func TestValidateToolManifestTooManyTools(t *testing.T) {
	tools := make([]ToolDefinition, 257)
	for i := range tools {
		tools[i] = ToolDefinition{Name: "t", Service: "s"}
	}
	m := &ToolManifest{Schema: ToolManifestSchemaV3, Tools: tools}
	err := validateToolManifest(m)
	if err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("expected too-many error, got %v", err)
	}
}

func TestValidateToolManifestEmptyName(t *testing.T) {
	m := &ToolManifest{Schema: ToolManifestSchemaV3,
		Tools: []ToolDefinition{{Name: "", Service: "s"}},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("expected name-required error, got %v", err)
	}
}

func TestValidateToolManifestInvalidName(t *testing.T) {
	m := &ToolManifest{Schema: ToolManifestSchemaV3,
		Tools: []ToolDefinition{{Name: "has space", Service: "s"}},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "invalid name") {
		t.Fatalf("expected invalid-name error, got %v", err)
	}
}

func TestValidateToolManifestInvalidService(t *testing.T) {
	m := &ToolManifest{Schema: ToolManifestSchemaV3,
		Tools: []ToolDefinition{
			{Name: "t", Source: "s", OperationClass: "read", Service: "bad service", Route: &ToolRoute{HarnessExecutor: &HarnessExecutorRoute{Executor: "s", Registration: "t"}}},
		},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "invalid service") {
		t.Fatalf("expected invalid-service error, got %v", err)
	}
}
