package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadToolManifestSyncMode(t *testing.T) {
	validV4 := `{"schema":"kei.tool-manifest/v4","sync_mode":"merge","tools":[{"name":"codex.shell","service":"codex","source":"codex","operation_class":"write","route":{"harness_executor":{"executor":"codex","registration":"codex.shell"}}}]}`
	cases := []struct {
		name, raw string
		wantErr   bool
	}{
		{"v4 merge", validV4, false},
		{"v4 omitted replace default", `{"schema":"kei.tool-manifest/v4","tools":[{"name":"codex.shell","service":"codex","source":"codex","operation_class":"write","route":{"harness_executor":{"executor":"codex","registration":"codex.shell"}}}]}`, false},
		{"v4 unsupported value", strings.Replace(validV4, `"merge"`, `"replace"`, 1), true},
		{"v4 invalid mode", strings.Replace(validV4, `"merge"`, `"merge-ish"`, 1), true},
		{"v2 merge forbidden", `{"schema":"kei.tool-manifest/v2","sync_mode":"merge","tools":[]}`, true},
		{"v3 merge forbidden", `{"schema":"kei.tool-manifest/v3","sync_mode":"merge","tools":[]}`, true},
		{"unknown field closed", strings.Replace(validV4, `"sync_mode":"merge"`, `"sync_mode":"merge","other":"value"`, 1), true},
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
			if err == nil && tc.name == "v4 merge" && manifest.SyncMode != "merge" {
				t.Fatalf("sync mode=%q", manifest.SyncMode)
			}
			if err == nil && tc.name == "v4 omitted replace default" && manifest.SyncMode != "" {
				t.Fatalf("omitted sync mode=%q", manifest.SyncMode)
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

func TestValidateToolManifestV2MissingSource(t *testing.T) {
	m := &ToolManifest{
		Schema: ToolManifestSchemaV2,
		Tools: []ToolDefinition{
			{Name: "test.tool", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "read"},
		},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "source is required") {
		t.Fatalf("expected source-required error, got %v", err)
	}
}

func TestValidateToolManifestV2MissingCapabilities(t *testing.T) {
	m := &ToolManifest{
		Schema: ToolManifestSchemaV2,
		Tools: []ToolDefinition{
			{Name: "test.tool", Source: "github", ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "read"},
		},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "required_capabilities") {
		t.Fatalf("expected capabilities-required error, got %v", err)
	}
}

func TestValidateToolManifestV2MissingResourceTypes(t *testing.T) {
	m := &ToolManifest{
		Schema: ToolManifestSchemaV2,
		Tools: []ToolDefinition{
			{Name: "test.tool", Source: "github", RequiredCapabilities: []string{"r"}, OperationClass: "read"},
		},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "resource_types") {
		t.Fatalf("expected resource_types-required error, got %v", err)
	}
}

func TestValidateToolManifestV2MissingOperationClass(t *testing.T) {
	m := &ToolManifest{
		Schema: ToolManifestSchemaV2,
		Tools: []ToolDefinition{
			{Name: "test.tool", Source: "github", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}},
		},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "operation_class") {
		t.Fatalf("expected operation_class-required error, got %v", err)
	}
}

func TestValidateToolManifestV2InvalidOperationClass(t *testing.T) {
	m := &ToolManifest{
		Schema: ToolManifestSchemaV2,
		Tools: []ToolDefinition{
			{Name: "test.tool", Source: "github", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "delete"},
		},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "invalid operation_class") {
		t.Fatalf("expected invalid operation_class error, got %v", err)
	}
}

func TestValidateToolManifestV2InvalidSource(t *testing.T) {
	m := &ToolManifest{
		Schema: ToolManifestSchemaV2,
		Tools: []ToolDefinition{
			{Name: "test.tool", Source: "UPPERCASE", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "read"},
		},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "invalid source") {
		t.Fatalf("expected invalid source error, got %v", err)
	}
}

func TestValidateToolManifestDuplicateNames(t *testing.T) {
	m := &ToolManifest{
		Tools: []ToolDefinition{
			{Name: "foo.bar", Source: "foo", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "read", Description: "first"},
			{Name: "foo.bar", Source: "foo", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "read", Description: "second"},
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
	m := &ToolManifest{Tools: tools}
	err := validateToolManifest(m)
	if err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("expected too-many error, got %v", err)
	}
}

func TestValidateToolManifestEmptyName(t *testing.T) {
	m := &ToolManifest{
		Tools: []ToolDefinition{{Name: "", Service: "s"}},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("expected name-required error, got %v", err)
	}
}

func TestValidateToolManifestInvalidName(t *testing.T) {
	m := &ToolManifest{
		Tools: []ToolDefinition{{Name: "has space", Service: "s"}},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "invalid name") {
		t.Fatalf("expected invalid-name error, got %v", err)
	}
}

func TestValidateToolManifestInvalidService(t *testing.T) {
	m := &ToolManifest{
		Tools: []ToolDefinition{
			{Name: "t", Source: "s", RequiredCapabilities: []string{"r"}, ResourceTypes: []KeiResourceType{{Type: "r"}}, OperationClass: "read", Service: "bad service"},
		},
	}
	if err := validateToolManifest(m); err == nil || !strings.Contains(err.Error(), "invalid service") {
		t.Fatalf("expected invalid-service error, got %v", err)
	}
}
