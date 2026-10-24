package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadToolManifestV3Only(t *testing.T) {
	cases := []struct {
		name, raw string
		wantErr   bool
	}{
		{"v3 valid", `{"schema":"kei.tool-manifest/v3","tools":[{"name":"local.echo","service":"harness","source":"local","operation_class":"write","route":{"harness_executor":{"executor":"harness","registration":"echo"}}}]}`, false},
		{"unknown field closed", `{"schema":"kei.tool-manifest/v3","other":"value","tools":[]}`, true},
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
			if err == nil && tc.name == "v3 valid" && manifest.Schema != ToolManifestSchemaV3 {
				t.Fatalf("schema=%q", manifest.Schema)
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
