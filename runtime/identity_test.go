package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSyncToolsPreservesV4SyncMode(t *testing.T) {
	for _, mode := range []string{"merge", ""} {
		t.Run(map[string]string{"merge": "merge", "": "omitted"}[mode], func(t *testing.T) {
			var got map[string]json.RawMessage
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPut || r.URL.Path != "/api/v1/runtime/tools" {
					t.Errorf("request=%s %s", r.Method, r.URL.Path)
				}
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Error(err)
				}
				w.Header().Set(ToolManifestProtocolHeader, ToolManifestSchemaV4)
				w.Header().Set(ToolManifestSupportedHeader, ToolManifestSchemaV4)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			manifest := &ToolManifest{Schema: ToolManifestSchemaV4, SyncMode: mode, Tools: []ToolDefinition{{Name: "codex.shell", Service: "codex", Source: "codex", OperationClass: "write", Route: &ToolRoute{HarnessExecutor: &HarnessExecutorRoute{Executor: "codex", Registration: "codex.shell"}}}}}
			if err := NewRuntimeClient(server.URL, time.Second).SyncTools(context.Background(), "token", manifest); err != nil {
				t.Fatal(err)
			}
			if mode == "merge" {
				var gotMode string
				if err := json.Unmarshal(got["sync_mode"], &gotMode); err != nil || gotMode != mode {
					t.Fatalf("encoded sync_mode=%s err=%v", got["sync_mode"], err)
				}
			} else if _, exists := got["sync_mode"]; exists {
				t.Fatalf("omitted mode encoded: %s", got["sync_mode"])
			}
		})
	}
}

func TestSyncToolsRejectsMergeOutsideV4(t *testing.T) {
	client := NewRuntimeClient("http://127.0.0.1:1", time.Second)
	for _, schema := range []string{ToolManifestSchemaV2, ToolManifestSchemaV3} {
		if err := client.SyncTools(context.Background(), "token", &ToolManifest{Schema: schema, SyncMode: "merge"}); err == nil {
			t.Errorf("SyncTools accepted sync_mode=merge for %s", schema)
		}
	}
	if err := client.SyncTools(context.Background(), "token", &ToolManifest{Schema: ToolManifestSchemaV4, SyncMode: "replace"}); err == nil {
		t.Error("SyncTools accepted unsupported v4 sync mode")
	}
}

func TestWhoAmIRoundTripsWorkspaceID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/whoami" {
			t.Fatalf("unexpected runtime path %q", r.URL.Path)
		}
		fmt.Fprint(w, `{"id":"installation-1","org_id":"org-1","workspace_id":"workspace-9","platform":"discord","status":"active","binding_status":"verified"}`)
	}))
	defer server.Close()

	identity, err := NewRuntimeClient(server.URL, time.Second).WhoAmI(context.Background(), "runtime-token")
	if err != nil {
		t.Fatal(err)
	}
	if identity.WorkspaceID == nil {
		t.Fatal("workspace_id = nil, want \"workspace-9\"")
	}
	if *identity.WorkspaceID != "workspace-9" {
		t.Fatalf("workspace_id = %q, want \"workspace-9\"", *identity.WorkspaceID)
	}
}

func TestWhoAmIOmittedWorkspaceIDStaysNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"installation-1","org_id":"org-1","platform":"discord","status":"active","binding_status":"verified"}`)
	}))
	defer server.Close()

	identity, err := NewRuntimeClient(server.URL, time.Second).WhoAmI(context.Background(), "runtime-token")
	if err != nil {
		t.Fatal(err)
	}
	if identity.WorkspaceID != nil {
		t.Fatalf("workspace_id = %q, want nil", *identity.WorkspaceID)
	}
}

func TestRuntimeClientFailsClosedOnRejectedRuntimeToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	if _, err := NewRuntimeClient(server.URL, time.Second).WhoAmI(context.Background(), "bad-token"); err == nil {
		t.Fatal("expected rejected runtime token to fail")
	}
}
