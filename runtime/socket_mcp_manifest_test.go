package runtime_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-contracts/manifest"
	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

func mcpManifestBundle(t *testing.T, hash, toolHash string, approved bool) []byte {
	t.Helper()
	bundle := bundleWithIdentities(t, []policybundle.Identity{{Source: "discord", ExternalID: "discord-user", UserID: "u-alice", Status: "linked"}})
	var doc map[string]any
	if err := json.Unmarshal(bundle, &doc); err != nil {
		t.Fatal(err)
	}
	mcp := map[string]any{
		"url": "https://mcp.linear.example/mcp", "transport": "streamable_http", "auth_method": "oauth",
		"approved_tools": []any{},
	}
	if approved {
		mcp["approved_manifest_hash"] = hash
		mcp["approved_tools"] = []any{map[string]any{"name": "create_issue", "tool_hash": toolHash}}
	} else {
		mcp["approved_manifest_hash"] = nil
	}
	connector := map[string]any{
		"id": "connector-1", "name": "Linear production", "provider": "linear_mcp", "capabilities": []any{},
		"credential_source": "oauth", "account_model": "shared", "kind": "mcp", "slug": "linear",
		"mcp": mcp,
	}
	doc["policy_set"].(map[string]any)["connectors"] = []any{connector}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSocketMCPManifestSyncSubmitsCandidateAndRequiresBundleApproval(t *testing.T) {
	tool := json.RawMessage(`{"name":"create_issue","description":"Create issue","inputSchema":{"type":"object"}}`)
	tools := []json.RawMessage{tool}
	hash, err := manifest.Hash(tools)
	if err != nil {
		t.Fatal(err)
	}
	toolHash, err := manifest.ToolHash(tool)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name         string
		approved     bool
		status       string
		wantApproved bool
	}{
		{name: "new candidate", status: "candidate"},
		{name: "approved manifest present in local bundle", approved: true, status: "approved", wantApproved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/api/v1/organizations/org-fixture-0001/workspaces/ws-fixture-0001/data-connectors/connector-1/tool-manifests" {
					t.Errorf("catalog request = %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer runtime-secret" {
					t.Errorf("runtime auth header = %q", r.Header.Get("Authorization"))
				}
				var body struct {
					ManifestHash string            `json:"manifest_hash"`
					Tools        []json.RawMessage `json:"tools"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode catalog request: %v", err)
				}
				if body.ManifestHash != hash || len(body.Tools) != 1 {
					t.Errorf("catalog body = %+v", body)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"manifest_hash":"` + hash + `","status":"` + tc.status + `"}`))
			}))
			defer controlPlane.Close()

			stateDir := t.TempDir()
			activateBundle(t, stateDir, mcpManifestBundle(t, hash, toolHash, tc.approved))
			l := keiruntime.NewLocalPDP(connectorruntime.Config{
				RuntimeToken: "runtime-secret", RuntimeControlPlaneURL: controlPlane.URL, RuntimeStateDir: stateDir,
			}, nil)
			defer l.Close()
			l.SetIdentity(&keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: "agent-fixture-0001"})

			body := `{"schema":"kei.mcp-manifest-sync-request/v1","server_slug":"linear","tools":[{"name":"create_issue","description":"Create issue","inputSchema":{"type":"object"}}]}`
			handler := l.NewSocketHandler(http.NotFoundHandler(), func() error { return nil }, func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer runtime-secret" })
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/mcp-manifests:sync", strings.NewReader(body)))
			if response.Code != http.StatusOK {
				t.Fatalf("sync response = %d %s", response.Code, response.Body.String())
			}
			var result struct {
				Schema       string `json:"schema"`
				ManifestHash string `json:"manifest_hash"`
				Status       string `json:"status"`
				Approved     bool   `json:"approved"`
				ReasonCode   string `json:"reason_code"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Schema != "kei.mcp-manifest-sync-response/v1" || result.ManifestHash != hash || result.Status != tc.status || result.Approved != tc.wantApproved {
				t.Fatalf("sync result = %+v", result)
			}
			if !tc.wantApproved && result.ReasonCode != "manifest_approval_required" {
				t.Fatalf("pending result reason = %q", result.ReasonCode)
			}

			sessionID, err := l.Sessions.Create(pdp.Subject{UserID: "u-alice", Status: pdp.StatusLinked, Source: "discord", ExternalID: "discord-user"})
			if err != nil {
				t.Fatal(err)
			}
			authorize := func(manifestHash string) *httptest.ResponseRecorder {
				authorizeBody := `{"schema":"kei.authorize-request/v1","tool":"mcp:linear.create_issue","framework":"pi","span_id":"span-1","tool_args_digest":"sha256:` + strings.Repeat("a", 64) + `","mcp_manifest_hash":"` + manifestHash + `"}`
				req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(authorizeBody))
				req.Header.Set("Authorization", "Bearer runtime-secret")
				session.SetHeader(req, sessionID)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, req)
				return response
			}
			if !tc.approved {
				response := authorize(hash)
				if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "mcp_manifest_unapproved") {
					t.Fatalf("unapproved authorize response = %d %s", response.Code, response.Body.String())
				}
			} else {
				response := authorize("sha256:" + strings.Repeat("b", 64))
				if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "mcp_manifest_drift") {
					t.Fatalf("drifted authorize response = %d %s", response.Code, response.Body.String())
				}
				response = authorize(hash)
				if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "no_matching_policy") {
					t.Fatalf("matching approved manifest authorize response = %d %s", response.Code, response.Body.String())
				}
			}
		})
	}
}
