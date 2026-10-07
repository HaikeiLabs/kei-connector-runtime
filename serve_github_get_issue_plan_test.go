package connectorruntime

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

func TestGitHubGetIssuePlanPermitsOnlyExactRepositoryAndIssue(t *testing.T) {
	for _, tc := range []struct {
		name, repository, number string
		allow                    bool
		wantCalls                int
	}{{"exact target", "acme/kei", "7", true, 1}, {"wrong repository", "acme/other", "7", false, 0}, {"wrong issue", "acme/kei", "8", false, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newInvokeRig(t)
			now := time.Now().UTC()
			check := map[string]any{"policy_id": "issue-7-repository", "name": "issue read", "effect": "permit", "priority": 10, "scope": map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": "agent-fixture-0001"}, "selector": map[string]any{"source_principal": "user:u-canary", "source": "github", "connector_id": invokeConnector, "tool": "github.get_issue", "capability": "issue.read", "resource_type": "issue", "resource_id": "7", "resource_parent": "acme/kei"}}
			plan := map[string]any{"args_schema": map[string]any{"type": "object", "properties": map[string]any{"issue_number": map[string]any{"type": "integer", "minimum": 1}}, "required": []any{"issue_number"}, "additionalProperties": false}, "context_schema": map[string]any{"type": "object", "properties": map[string]any{"repository": map[string]any{"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"}}, "required": []any{"repository"}, "additionalProperties": false}, "operations": []any{map[string]any{"id": "get-issue", "capability": "issue.read", "resource": map[string]any{"type": "issue", "id": map[string]any{"from": "args", "pointer": "/issue_number", "type": "integer"}, "parent": map[string]any{"type": "repository", "id": map[string]any{"from": "context", "field": "repository", "type": "string"}}}, "provider_resource_template": "repos/{parent.id}/issues/{resource.id}", "provider_input": map[string]any{}}}}
			bundle, err := json.Marshal(map[string]any{"schema": "kei.policy-bundle/v2", "bundle_id": "bundle-github-issue", "bundle_version": 43, "policy_revision": 7, "issuer": policybundle.Issuer, "audience": map[string]any{"installation_id": "inst-fixture-0001", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001"}, "issued_at": now.Format(time.RFC3339Nano), "not_after": now.Add(time.Hour).Format(time.RFC3339Nano), "refresh": map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300}, "subject_resolution": map[string]any{"mode": "bundle", "max_cache_seconds": 60}, "policy_set": map[string]any{"schema": "kei.policy-set/v2", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "match_semantics": "kei.match/v2", "evaluation": map[string]any{"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"}, "checks": "per_capability_first_match_and", "default": "deny"}, "tools": []any{map[string]any{"name": "github.get_issue", "source": "github", "operation_class": "read", "route": map[string]any{"connector_binding": map[string]any{"connector_id": invokeConnector}}, "required_capabilities": []string{"issue.read"}, "resource_types": []any{map[string]any{"type": "issue", "parent_type": "repository"}}, "plan": plan}}, "checks": []any{check}, "tool_policies": []any{}}, "agent_connector_bindings": []any{map[string]any{"agent_id": "agent-fixture-0001", "connector_id": invokeConnector, "capabilities": []string{"issue.read"}}}, "identities": []any{map[string]any{"source": "discord", "external_id": invokeExternalID, "user_id": "u-canary", "status": "linked", "groups": []string{"members"}, "subject_token": subjectCanary}}})
			if err != nil {
				t.Fatal(err)
			}
			store, err := policybundle.OpenStore(rig.cfg.RuntimeStateDir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Activate(bundle, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", now); err != nil {
				t.Fatal(err)
			}
			sessionID := rig.startNamedSession(t)
			args := `{"issue_number":` + tc.number + `}`
			contextMap := `{"repository":"` + tc.repository + `"}`
			pre := socketDoSession(t, rig.client, http.MethodPost, "/v1/preflight", sessionID, `{"schema":"kei.preflight-request/v1","session_id":"`+sessionID+`","tool":"github.get_issue","agent_id":"agent-fixture-0001","arguments":`+args+`,"context":`+contextMap+`}`)
			if !tc.allow {
				if pre.code != http.StatusForbidden {
					t.Fatalf("wrong target preflight=%d %s", pre.code, pre.dump)
				}
				_, calls := rig.counts()
				if len(calls) != 0 {
					t.Fatalf("denied preflight reached provider: %v", calls)
				}
				return
			}
			if pre.code != http.StatusOK {
				t.Fatalf("exact target preflight=%d %s", pre.code, pre.dump)
			}
			start := strings.Index(pre.dump, "{")
			var grant struct {
				Handle string `json:"handle"`
			}
			if start < 0 || json.Unmarshal([]byte(pre.dump[start:]), &grant) != nil || grant.Handle == "" {
				t.Fatalf("preflight response=%s", pre.dump)
			}
			body, _ := json.Marshal(map[string]any{"schema": "kei.connector-invoke-request/v1", "tool_name": "github.get_issue", "preflight_handle": grant.Handle, "session_id": sessionID, "agent_id": "agent-fixture-0001", "input": json.RawMessage(args), "context": json.RawMessage(contextMap), "trace_id": "trace-get-issue"})
			response := socketDoSession(t, rig.client, http.MethodPost, "/v1/connectors:invoke", sessionID, string(body))
			if response.code != http.StatusOK || !strings.Contains(response.dump, `"decision":"allow"`) {
				t.Fatalf("issue invoke=%d %s", response.code, response.dump)
			}
			_, calls := rig.counts()
			if len(calls) != tc.wantCalls {
				t.Fatalf("provider calls=%d want=%d", len(calls), tc.wantCalls)
			}
			paths := rig.providerPaths()
			if len(paths) != 1 || paths[0] != "/repos/acme/kei/issues/7" {
				t.Fatalf("provider paths=%v", paths)
			}
		})
	}
}
