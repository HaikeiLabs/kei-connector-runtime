package connectorruntime

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

func TestResourceLessPlanStillUsesLiteralProviderResourceAndPolicy(t *testing.T) {
	for _, tc := range []struct {
		name              string
		resourceSelector  bool
		allow             bool
		wantProviderCalls int
	}{{"tool capability permit", false, true, 1}, {"resource selector cannot match absent dimensions", true, false, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newInvokeRig(t)
			now := time.Now().UTC()
			selector := map[string]any{"source_principal": "user:u-canary", "source": "github", "connector_id": invokeConnector, "tool": "github.repository_read", "capability": "repository.read"}
			if tc.resourceSelector {
				selector["resource_type"] = "repository"
				selector["resource_id"] = "acme/kei"
			}
			check := map[string]any{"policy_id": "resource-less-policy", "name": "repo", "effect": "permit", "priority": 10, "scope": map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": "agent-fixture-0001"}, "selector": selector}
			plan := map[string]any{"args_schema": map[string]any{"type": "object", "properties": map[string]any{}, "required": []any{}, "additionalProperties": false}, "context_schema": map[string]any{"type": "object", "properties": map[string]any{}, "required": []any{}, "additionalProperties": false}, "operations": []any{map[string]any{"id": "list-default-repository", "capability": "repository.read", "provider_resource_template": "repos/acme/kei", "provider_input": map[string]any{}}}}
			bundle, err := json.Marshal(map[string]any{"schema": "kei.policy-bundle/v2", "bundle_id": "bundle-resource-less", "bundle_version": 43, "policy_revision": 7, "issuer": "kei-policy-catalog", "audience": map[string]any{"installation_id": "inst-fixture-0001", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001"}, "issued_at": now.Format(time.RFC3339Nano), "not_after": now.Add(time.Hour).Format(time.RFC3339Nano), "refresh": map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300}, "subject_resolution": map[string]any{"mode": "bundle", "max_cache_seconds": 60}, "policy_set": map[string]any{"schema": "kei.policy-set/v2", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "match_semantics": "kei.match/v2", "evaluation": map[string]any{"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"}, "checks": "per_capability_first_match_and", "default": "deny"}, "tools": []any{map[string]any{"name": "github.repository_read", "source": "github", "operation_class": "read", "route": map[string]any{"connector_binding": map[string]any{"connector_id": invokeConnector}}, "required_capabilities": []string{"repository.read"}, "plan": plan}}, "checks": []any{check}, "tool_policies": []any{}}, "agent_connector_bindings": []any{map[string]any{"agent_id": "agent-fixture-0001", "connector_id": invokeConnector, "capabilities": []string{"repository.read"}}}, "identities": []any{map[string]any{"source": "discord", "external_id": invokeExternalID, "user_id": "u-canary", "status": "linked", "groups": []string{"members"}, "subject_token": subjectCanary}}})
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
			args, contextMap := `{}`, `{}`
			preflight := socketDoSession(t, rig.client, http.MethodPost, "/v1/preflight", sessionID, `{"schema":"kei.preflight-request/v1","session_id":"`+sessionID+`","tool":"github.repository_read","agent_id":"agent-fixture-0001","arguments":{},"context":{}}`)
			if !tc.allow {
				if preflight.code != http.StatusForbidden {
					t.Fatalf("resource selector preflight=%d %s", preflight.code, preflight.dump)
				}
				_, providerCalls := rig.counts()
				if len(providerCalls) != 0 {
					t.Fatalf("denied resource-less plan reached provider: %v", providerCalls)
				}
				return
			}
			if preflight.code != http.StatusOK {
				t.Fatalf("resource-less preflight=%d %s", preflight.code, preflight.dump)
			}
			start := strings.Index(preflight.dump, "{")
			var grant struct {
				Handle string `json:"handle"`
			}
			if start < 0 || json.Unmarshal([]byte(preflight.dump[start:]), &grant) != nil || grant.Handle == "" {
				t.Fatalf("preflight response=%s", preflight.dump)
			}
			body, _ := json.Marshal(map[string]any{"schema": "kei.connector-invoke-request/v1", "tool_name": "github.repository_read", "preflight_handle": grant.Handle, "session_id": sessionID, "agent_id": "agent-fixture-0001", "input": json.RawMessage(args), "context": json.RawMessage(contextMap), "trace_id": "trace-resource-less"})
			response := socketDoSession(t, rig.client, http.MethodPost, "/v1/connectors:invoke", sessionID, string(body))
			if response.code != http.StatusOK || !strings.Contains(response.dump, `"decision":"allow"`) {
				t.Fatalf("resource-less invoke=%d %s", response.code, response.dump)
			}
			_, providerCalls := rig.counts()
			if len(providerCalls) != tc.wantProviderCalls {
				t.Fatalf("provider calls=%d want=%d", len(providerCalls), tc.wantProviderCalls)
			}
		})
	}
}
