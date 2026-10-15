package connectorruntime

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

// HAI-378 (ADR-034 amendment 2026-10-11), runtime step: the runtime accepts
// policy_set.connectors before the catalog emits it. These tests run the
// daemon's production wiring with a v2 bundle that carries descriptors.

// descriptorV2Bundle is a v2 bundle with one registered connector tool,
// github.repository_read on invokeConnector, and the given descriptors.
func descriptorV2Bundle(t *testing.T, connectors []any) []byte {
	t.Helper()
	now := time.Now().UTC()
	check := map[string]any{"policy_id": "permit-repository", "name": "repo read", "effect": "permit", "priority": 10, "scope": map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": "agent-fixture-0001"}, "selector": map[string]any{"source_principal": "user:u-canary", "source": "github", "connector_id": invokeConnector, "tool": "github.repository_read", "capability": "repository.read"}}
	plan := map[string]any{"args_schema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}, "context_schema": map[string]any{"type": "object", "properties": map[string]any{"repository": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"}}, "required": []any{"repository"}, "additionalProperties": false}, "operations": []any{map[string]any{"id": "get-repository", "capability": "repository.read", "resource": map[string]any{"type": "repository", "id": map[string]any{"from": "context", "field": "repository", "type": "string"}}, "provider_resource_template": "repos/{resource.id}", "provider_input": map[string]any{}}}}
	policySet := map[string]any{"schema": "kei.policy-set/v2", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "match_semantics": "kei.match/v2", "evaluation": map[string]any{"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"}, "checks": "per_capability_first_match_and", "default": "deny"}, "tools": []any{map[string]any{"name": "github.repository_read", "source": "github", "operation_class": "read", "route": map[string]any{"connector_binding": map[string]any{"connector_id": invokeConnector}}, "required_capabilities": []string{"repository.read"}, "resource_types": []any{map[string]any{"type": "repository"}}, "plan": plan}}, "checks": []any{check}, "tool_policies": []any{}, "harness_match_semantics": "kei.harness-match/v1", "harness_policies": []any{}}
	if connectors != nil {
		policySet["connectors"] = connectors
	}
	bundle, err := json.Marshal(map[string]any{"schema": "kei.policy-bundle/v2", "bundle_id": "bundle-serve-descriptors", "bundle_version": 44, "policy_revision": 8, "issuer": "kei-policy-catalog", "audience": map[string]any{"installation_id": "inst-fixture-0001", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001"}, "issued_at": now.Format(time.RFC3339Nano), "not_after": now.Add(time.Hour).Format(time.RFC3339Nano), "refresh": map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300}, "subject_resolution": map[string]any{"mode": "bundle", "max_cache_seconds": 60}, "policy_set": policySet, "agent_connector_bindings": []any{map[string]any{"agent_id": "agent-fixture-0001", "connector_id": invokeConnector, "capabilities": []string{"repository.read"}}}, "identities": []any{map[string]any{"source": "discord", "external_id": invokeExternalID, "user_id": "u-canary", "status": "linked", "groups": []string{"members"}, "subject_token": subjectCanary}}})
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

// crmAndGitHubDescriptors are the contract example's two descriptor shapes:
// an http_api connector named crm (opaque_ref) and per_user github.
func crmAndGitHubDescriptors(githubID string) []any {
	return []any{
		map[string]any{"id": "conn-crm-0001", "name": "crm", "provider": "http_api", "capabilities": []any{map[string]any{"name": "http.get", "mutating": false}}, "credential_source": "opaque_ref", "account_model": "shared", "credential_ref": "kei://connectors/conn-crm-0001/api_key", "credential_backend": "aws-secrets-manager", "http_api": map[string]any{"registered_base_url": "https://crm.example.com/api", "registered_hostname": "crm.example.com", "allowed_methods": []string{"GET"}, "allowed_path_patterns": []string{"/leads/*"}, "query_allowlist": []string{}, "request_max_bytes": 1024, "response_max_bytes": 65536, "timeout_ms": 5000, "allow_redirects": false, "max_redirects": 0, "allow_cross_host_redirects": false, "credential_injection": map[string]any{"location": "header", "name": "Authorization", "scheme": "Bearer"}, "redaction": map[string]any{"headers": []string{"Authorization"}, "query_parameters": []string{}, "response_fields": []string{}}}},
		map[string]any{"id": githubID, "name": "github", "provider": "github", "capabilities": []any{map[string]any{"name": "repository.read", "mutating": false}}, "credential_source": "oauth", "account_model": "per_user"},
	}
}

// invokeV2RepositoryRead runs preflight and invoke for github.repository_read
// in a named session and returns the invoke response.
func invokeV2RepositoryRead(t *testing.T, rig *invokeRig, bundle []byte) socketResponse {
	t.Helper()
	return invokeV2RepositoryReadWith(t, rig, bundle, nil)
}

// invokeV2RepositoryReadWith is invokeV2RepositoryRead with extra fields in
// the invoke request body.
func invokeV2RepositoryReadWith(t *testing.T, rig *invokeRig, bundle []byte, extra map[string]any) socketResponse {
	t.Helper()
	store, err := policybundle.OpenStore(rig.cfg.RuntimeStateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(bundle, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", time.Now().UTC()); err != nil {
		t.Fatalf("the runtime must accept a v2 bundle with policy_set.connectors: %v", err)
	}
	sessionID := rig.startNamedSession(t)
	contextMap := `{"repository":"acme/kei"}`
	preflight := socketDoSession(t, rig.client, http.MethodPost, "/v1/preflight", sessionID, `{"schema":"kei.preflight-request/v1","session_id":"`+sessionID+`","tool":"github.repository_read","agent_id":"agent-fixture-0001","arguments":{},"context":`+contextMap+`}`)
	if preflight.code != http.StatusOK {
		t.Fatalf("preflight status=%d body=%s", preflight.code, preflight.dump)
	}
	var grant struct {
		Handle string `json:"handle"`
	}
	if err := json.Unmarshal([]byte(preflight.dump[strings.Index(preflight.dump, "{"):]), &grant); err != nil || grant.Handle == "" {
		t.Fatalf("preflight response=%s err=%v", preflight.dump, err)
	}
	request := map[string]any{"schema": "kei.connector-invoke-request/v1", "tool_name": "github.repository_read", "preflight_handle": grant.Handle, "session_id": sessionID, "agent_id": "agent-fixture-0001", "input": json.RawMessage(`{}`), "context": json.RawMessage(contextMap), "trace_id": "trace-hai-378"}
	for k, v := range extra {
		if v != "" {
			request[k] = v
		}
	}
	body, _ := json.Marshal(request)
	return socketDoSession(t, rig.client, http.MethodPost, "/v1/connectors:invoke", sessionID, string(body))
}

func TestServeAcceptsConnectorDescriptorsAndRunsPerUserOAuthFromThem(t *testing.T) {
	var logs bytes.Buffer
	prevLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prevLog) })

	rig := newInvokeRig(t)
	var response socketResponse
	stdout, stderr := captureFDs(t, func() {
		response = invokeV2RepositoryRead(t, rig, descriptorV2Bundle(t, crmAndGitHubDescriptors(invokeConnector)))
	})
	if response.code != http.StatusOK || !strings.Contains(response.dump, `"decision":"allow"`) {
		t.Fatalf("invoke=%d %s", response.code, response.dump)
	}
	_, github := rig.counts()
	if len(github) != 1 || !strings.Contains(github[0], credentialCanary) {
		t.Fatalf("GitHub calls=%d; the per_user descriptor must use the session credential", len(github))
	}
	for name, content := range map[string]string{"socket": response.dump, "stdout": stdout, "stderr": stderr, "log": logs.String(), "audit spool": readSpool(t, rig.cfg.AuditPath)} {
		for _, canary := range []string{credentialCanary, subjectCanary} {
			if strings.Contains(content, canary) {
				t.Errorf("%s leaked %s", name, canary)
			}
		}
	}
}

// Once a bundle carries descriptors, a routed connector without one is a
// broken bundle: the call denies instead of falling back.
func TestServeDeniesRoutedConnectorWithoutDescriptor(t *testing.T) {
	rig := newInvokeRig(t)
	response := invokeV2RepositoryRead(t, rig, descriptorV2Bundle(t, crmAndGitHubDescriptors("conn-github-other")))
	if response.code != http.StatusOK || !strings.Contains(response.dump, `"reason_code":"descriptor_invalid"`) {
		t.Fatalf("invoke=%d %s", response.code, response.dump)
	}
	if _, github := rig.counts(); len(github) != 0 {
		t.Fatalf("GitHub was called %d times on a deny", len(github))
	}
}

// Without policy_set.connectors (an older catalog) the runtime keeps its
// pre-descriptor behavior.
func TestServeWithoutConnectorDescriptorsKeepsSessionProviders(t *testing.T) {
	rig := newInvokeRig(t)
	response := invokeV2RepositoryRead(t, rig, descriptorV2Bundle(t, nil))
	if response.code != http.StatusOK || !strings.Contains(response.dump, `"decision":"allow"`) {
		t.Fatalf("invoke=%d %s", response.code, response.dump)
	}
}
