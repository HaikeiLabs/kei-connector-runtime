package runtime_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// A tool-bound POST /v1/credentials:release for a registered connector_binding
// tool may omit connector{}: the runtime derives connector_id from the tool's
// verified binding and the capability from its operation plan. A caller that
// still names the connector must name the bound one.

const (
	boundTool       = "github.read_repo"
	boundOtherConn  = "00000000-0000-4000-8000-000000009999"
	boundResource   = "repos/acme/kei"
	boundToolFields = `"tool":"github.read_repo","tool_args":{},"tool_context":{"repository":"acme/kei"}`
)

// boundToolBundle is a v2 bundle whose connector_binding tool github.read_repo
// is bound to the opaque_ref connector pgConnectorID (with the given account
// model) and permitted for u-alice. A second, unbound connector is described
// so a caller naming it hits the binding check rather than a missing descriptor.
func boundToolBundle(t *testing.T, accountModel string) []byte {
	t.Helper()
	policybundle.SetV2SchemaValidator(runtimeV2SchemaValidator(t))
	now := time.Now().UTC()
	descriptor := func(id string) map[string]any {
		return map[string]any{
			"id": id, "name": "gh-" + id[len(id)-4:], "provider": "github", "kind": "native",
			"credential_source": "opaque_ref", "account_model": accountModel,
			"credential_ref": "kei://connectors/" + id + "/" + pgField, "credential_backend": pgBackend,
			"capabilities": []any{map[string]any{"name": "repository.read", "mutating": false}},
		}
	}
	plan := map[string]any{
		"args_schema":    map[string]any{"type": "object", "properties": map[string]any{}, "required": []any{}, "additionalProperties": false},
		"context_schema": map[string]any{"type": "object", "properties": map[string]any{"repository": map[string]any{"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"}}, "required": []any{"repository"}, "additionalProperties": false},
		"operations":     []any{map[string]any{"id": "read-repository", "capability": "repository.read", "resource": map[string]any{"type": "repository", "id": map[string]any{"from": "context", "field": "repository", "type": "string"}}, "provider_resource_template": "repos/{resource.id}", "provider_input": map[string]any{}}},
	}
	check := map[string]any{
		"policy_id": "policy-read", "name": "read", "effect": "permit", "priority": 10,
		"scope":    map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": "agent-fixture-0001"},
		"selector": map[string]any{"source_principal": "user:u-alice", "source": "github", "connector_id": pgConnectorID, "tool": boundTool, "capability": "repository.read", "resource_id": "acme/kei"},
	}
	raw, err := json.Marshal(map[string]any{
		"schema": "kei.policy-bundle/v2", "bundle_id": "bound-release-bundle", "bundle_version": 1, "policy_revision": 1, "issuer": policybundle.Issuer,
		"audience":  map[string]any{"installation_id": "inst-fixture-0001", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001"},
		"issued_at": now.Format(time.RFC3339Nano), "not_after": now.Add(12 * time.Hour).Format(time.RFC3339Nano),
		"refresh": map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300}, "subject_resolution": map[string]any{"mode": "bundle", "max_cache_seconds": 0},
		"policy_set": map[string]any{
			"schema": "kei.policy-set/v2", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "match_semantics": "kei.match/v2",
			"evaluation": map[string]any{"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"}, "checks": "per_capability_first_match_and", "default": "deny"},
			"tools": []any{map[string]any{
				"name": boundTool, "source": "github", "operation_class": "read",
				"route":                 map[string]any{"connector_binding": map[string]any{"connector_id": pgConnectorID}},
				"required_capabilities": []string{"repository.read"}, "resource_types": []any{map[string]any{"type": "repository"}}, "plan": plan,
			}},
			"checks": []any{check}, "tool_policies": []any{},
			"harness_match_semantics": "kei.harness-match/v1", "harness_policies": []any{},
			"connectors": []any{descriptor(pgConnectorID), descriptor(boundOtherConn)},
		},
		"agent_connector_bindings": []any{
			map[string]any{"agent_id": "agent-fixture-0001", "connector_id": pgConnectorID, "capabilities": []string{"repository.read"}},
			map[string]any{"agent_id": "agent-fixture-0001", "connector_id": boundOtherConn, "capabilities": []string{"repository.read"}},
		},
		"identities": []any{map[string]any{"source": "discord", "external_id": "ext-alice", "user_id": "u-alice", "status": "linked", "subject_token": "es256-subject-alice"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func boundRelease(t *testing.T, rig *pgRig, externalID, body string) (int, pgReleaseResponse, string) {
	t.Helper()
	put := putSession(t, rig.h, `{"schema":"kei.session/v2","source":"discord","external_id":"`+externalID+`"}`)
	var opened struct {
		SessionID string `json:"session_id"`
	}
	if put.Code != http.StatusCreated || json.Unmarshal(put.Body.Bytes(), &opened) != nil || opened.SessionID == "" {
		t.Fatalf("PUT session = %d %s", put.Code, put.Body.String())
	}
	session := opened.SessionID
	rec := sessionRequest(rig.h, http.MethodPost, "/v1/credentials:release", session, body)
	var out pgReleaseResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, rec.Body.String())
		}
	}
	return rec.Code, out, rec.Body.String()
}

func TestCredentialsReleaseDerivesConnectorFromBoundTool(t *testing.T) {
	rig := newPGRig(t, pgRigOptions{bundle: boundToolBundle(t, "shared"), entries: []credentials.ConnectorReference{deliveredEntry()}})
	code, out, raw := boundRelease(t, rig, "ext-alice",
		fmt.Sprintf(`{"schema":"kei.credential-release-request/v1",%s,"resource":"%s"}`, boundToolFields, boundResource))
	if code != http.StatusOK || out.Decision != "allow" || out.Credential == nil || out.Credential.ConnectorID != pgConnectorID || out.Credential.AccessToken != pgDSN {
		t.Fatalf("release without connector: status=%d body=%s", code, raw)
	}
	// The audit records the derived connector and capability.
	if !containsAll(rig.auditText(), `"decision":"allow"`, pgConnectorID, "repository.read") {
		t.Fatalf("audit does not name the derived connector: %s", rig.auditText())
	}
	rig.assertNoLeak(t)
}

func TestCredentialsReleaseCallerConnectorStillAcceptedWhenItMatches(t *testing.T) {
	rig := newPGRig(t, pgRigOptions{bundle: boundToolBundle(t, "shared"), entries: []credentials.ConnectorReference{deliveredEntry()}})
	code, out, raw := boundRelease(t, rig, "ext-alice",
		fmt.Sprintf(`{"schema":"kei.credential-release-request/v1",%s,"connector":{"connector_id":"%s","capability":"repository.read"},"resource":"%s"}`, boundToolFields, pgConnectorID, boundResource))
	if code != http.StatusOK || out.Decision != "allow" || out.Credential == nil || out.Credential.ConnectorID != pgConnectorID {
		t.Fatalf("legacy release with the bound id: status=%d body=%s", code, raw)
	}
}

func TestCredentialsReleaseCallerConnectorMismatchDenied(t *testing.T) {
	rig := newPGRig(t, pgRigOptions{bundle: boundToolBundle(t, "shared"), entries: []credentials.ConnectorReference{deliveredEntry()}})
	code, out, raw := boundRelease(t, rig, "ext-alice",
		fmt.Sprintf(`{"schema":"kei.credential-release-request/v1",%s,"connector":{"connector_id":"%s","capability":"repository.read"},"resource":"%s"}`, boundToolFields, boundOtherConn, boundResource))
	if code != http.StatusOK || out.Decision != "deny" || out.ReasonCode != "tool_not_registered" || out.Credential != nil {
		t.Fatalf("mismatched connector: status=%d body=%s", code, raw)
	}
}

func TestCredentialsReleaseWithoutConnectorNeedsABoundTool(t *testing.T) {
	rig := newPGRig(t, pgRigOptions{bundle: boundToolBundle(t, "shared"), entries: []credentials.ConnectorReference{deliveredEntry()}})
	for name, body := range map[string]string{
		"unregistered tool with args": fmt.Sprintf(`{"schema":"kei.credential-release-request/v1","tool":"web_search","tool_args":{},"tool_context":{"repository":"acme/kei"},"resource":"%s"}`, boundResource),
		"bound tool without args":     fmt.Sprintf(`{"schema":"kei.credential-release-request/v1","tool":"%s","resource":"%s"}`, boundTool, boundResource),
		"untooled release":            fmt.Sprintf(`{"schema":"kei.credential-release-request/v1","resource":"%s"}`, boundResource),
	} {
		t.Run(name, func(t *testing.T) {
			code, _, raw := boundRelease(t, rig, "ext-alice", body)
			if code != http.StatusBadRequest || !containsAll(raw, `"invalid_request"`) {
				t.Fatalf("status=%d body=%s, want 400 invalid_request", code, raw)
			}
		})
	}
}

func TestCredentialsReleaseDerivedResourceOutsidePlanDenied(t *testing.T) {
	rig := newPGRig(t, pgRigOptions{bundle: boundToolBundle(t, "shared"), entries: []credentials.ConnectorReference{deliveredEntry()}})
	code, out, raw := boundRelease(t, rig, "ext-alice",
		fmt.Sprintf(`{"schema":"kei.credential-release-request/v1",%s,"resource":"repos/other/repo"}`, boundToolFields))
	if code != http.StatusOK || out.Decision != "deny" || out.ReasonCode != "operation_plan_invalid" || out.Credential != nil {
		t.Fatalf("resource outside the plan: status=%d body=%s", code, raw)
	}
}

func TestCredentialsReleaseDerivedPerUserConnectorNeedsUserSession(t *testing.T) {
	rig := newPGRig(t, pgRigOptions{bundle: boundToolBundle(t, "per_user"), entries: []credentials.ConnectorReference{deliveredEntry()}})
	code, out, raw := boundRelease(t, rig, "ext-unlinked",
		fmt.Sprintf(`{"schema":"kei.credential-release-request/v1",%s,"resource":"%s"}`, boundToolFields, boundResource))
	if code != http.StatusOK || out.Decision != "deny" || out.ReasonCode != "account_model_not_supported" || out.Credential != nil {
		t.Fatalf("per_user without a user session: status=%d body=%s", code, raw)
	}
	// Denied by the decision itself, before any credential lookup.
	if !containsAll(rig.auditText(), `"deny_source":"policy"`) || containsAll(rig.auditText(), `"deny_source":"runtime_state"`) {
		t.Fatalf("per_user deny was not a policy decision: %s", rig.auditText())
	}
}
