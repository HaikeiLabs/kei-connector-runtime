package connectorruntime

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

// HAI-669 (R2): the harness hands the user's Entra token to
// POST /v1/connectors:invoke as user_assertion. Through serve's real wiring,
// the daemon checks it against the session subject's bundle identity
// {source: "entra", external_id: <oid>} with the on_behalf_of exchanger
// before anything else runs, and never echoes, logs or audits it.

const (
	oboTenant   = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	oboUserOID  = "99999999-0000-0000-0000-000000000001"
	oboOtherOID = "99999999-0000-0000-0000-000000000002"
)

// oboTestAssertion is an unsigned user token for tenant tid and user oid,
// carrying a canary claim.
func oboTestAssertion(t *testing.T, tid, oid string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"tid": tid, "oid": oid, "aud": "api://kei-test", "canary": "obo-assertion-canary-61d2", "exp": time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + enc.EncodeToString(payload) + ".c2ln"
}

// oboDescriptorBundle is descriptorV2Bundle with invokeConnector as an
// on_behalf_of descriptor and, when entraOID is set, the session user's
// entra identity, the shape the catalog emits (gc-551).
func oboDescriptorBundle(t *testing.T, entraOID string) []byte {
	t.Helper()
	descriptor := map[string]any{
		"id": invokeConnector, "name": "entra-api", "provider": "http_api",
		"capabilities":      []any{map[string]any{"name": "http.get", "mutating": false}},
		"credential_source": "on_behalf_of", "account_model": "per_user", "credential_backend": "aws-secrets-manager",
		"on_behalf_of": map[string]any{
			"tenant_id": oboTenant, "client_id": "11111111-2222-3333-4444-555555555555",
			"resource": "https://api.example.com", "scopes": []string{"https://api.example.com/Data.Read"},
			"client_secret_ref": "kei://connectors/" + invokeConnector + "/client_secret",
		},
		"http_api": map[string]any{"registered_base_url": "https://api.example.com/v1", "registered_hostname": "api.example.com", "allowed_methods": []string{"GET"}, "allowed_path_patterns": []string{"/*"}, "query_allowlist": []string{}, "request_max_bytes": 1024, "response_max_bytes": 65536, "timeout_ms": 5000, "allow_redirects": false, "max_redirects": 0, "allow_cross_host_redirects": false, "credential_injection": map[string]any{"location": "header", "name": "Authorization", "scheme": "Bearer"}, "redaction": map[string]any{"headers": []string{"Authorization"}, "query_parameters": []string{}, "response_fields": []string{}}},
	}
	var doc map[string]any
	if err := json.Unmarshal(descriptorV2Bundle(t, []any{descriptor}), &doc); err != nil {
		t.Fatal(err)
	}
	// The tool is an http_api tool on the connector: http.get everywhere the
	// github fixture says repository.read.
	set := doc["policy_set"].(map[string]any)
	tool := set["tools"].([]any)[0].(map[string]any)
	tool["source"], tool["required_capabilities"] = "http_api", []string{"http.get"}
	op := tool["plan"].(map[string]any)["operations"].([]any)[0].(map[string]any)
	op["capability"] = "http.get"
	selector := set["checks"].([]any)[0].(map[string]any)["selector"].(map[string]any)
	selector["source"], selector["capability"] = "http_api", "http.get"
	doc["agent_connector_bindings"].([]any)[0].(map[string]any)["capabilities"] = []string{"http.get"}
	if entraOID != "" {
		doc["identities"] = append(doc["identities"].([]any), map[string]any{"source": "entra", "external_id": entraOID, "user_id": "u-canary", "status": "linked"})
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// allowOnBehalfOfDescriptors validates bundles with the real closed v2
// schema after rewriting on_behalf_of descriptors to the opaque_ref shape it
// knows. The pinned schema does not admit on_behalf_of yet (a catalog and
// runtime follow-up); everything else stays validated.
func allowOnBehalfOfDescriptors(t *testing.T) {
	t.Helper()
	policybundle.SetV2SchemaValidator(func(raw []byte) error {
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return err
		}
		if set, ok := doc["policy_set"].(map[string]any); ok {
			connectors, _ := set["connectors"].([]any)
			for _, c := range connectors {
				d := c.(map[string]any)
				if d["credential_source"] == "on_behalf_of" {
					delete(d, "on_behalf_of")
					delete(d, "account_model")
					d["credential_source"], d["credential_ref"] = "opaque_ref", "kei://connectors/"+d["id"].(string)+"/client_secret"
				}
			}
		}
		rewritten, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		return validatePolicyBundleV2Schema(rewritten)
	})
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(validatePolicyBundleV2Schema) })
}

func TestServeChecksTheUserAssertionAgainstTheSessionSubject(t *testing.T) {
	allowOnBehalfOfDescriptors(t)
	var logs bytes.Buffer
	prevLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prevLog) })

	matching := oboTestAssertion(t, oboTenant, oboUserOID)
	other := oboTestAssertion(t, oboTenant, oboOtherOID)
	for name, tc := range map[string]struct {
		entraOID, assertion, reason string
	}{
		// The gate passes; on_behalf_of execution is R3, so the call denies
		// before any provider request.
		"matching user":           {oboUserOID, matching, "credential_source_not_supported"},
		"another user":            {oboUserOID, other, "assertion_subject_mismatch"},
		"no entra identity":       {"", matching, "assertion_subject_unlinked"},
		"assertion from a tenant": {oboUserOID, oboTestAssertion(t, "ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee", oboUserOID), "assertion_invalid"},
		"no assertion":            {oboUserOID, "", "assertion_required"},
	} {
		t.Run(name, func(t *testing.T) {
			rig := newInvokeRig(t)
			var response socketResponse
			stdout, stderr := captureFDs(t, func() {
				response = invokeV2RepositoryReadWith(t, rig, oboDescriptorBundle(t, tc.entraOID), map[string]any{"user_assertion": tc.assertion})
			})
			if response.code != http.StatusOK || !strings.Contains(response.dump, `"reason_code":"`+tc.reason+`"`) {
				t.Fatalf("invoke=%d %s, want reason %s", response.code, response.dump, tc.reason)
			}
			if _, github := rig.counts(); len(github) != 0 {
				t.Fatalf("provider called %d times", len(github))
			}
			for where, content := range map[string]string{"socket": response.dump, "stdout": stdout, "stderr": stderr, "log": logs.String(), "audit spool": readSpool(t, rig.cfg.AuditPath)} {
				if strings.Contains(content, "obo-assertion-canary") || (tc.assertion != "" && strings.Contains(content, tc.assertion)) {
					t.Errorf("%s leaked the user assertion", where)
				}
			}
		})
	}
}
