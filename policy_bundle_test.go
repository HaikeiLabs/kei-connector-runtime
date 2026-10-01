package connectorruntime

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

func decodePayload(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
func encodePayload(b []byte) string          { return base64.StdEncoding.EncodeToString(b) }

func TestVerifyCanonicalBundleExample(t *testing.T) {
	env, err := os.ReadFile("docs/contracts/examples/policy-bundle-v1.envelope.example.json")
	if err != nil {
		t.Fatal(err)
	}
	keys := policybundle.KeySet{Keys: []policybundle.Key{{KTY: "OKP", CRV: "Ed25519", X: "W5NclXraIJdyUtLqIHtaY7XfnhskAmqiub36Tgt_ye8", KID: "kei-pb-000000-01", Use: "sig", Alg: "EdDSA", Status: "active"}}}
	verified, err := policybundle.Verify(env, keys, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", 41, time.Date(2026, 9, 28, 17, 0, 0, 0, time.UTC), false)
	if err != nil {
		t.Fatalf("verify canonical test envelope: %v", err)
	}
	if verified.Payload.BundleVersion != 42 || verified.Digest != "sha256:5f3896e479429bd8dae1c204c8ecbde5aa7a0e74d77a225592bfeed0fd30f311" {
		t.Fatalf("unexpected verified bundle: version=%d digest=%s", verified.Payload.BundleVersion, verified.Digest)
	}

	if _, err := policybundle.Verify(env, keys, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", 41, time.Date(2026, 9, 28, 17, 0, 0, 0, time.UTC), true); err == nil {
		t.Fatal("production accepted public test signing key")
	}
}

func TestVerifyBundleRejectsTamperingRevocationAudienceAndReplay(t *testing.T) {
	env, err := os.ReadFile("docs/contracts/examples/policy-bundle-v1.envelope.example.json")
	if err != nil {
		t.Fatal(err)
	}
	keys := policybundle.KeySet{Keys: []policybundle.Key{{KTY: "OKP", CRV: "Ed25519", X: "W5NclXraIJdyUtLqIHtaY7XfnhskAmqiub36Tgt_ye8", KID: "kei-pb-000000-01", Use: "sig", Alg: "EdDSA", Status: "active"}}}
	now := time.Date(2026, 9, 28, 17, 0, 0, 0, time.UTC)
	base := func(raw []byte, k policybundle.KeySet, installation string, high int64) error {
		_, e := policybundle.Verify(raw, k, installation, "org-fixture-0001", "ws-fixture-0001", high, now, false)
		return e
	}
	if err := base(env, keys, "other-installation", 41); err == nil {
		t.Fatal("accepted mismatched audience")
	}
	if err := base(env, keys, "inst-fixture-0001", 42); err == nil {
		t.Fatal("accepted equal bundle version")
	}
	keys.RevokedKeyIDs = []string{"kei-pb-000000-01"}
	if err := base(env, keys, "inst-fixture-0001", 41); err == nil {
		t.Fatal("accepted revoked key")
	}
	keys.RevokedKeyIDs = nil
	var envelope policybundle.Envelope
	if err := json.Unmarshal(env, &envelope); err != nil {
		t.Fatal(err)
	}
	payload, err := decodePayload(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload[len(payload)-2] ^= 1
	envelope.Payload = encodePayload(payload)
	tampered, _ := json.Marshal(envelope)
	if err := base(tampered, keys, "inst-fixture-0001", 41); err == nil {
		t.Fatal("accepted payload changed without re-signing")
	}
}

func TestVendoredFixtureHashesAndCanonicalAuthorizeParity(t *testing.T) {
	for path, want := range map[string]string{
		"docs/contracts/policy-bundle-v1.schema.json": "405320d0f605784ba26de3daf1b8bb6411772096b952beeea6e503f48a847b29",
		"docs/contracts/policy-set-v1.schema.json":    "0b69f38f0df1e9d873eba6bede8d0f69671c5fdc3fb2c5df95f37136bb875fd1",
	} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != want {
			t.Fatalf("canonical schema %s changed: %s", path, got)
		}
	}
	policyBytes, err := os.ReadFile("fixtures/kei/policy.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	casesBytes, err := os.ReadFile("fixtures/kei/authorize-cases.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(policyBytes)); got != "ee9d529451ba2a297327bcee55ee8af5a0adbbc198a890c9730dd507675846fb" {
		t.Fatalf("vendored policy fixture SHA-256 = %s", got)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(casesBytes)); got != "35b26c31aabd21f9eee72519908a3f1984b71652ca144f00801dca41b9236da6" {
		t.Fatalf("vendored authorize cases SHA-256 = %s", got)
	}
	var fixture struct {
		PolicySet json.RawMessage `json:"policy_set"`
		Seed      struct {
			Bindings json.RawMessage `json:"agent_connector_bindings"`
		} `json:"seed"`
		Subjects struct {
			Users map[string]struct {
				ID     string   `json:"id"`
				Groups []string `json:"effective_groups"`
				Linked bool     `json:"linked"`
			} `json:"users"`
		} `json:"subjects"`
	}
	if err := json.Unmarshal(policyBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	var cases struct {
		CallDefaults struct {
			AgentID           string `json:"agent_id"`
			ConnectorResource string `json:"connector_resource"`
		} `json:"call_defaults"`
		Cases []struct {
			ID    string `json:"id"`
			Path  string `json:"path"`
			Input struct {
				User        string `json:"user"`
				Tool        string `json:"tool"`
				Action      string `json:"action"`
				Resource    string `json:"resource"`
				ConnectorID string `json:"connector_id"`
				Capability  string `json:"capability"`
			} `json:"input"`
			Expected struct {
				Outcome  string  `json:"outcome"`
				PolicyID *string `json:"policy_id"`
			} `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(casesBytes, &cases); err != nil {
		t.Fatal(err)
	}
	verified := policybundle.Verified{Payload: policybundle.Payload{PolicySet: fixture.PolicySet, AgentConnectorBindings: fixture.Seed.Bindings}}
	for _, tc := range cases.Cases {
		user, exists := fixture.Subjects.Users[tc.Input.User]
		var subject *policybundle.Subject
		if exists {
			status := "linked_approved"
			if !user.Linked {
				status = "unlinked"
			}
			subject = &policybundle.Subject{UserID: user.ID, Status: status, EffectiveGroups: user.Groups}
		}
		call := policybundle.Call{Tool: tc.Input.Tool, Action: tc.Input.Action, Resource: tc.Input.Resource, AgentID: cases.CallDefaults.AgentID, UserID: user.ID, ConnectorID: tc.Input.ConnectorID, Capability: tc.Input.Capability}
		var got policybundle.Decision
		if tc.Path == "connector_invoke" {
			call.Resource = cases.CallDefaults.ConnectorResource
			got = verified.EvaluateConnector(call, subject)
		} else {
			got = verified.Evaluate(call, subject)
		}
		wantOutcome := tc.Expected.Outcome
		if wantOutcome == "enrollment_required" {
			wantOutcome = "deny"
		}
		// ADR-027 makes approvals workspace grants, not per-call gates.
		if wantOutcome == "approval_required" {
			wantOutcome = "allow"
		}
		if got.Outcome != wantOutcome {
			t.Errorf("%s outcome=%s want=%s reason=%s", tc.ID, got.Outcome, wantOutcome, got.ReasonCode)
		}
		if tc.Expected.PolicyID != nil && got.PolicyID != *tc.Expected.PolicyID {
			t.Errorf("%s policy=%s want=%s", tc.ID, got.PolicyID, *tc.Expected.PolicyID)
		}
	}
}

func TestPolicyBundleToolActionsAreExactRegisteredSelectors(t *testing.T) {
	bundle := policybundle.Verified{Payload: policybundle.Payload{PolicySet: json.RawMessage(`{
		"groups":[],"agents":[{"id":"agent-1","is_default":true}],
		"tools":[{"name":"web_search","service":"","action":"tool:web_search"},{"name":"search_wiki","service":"","action":"tool:search_wiki"}],
		"policies":[
			{"id":"web","src_pattern":"group:members","dst_pattern":"tool:web_search","action":"permit","scope":{"agent_id":null}},
			{"id":"wiki","src_pattern":"group:members","dst_pattern":"tool:search_wiki","action":"permit","scope":{"agent_id":null}}
		]}`), AgentConnectorBindings: json.RawMessage(`[]`)}}
	subject := &policybundle.Subject{Status: "linked_approved", EffectiveGroups: []string{"members"}}
	for _, tc := range []struct{ tool, action, policy string }{{"web_search", "tool:web_search", "web"}, {"search_wiki", "tool:search_wiki", "wiki"}} {
		got := bundle.Evaluate(policybundle.Call{Tool: tc.tool, Action: tc.action, UserID: "user-1"}, subject)
		if got.Outcome != "allow" || got.PolicyID != tc.policy {
			t.Errorf("%s decision = %+v", tc.tool, got)
		}
	}
	got := bundle.Evaluate(policybundle.Call{Tool: "web_search", Action: "web:search", UserID: "user-1"}, subject)
	if got.Outcome != "deny" || got.ReasonCode != "tool_action_mismatch" {
		t.Fatalf("caller-selected alternate action not rejected: %+v", got)
	}
}

func TestPolicyBundlePreservesCatalogArrayOrderForDenyPermitTies(t *testing.T) {
	bundle := policybundle.Verified{Payload: policybundle.Payload{PolicySet: json.RawMessage(`{"groups":[],"agents":[],"tools":[{"name":"web_search","service":"","action":"tool:web_search"}],"policies":[{"id":"deny-first","src_pattern":"group:members","dst_pattern":"tool:web_search","action":"deny","priority":50,"enabled":true,"approval_required":false,"scope":{"org_id":null,"workspace_id":null,"agent_id":null}},{"id":"permit-second","src_pattern":"group:members","dst_pattern":"tool:web_search","action":"permit","priority":50,"enabled":true,"approval_required":false,"scope":{"org_id":null,"workspace_id":null,"agent_id":null}}]}`), AgentConnectorBindings: json.RawMessage(`[]`)}}
	decision := bundle.Evaluate(policybundle.Call{Tool: "web_search", Action: "tool:web_search", UserID: "u"}, &policybundle.Subject{Status: "linked_approved", EffectiveGroups: []string{"members"}})
	if decision.Outcome != "deny" || decision.PolicyID != "deny-first" {
		t.Fatalf("first matching catalog-ordered deny did not win: %+v", decision)
	}
}

func TestPolicyBundleFailsClosedWhenSubjectResolutionMissing(t *testing.T) {
	bundle := policybundle.Verified{Payload: policybundle.Payload{PolicySet: json.RawMessage(`{"groups":[],"agents":[],"tools":[{"name":"web_search","service":"","action":"tool:web_search"}],"policies":[{"id":"p","src_pattern":"group:members","dst_pattern":"tool:web_search","action":"permit","scope":{"agent_id":null}},{"id":"fallback","src_pattern":"*","dst_pattern":"tool:web_search","action":"permit","scope":{"agent_id":null}}]}`), AgentConnectorBindings: json.RawMessage(`[]`)}}
	got := bundle.Evaluate(policybundle.Call{Tool: "web_search", Action: "tool:web_search", UserID: "user-1"}, nil)
	if got.Outcome != "deny" || got.ReasonCode != "subject_resolution_unavailable" {
		t.Fatalf("missing subject did not fail closed: %+v", got)
	}
}
