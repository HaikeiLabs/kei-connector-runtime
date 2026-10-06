package connectorruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

func TestValidateUnsignedCanonicalBundleAndDigest(t *testing.T) {
	raw, err := os.ReadFile("docs/contracts/examples/policy-bundle-v1.payload.example.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 28, 17, 0, 0, 0, time.UTC)
	verified, err := policybundle.Validate(raw, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", 41, now)
	if err != nil {
		t.Fatalf("validate unsigned canonical bundle: %v", err)
	}
	want := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	if verified.Payload.BundleVersion != 42 || verified.Digest != want || string(verified.PayloadBytes) != string(raw) {
		t.Fatalf("unsigned bundle version=%d digest=%s want=%s", verified.Payload.BundleVersion, verified.Digest, want)
	}
	if strings.Contains(string(raw), `"signatures"`) {
		t.Fatal("canonical JSON payload unexpectedly requires or carries signatures")
	}
}

func TestValidateUnsignedBundleRejectsAudienceRollbackExpirySchemaAndDuplicateKeys(t *testing.T) {
	now := time.Date(2026, 9, 28, 17, 0, 0, 0, time.UTC)
	base := fixtureBundlePayloadForTest(t, now)
	validate := func(raw []byte, installation string, highest int64, at time.Time) error {
		_, err := policybundle.Validate(raw, installation, "org-fixture-0001", "ws-fixture-0001", highest, at)
		return err
	}
	if err := validate(base, "other-installation", 41, now); err == nil {
		t.Fatal("accepted mismatched audience")
	}
	if err := validate(base, "inst-fixture-0001", 42, now); err == nil {
		t.Fatal("accepted equal bundle version")
	}
	if err := validate(base, "inst-fixture-0001", 41, now.Add(12*time.Hour)); !errors.Is(err, policybundle.ErrBundleExpired) {
		t.Fatalf("expiry error=%v", err)
	}
	unknown := append(append([]byte(nil), base[:len(base)-2]...), []byte(`,"unexpected":true}`)...)
	if err := validate(unknown, "inst-fixture-0001", 41, now); err == nil {
		t.Fatal("accepted unknown schema field")
	}
	duplicate := bytes.Replace(base, []byte(`"bundle_version": 42`), []byte(`"bundle_version": 42, "bundle_version": 43`), 1)
	if err := validate(duplicate, "inst-fixture-0001", 41, now); err == nil {
		t.Fatal("accepted duplicate security field")
	}
}

func TestVendoredFixtureHashesAndCanonicalAuthorizeParity(t *testing.T) {
	for path, want := range map[string]string{
		"docs/contracts/policy-bundle-v1.schema.json": "8eb5a6bb6c98f26825111d5067829670857970fa22278310cd81a47ba132efd1",
		"docs/contracts/policy-set-v1.schema.json":    "03ae8ac640375319f826b8df5fad0770b8ffe582e94edb138070b303ac3d8a50",
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

func TestUnsignedBundleLocallyAllowsExactSearchSelectors(t *testing.T) {
	now := time.Now().UTC()
	raw := fixtureBundlePayloadForTest(t, now)
	bundle, err := policybundle.Validate(raw, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", 41, now)
	if err != nil {
		t.Fatal(err)
	}
	subject := &policybundle.Subject{UserID: "user-member-0001", Status: "linked_approved", EffectiveGroups: []string{"members"}}
	for _, tc := range []struct{ tool, action string }{{"web_search", "tool:web_search"}, {"search_wiki", "tool:search_wiki"}} {
		got := bundle.Evaluate(policybundle.Call{Tool: tc.tool, Action: tc.action, UserID: subject.UserID}, subject)
		if got.Outcome != "allow" {
			t.Errorf("unsigned bundle action %s -> %s decision=%+v", tc.tool, tc.action, got)
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
