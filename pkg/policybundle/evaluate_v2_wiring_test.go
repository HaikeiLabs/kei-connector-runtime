package policybundle

import (
	"encoding/json"
	"testing"
	"time"
)

// A binding is wiring, not authorization (HAI-623): the plan is decided by
// the bundle's rules and grants whether or not agent_connector_bindings has
// an entry that covers the tool's required capabilities.
func TestEvaluateV2PlanIgnoresAgentConnectorBindings(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	subject := &SessionSubject{UserID: "user-alice", Source: "discord", ExternalID: "ext-alice", Status: SubjectLinked}
	ops := v2TestPlanOps()
	bindings := map[string]json.RawMessage{
		"no binding":                 json.RawMessage(`[]`),
		"binding omits a capability": json.RawMessage(`[{"agent_id":"agent-a","connector_id":"conn-a","capabilities":["pull_request.read"]}]`),
		"binding for another agent":  json.RawMessage(`[{"agent_id":"agent-b","connector_id":"conn-a","capabilities":["pull_request.read","check.read"]}]`),
	}
	for name, raw := range bindings {
		t.Run(name+" still allows when rules permit", func(t *testing.T) {
			v := v2ToolBundle(t, now, []any{v2Permit("p1", "pull_request.read"), v2Permit("p2", "check.read")})
			v.Payload.AgentConnectorBindings = raw
			if d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, ops, now); d.Outcome != "allow" {
				t.Fatalf("decision = %+v, want allow", d)
			}
		})
		t.Run(name+" is a policy deny when no rule matches", func(t *testing.T) {
			v := v2ToolBundle(t, now, nil)
			v.Payload.AgentConnectorBindings = raw
			d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, ops, now)
			if d.Outcome != "deny" || d.ReasonCode == "agent_not_bound_to_connector" {
				t.Fatalf("decision = %+v, want a deny that is not agent_not_bound_to_connector", d)
			}
		})
	}
}
