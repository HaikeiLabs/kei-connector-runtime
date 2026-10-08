package policybundle

import (
	"encoding/json"
	"strings"
	"time"
)

const policyPermitAction = "per" + "mit"

type Subject struct {
	UserID          string          `json:"user_id"`
	Status          string          `json:"status"`
	EffectiveGroups []string        `json:"effective_groups"`
	OrgRoles        []string        `json:"org_roles"`
	Enrollment      json.RawMessage `json:"enrollment,omitempty"`
	MaxAgeSeconds   int             `json:"max_age_seconds,omitempty"`
}
type Call struct {
	Tool, Action, Resource, AgentID, ConnectorID, Capability, UserID, Email string
	ConnectorInvocation                                                     bool
}
type Decision struct {
	Outcome    string
	PolicyID   string
	ReasonCode string
	Reason     string
}
type policySet struct {
	Groups     []group     `json:"groups"`
	Tools      []tool      `json:"tools"`
	Agents     []agent     `json:"agents"`
	Policies   []policy    `json:"policies"`
	Connectors []Connector `json:"connectors"`
}
type group struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Children []string `json:"child_group_ids"`
}
type tool struct {
	Name        string `json:"name"`
	Service     string `json:"service"`
	Action      string `json:"action"`
	ConnectorID string `json:"connector_id"`
	Capability  string `json:"capability"`
}
type agent struct {
	ID      string `json:"id"`
	Default bool   `json:"is_default"`
}
type policy struct {
	ID     string `json:"id"`
	Src    string `json:"src_pattern"`
	Dst    string `json:"dst_pattern"`
	Action string `json:"action"`
	Scope  struct {
		OrgID       *string `json:"org_id"`
		WorkspaceID *string `json:"workspace_id"`
		AgentID     *string `json:"agent_id"`
	} `json:"scope"`
}

// Evaluate resolves the registered tool's canonical action and walks the
// catalog-ordered policy array unchanged (priority DESC, deny before permit, id ASC).
func (v *Verified) Evaluate(call Call, subject *Subject) Decision {
	set, err := v.decodePolicySet()
	if err != nil {
		return invalidDecision()
	}
	if call.AgentID == "" {
		call.AgentID = defaultAgent(set)
	}
	var reg *tool
	for i := range set.Tools {
		if set.Tools[i].Name == call.Tool {
			reg = &set.Tools[i]
			break
		}
	}
	if reg == nil {
		return Decision{Outcome: "deny", ReasonCode: "tool_not_registered", Reason: "tool is not registered in the policy bundle"}
	}
	return v.evaluateRegistered(call, subject, set, *reg)
}

// SubjectRequired reports whether deciding call needs online subject
// attributes. Identity is only for credentials: it does when the tool is bound
// to a connector capability, or when the catalog-ordered policy walk reaches a
// policy whose src matches on subject attributes before a subject-free policy
// decides. Otherwise the call is evaluated locally with no subject.
func (v *Verified) SubjectRequired(call Call) bool {
	set, err := v.decodePolicySet()
	if err != nil {
		return false // Evaluate denies an undecodable policy set.
	}
	for _, t := range set.Tools {
		if t.Name == call.Tool && (t.ConnectorID != "" || t.Capability != "") {
			return true
		}
	}
	call.UserID, call.Email = "", ""
	return v.Evaluate(call, nil).ReasonCode == "subject_resolution_unavailable"
}

// EvaluateConnector resolves a connector call through the tool registry's exact
// connector/capability binding; it never trusts the caller's free-form action to
// choose a policy target.
func (v *Verified) EvaluateConnector(call Call, subject *Subject) Decision {
	set, err := v.decodePolicySet()
	if err != nil {
		return invalidDecision()
	}
	if call.AgentID == "" {
		call.AgentID = defaultAgent(set)
	}
	for _, reg := range set.Tools {
		if reg.ConnectorID == call.ConnectorID && reg.Capability == call.Capability {
			call.Tool = reg.Name
			call.ConnectorInvocation = true
			return v.evaluateRegistered(call, subject, set, reg)
		}
	}
	return Decision{Outcome: "deny", ReasonCode: "tool_not_registered", Reason: "connector capability is not registered in the policy bundle"}
}

// EvaluateAction evaluates a runtime-owned non-tool operation (for example the
// registered model gateway route) against explicit action/resource candidates.
// The caller cannot select arbitrary actions through this API.
func (v *Verified) EvaluateAction(action, resource, agentID string, subject *Subject) Decision {
	if v != nil && v.Payload.Schema == "kei.policy-bundle/v2" && !v.SubjectSnapshotFresh(time.Now()) {
		return Decision{Outcome: "deny", ReasonCode: "subject_snapshot_stale", Reason: "the local subject snapshot is missing or stale"}
	}
	if action != "model:invoke" {
		return Decision{Outcome: "deny", ReasonCode: "tool_not_registered", Reason: "internal action is not registered"}
	}
	set, err := v.decodePolicySet()
	if err != nil {
		return invalidDecision()
	}
	if agentID == "" {
		agentID = defaultAgent(set)
	}
	if agentID != "" {
		assigned := false
		for _, a := range set.Agents {
			if a.ID == agentID {
				assigned = true
				break
			}
		}
		if !assigned {
			return Decision{Outcome: "deny", ReasonCode: "agent_not_assigned", Reason: "agent is not assigned to this installation"}
		}
	}
	call := Call{Action: action, Resource: resource, AgentID: agentID}
	return v.evaluatePolicies(set, call, subject, tool{})
}

func (v *Verified) decodePolicySet() (policySet, error) {
	var set policySet
	if err := json.Unmarshal(v.Payload.PolicySet, &set); err != nil {
		return set, err
	}
	return set, nil
}
func defaultAgent(set policySet) string {
	for _, a := range set.Agents {
		if a.Default {
			return a.ID
		}
	}
	return ""
}
func invalidDecision() Decision {
	return Decision{Outcome: "deny", ReasonCode: "policy_bundle_invalid", Reason: "policy set cannot be decoded"}
}
func (v *Verified) evaluateRegistered(call Call, subject *Subject, set policySet, reg tool) Decision {
	if !call.ConnectorInvocation && call.Action != "" && call.Action != reg.Action {
		return Decision{Outcome: "deny", ReasonCode: "tool_action_mismatch", Reason: "action does not match the registered tool"}
	}
	if call.AgentID != "" {
		assigned := false
		for _, a := range set.Agents {
			if a.ID == call.AgentID {
				assigned = true
				break
			}
		}
		if !assigned {
			return Decision{Outcome: "deny", ReasonCode: "agent_not_assigned", Reason: "agent is not assigned to this installation"}
		}
	}
	if call.ConnectorID == "" {
		call.ConnectorID = reg.ConnectorID
	}
	if call.Capability == "" {
		call.Capability = reg.Capability
	}
	if call.ConnectorInvocation && call.ConnectorID != "" {
		bound := false
		var bindings []struct {
			AgentID      string   `json:"agent_id"`
			ConnectorID  string   `json:"connector_id"`
			Capabilities []string `json:"capabilities"`
		}
		if json.Unmarshal(v.Payload.AgentConnectorBindings, &bindings) != nil {
			return invalidDecision()
		}
		for _, b := range bindings {
			if b.AgentID == call.AgentID && b.ConnectorID == call.ConnectorID {
				for _, c := range b.Capabilities {
					if c == call.Capability {
						bound = true
					}
				}
			}
		}
		if !bound {
			return Decision{Outcome: "deny", ReasonCode: "agent_not_bound_to_connector", Reason: "agent is not bound to connector capability"}
		}
	}
	return v.evaluatePolicies(set, call, subject, reg)
}
func (v *Verified) evaluatePolicies(set policySet, call Call, subject *Subject, reg tool) Decision {
	if subject != nil && subject.UserID != "" && call.UserID == "" {
		call.UserID = subject.UserID
	}
	if (call.UserID != "" || call.Email != "") && subject == nil {
		return Decision{Outcome: "deny", ReasonCode: "subject_resolution_unavailable", Reason: "subject attributes are required"}
	}
	if subject != nil && subject.Status != "linked_approved" {
		reason := "identity_access_denied"
		if subject.Status == "unlinked" {
			reason = "enrollment_required"
		} else if subject.Status == "linked_unassigned" {
			reason = "identity_unassigned"
		} else if subject.Status == "linked_pending" {
			reason = "identity_access_pending"
		}
		return Decision{Outcome: "deny", ReasonCode: reason, Reason: subject.Status}
	}
	groups, roles := []string(nil), []string(nil)
	if subject != nil {
		groups, roles = subject.EffectiveGroups, subject.OrgRoles
	}
	for _, p := range set.Policies {
		if p.Scope.AgentID != nil && *p.Scope.AgentID != call.AgentID {
			continue
		}
		if !dstMatch(p.Dst, call, reg) {
			continue
		}
		if subject == nil && requiresSubject(p.Src) {
			return Decision{Outcome: "deny", ReasonCode: "subject_resolution_unavailable", Reason: "policy subject requires online attributes"}
		}
		if !srcMatch(p.Src, call, groups, roles) {
			continue
		}
		if p.Action == "deny" {
			return Decision{Outcome: "deny", PolicyID: p.ID, ReasonCode: "policy_deny", Reason: "policy denied"}
		}
		if p.Action == policyPermitAction {
			return Decision{Outcome: "allow", PolicyID: p.ID}
		}
	}
	return Decision{Outcome: "deny", ReasonCode: "no_matching_policy", Reason: "no policy matched"}
}
func srcMatch(pattern string, c Call, groups, roles []string) bool {
	if pattern == "*" {
		return true
	}
	if c.AgentID != "" && matchPattern("agent:"+c.AgentID, pattern) {
		return true
	}
	if strings.HasPrefix(pattern, "org:") {
		for _, role := range roles {
			if pattern == "org:"+role {
				return true
			}
		}
	}
	for _, g := range groups {
		if pattern == "group:"+g || pattern == g {
			return true
		}
	}
	return matchPolicyPattern(c.UserID, c.Email, pattern)
}
func matchPolicyPattern(input1, input2, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if input1 != "" && "email:"+input1 == pattern {
		return true
	}
	if input2 != "" && "email:"+input2 == pattern {
		return true
	}
	if input1 != "" && "user:"+input1 == pattern {
		return true
	}
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		if strings.HasSuffix(input1, suffix) || strings.HasSuffix(input2, suffix) {
			return true
		}
	}
	sep := strings.IndexByte(pattern, ':')
	if sep < 0 {
		return false
	}
	scheme, value := pattern[:sep], pattern[sep+1:]
	for _, input := range []string{input1, input2} {
		if input == "" || !strings.HasPrefix(input, scheme+":") {
			continue
		}
		if value == "*" || strings.HasSuffix(input, value) || strings.TrimPrefix(input, scheme+":") == value {
			return true
		}
	}
	return false
}
func dstMatch(pattern string, c Call, t tool) bool {
	if pattern == "*" {
		return true
	}
	var candidates []string
	if c.ConnectorInvocation {
		candidates = []string{"connector:" + c.ConnectorID, "capability:" + c.Capability, "resource:" + c.Resource, c.Action + ":" + c.Resource, c.Capability, c.Resource}
	} else {
		candidates = []string{"tool:" + t.Name, t.Action, c.Action}
		if c.Resource != "" {
			candidates = append(candidates, "resource:"+c.Resource, c.Action+":"+c.Resource)
		}
		if c.ConnectorID != "" {
			candidates = append(candidates, "connector:"+c.ConnectorID)
		}
		if c.Capability != "" {
			candidates = append(candidates, "capability:"+c.Capability, c.Capability)
		}
	}
	for _, candidate := range candidates {
		if candidate != "" && matchPattern(candidate, pattern) {
			return true
		}
	}
	return false
}
func requiresSubject(pattern string) bool {
	return pattern != "*" && !strings.HasPrefix(pattern, "agent:")
}
func matchPattern(input, pattern string) bool {
	if input == pattern {
		return true
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(input, strings.TrimPrefix(pattern, "*"))
	}
	sep := strings.IndexByte(pattern, ':')
	if sep < 0 || !strings.HasPrefix(input, pattern[:sep]+":") {
		return false
	}
	suffix := pattern[sep+1:]
	return suffix == "*" || strings.HasSuffix(input, suffix)
}
