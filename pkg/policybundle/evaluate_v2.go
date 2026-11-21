package policybundle

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	bundle "github.com/HaikeiLabs/kei-connector-contracts/bundle"
	pol "github.com/HaikeiLabs/kei-connector-contracts/policy"
)

// Operation is one exact planner-produced connector operation. Resource
// identity remains structured; no field is parsed from or flattened into another.
type Operation struct {
	ID                 string
	ConnectorID        string
	Capability         string
	Action             string
	Resource           string
	InputDigest        string
	ProviderInput      json.RawMessage
	ProviderResource   string
	CredentialResource string
	ResourceType       string
	ResourceID         string
	ResourceParent     string
	ResourceParentType string
	// BindingVersion is the connector binding version the caller pinned the
	// plan to, when it names one. Empty means the caller names no version.
	BindingVersion string
}

// V2ResourceType is an alias for the shared contracts type.
type V2ResourceType = bundle.V2ResourceType

// V2Tool is an alias for the shared contracts type.
type V2Tool = bundle.V2Tool

// V2HarnessTool reports whether name resolves to an explicitly registered
// harness_executor route in a verified v2 bundle. The lookup decodes the
// policy set with the runtime's own v2Tool type: the shared contracts type
// strict-decodes connector bindings into a struct without resource_template
// and version, so a bundle whose connector tools carry them would make every
// tool — harness ones included — read as not registered.
func (v *Verified) V2HarnessTool(name string, now time.Time) bool {
	if v == nil || v.Payload.Schema != "kei.policy-bundle/v2" || !v.SubjectSnapshotFresh(now) {
		return false
	}
	var set v2PolicySet
	if strictJSON(v.Payload.PolicySet, &set) != nil {
		return false
	}
	for _, tool := range set.Tools {
		if tool.Name == name {
			return tool.Route.HarnessExecutor != nil && tool.Route.ConnectorBinding == nil
		}
	}
	return false
}

// V2ConnectorTool resolves one trusted connector tool from the parsed v2 set.
// Like V2HarnessTool, the lookup runs on the runtime-local v2Tool type so a
// templated binding cannot make the tool unfindable (see that method).
func (v *Verified) V2ConnectorTool(name string, now time.Time) (V2Tool, bool) {
	if v == nil || v.Payload.Schema != "kei.policy-bundle/v2" || !v.SubjectSnapshotFresh(now) {
		return V2Tool{}, false
	}
	var set v2PolicySet
	if strictJSON(v.Payload.PolicySet, &set) != nil {
		return V2Tool{}, false
	}
	for _, tool := range set.Tools {
		if tool.Name == name && tool.Route.ConnectorBinding != nil && len(tool.Plan) > 0 && ValidateV2Plan(tool.V2Tool) == nil {
			// The alias's route binding type has only the connector id; the
			// template and version stay on the runtime-local route that
			// EvaluateV2Plan re-reads for its own decision.
			tool.V2Tool.Route.ConnectorBinding = &struct {
				ConnectorID string `json:"connector_id"`
			}{ConnectorID: tool.Route.ConnectorBinding.ConnectorID}
			return tool.V2Tool, true
		}
	}
	return V2Tool{}, false
}

type v2Check struct {
	PolicyID string `json:"policy_id"`
	Name     string `json:"name"`
	Effect   string `json:"effect"`
	Priority int    `json:"priority"`
	Scope    struct {
		OrgID       *string `json:"org_id"`
		WorkspaceID *string `json:"workspace_id"`
		AgentID     *string `json:"agent_id"`
	} `json:"scope"`
	Selector map[string]string `json:"selector"`
}

type v2PolicySet struct {
	Schema         string `json:"schema"`
	OrgID          string `json:"org_id"`
	WorkspaceID    string `json:"workspace_id"`
	MatchSemantics string `json:"match_semantics"`
	Evaluation     struct {
		Precedence []string `json:"precedence"`
		Checks     string   `json:"checks"`
		Default    string   `json:"default"`
	} `json:"evaluation"`
	Tools                 []v2Tool          `json:"tools"`
	Checks                []v2Check         `json:"checks"`
	ToolPolicies          []v2Check         `json:"tool_policies"`
	HarnessMatchSemantics string            `json:"harness_match_semantics"`
	HarnessPolicies       []v2HarnessPolicy `json:"harness_policies"`
	// Connectors is the optional descriptor section (HAI-378); see Connector.
	Connectors []Connector `json:"connectors,omitempty"`
}

// v2ToolBinding mirrors the bundle's connector_binding with the additive
// resource_template and version fields. Older bundles omit both; the
// corresponding enforcement is skipped while they are empty, so legacy
// bundles evaluate exactly as before.
type v2ToolBinding struct {
	ConnectorID      string `json:"connector_id"`
	ResourceTemplate string `json:"resource_template,omitempty"`
	Version          string `json:"version,omitempty"`
}

// v2ToolRoute mirrors the bundle's route with the extended binding.
type v2ToolRoute struct {
	ConnectorBinding *v2ToolBinding   `json:"connector_binding,omitempty"`
	HarnessExecutor  *json.RawMessage `json:"harness_executor,omitempty"`
}

// v2Tool mirrors bundle.V2Tool on the wire with the extended route. The
// embedded alias keeps plan validation and resource-type matching on the
// shared contracts type.
type v2Tool struct {
	bundle.V2Tool
	Route v2ToolRoute `json:"route"`
}

// denyOverrides reports whether the policy set declares the deny_overrides
// evaluation id in its precedence (ADR-038 D-1). Bundles without it keep the
// legacy priority order.
func (s v2PolicySet) denyOverrides() bool {
	for _, id := range s.Evaluation.Precedence {
		if id == "deny_overrides" {
			return true
		}
	}
	return false
}

// v2HarnessPolicy is one ADR-029 harness policy row as the catalog emits it
// under policy_set.harness_policies (kei.harness-match/v1).
type v2HarnessPolicy struct {
	PolicyID string `json:"policy_id"`
	Name     string `json:"name"`
	Src      string `json:"src_pattern"`
	Dst      string `json:"dst_pattern"`
	Action   string `json:"action"`
	Priority int    `json:"priority"`
	Scope    struct {
		OrgID       *string `json:"org_id"`
		WorkspaceID *string `json:"workspace_id"`
		AgentID     *string `json:"agent_id"`
	} `json:"scope"`
	// When narrows the policy to calls made through one harness kind
	// (ADR-038 D-6). Absent means it applies to every kind.
	When *struct {
		Harness string `json:"harness"`
	} `json:"when,omitempty"`
}

// whenHolds reports whether the policy applies to a call made through kind. A
// condition naming a harness never holds for another or an unknown kind.
func (p v2HarnessPolicy) whenHolds(kind string) bool {
	return p.When == nil || p.When.Harness == kind
}

// v2SubjectDenial is the v2 session-subject gate shared by every local v2
// decision: a fresh identity snapshot must corroborate a linked session
// subject. It reports the denial, or false when the subject passes.
func (v *Verified) v2SubjectDenial(subject *SessionSubject, now time.Time) (Decision, bool) {
	if v == nil || v.Payload.Schema != "kei.policy-bundle/v2" || !v.SubjectSnapshotFresh(now) {
		return Decision{Outcome: "deny", ReasonCode: "subject_snapshot_stale", Reason: "the local subject snapshot is missing or stale"}, true
	}
	if subject == nil {
		return Decision{Outcome: "deny", ReasonCode: "subject_unlinked", Reason: "no session subject"}, true
	}
	if decision, denied := subjectGate(subject); denied {
		return decision, true
	}
	var identity Identity
	var known bool
	if subject.Source == "installation_owner" {
		if v.Payload.Subject != nil && v.Payload.Subject.UserID == subject.UserID {
			identity, known = Identity{UserID: subject.UserID, Status: SubjectLinked}, true
		}
	} else if subject.Source == "cli" && subject.ExternalID == "" {
		identity, known = v.LookupLinkedUser(subject.UserID, now)
	} else {
		identity, known = v.LookupIdentity(subject.Source, subject.ExternalID, now)
	}
	if !known || identity.UserID != subject.UserID {
		return Decision{Outcome: "deny", ReasonCode: "subject_unlinked", Reason: "the session identity is not present in the fresh bundle snapshot"}, true
	}
	if identity.Status != SubjectLinked {
		return Decision{Outcome: "deny", ReasonCode: statusReasonCode(identity.Status), Reason: "the bundle snapshot does not grant the session identity"}, true
	}
	return Decision{}, false
}

// EvaluateV2HarnessTool decides one harness-executed tool against the v2
// tool_policies set. The harness executes the tool; this method only returns
// the local policy decision. A fresh bundle identity must corroborate the
// named session subject before any tool policy can permit it.
func (v *Verified) EvaluateV2HarnessTool(toolName, agentID string, subject *SessionSubject, now time.Time) Decision {
	return v.EvaluateV2HarnessToolForTarget(toolName, agentID, "", "", "", subject, now)
}

// EvaluateV2HarnessToolForTarget evaluates a harness tool while binding any
// connector release context to this same policy decision. Target dimensions
// are available to selectors, so a policy may narrow the tool to a connector,
// capability, or resource; omitted selector dimensions remain governed by the
// tool's ordinary authorization policy.
func (v *Verified) EvaluateV2HarnessToolForTarget(toolName, agentID, connectorID, capability, resource string, subject *SessionSubject, now time.Time) Decision {
	decision, _ := v.evaluateV2HarnessToolForTarget(toolName, agentID, connectorID, capability, resource, subject, now)
	return decision
}

// ReasonConnectorNotNamed is the deny reason for a credential release whose
// call a permit allowed without naming the requested connector (HAI-1070).
const ReasonConnectorNotNamed = "connector_not_named"

// EvaluateV2HarnessToolRelease decides a connector credential release for a
// harness tool. It is EvaluateV2HarnessToolForTarget plus one rule: the
// credential is released only when the permit that allowed the call has a
// selector whose connector_id is exactly connectorID. A tool-only permit, or an
// access grant (whose target names only the tool), still permits the tool call
// through EvaluateV2HarnessTool but never releases a credential. The check is
// local to the verified bundle.
func (v *Verified) EvaluateV2HarnessToolRelease(toolName, agentID, connectorID, capability, resource string, subject *SessionSubject, now time.Time) Decision {
	decision, winner := v.evaluateV2HarnessToolForTarget(toolName, agentID, connectorID, capability, resource, subject, now)
	if decision.Outcome != "allow" {
		return decision
	}
	if connectorID == "" || winner == nil || winner.Selector["connector_id"] != connectorID {
		return Decision{Outcome: "deny", PolicyID: decision.PolicyID, ReasonCode: ReasonConnectorNotNamed, Reason: "the permit that allowed the call does not name this connector"}
	}
	return decision
}

// evaluateV2HarnessToolForTarget returns the decision and, when a tool policy
// decided it, that winning check. An access-grant decision has no check.
func (v *Verified) evaluateV2HarnessToolForTarget(toolName, agentID, connectorID, capability, resource string, subject *SessionSubject, now time.Time) (Decision, *v2Check) {
	if decision, denied := v.v2SubjectDenial(subject, now); denied {
		return decision, nil
	}
	var set v2PolicySet
	if err := strictJSON(v.Payload.PolicySet, &set); err != nil {
		return invalidDecision(), nil
	}
	var registered *v2Tool
	for i := range set.Tools {
		if set.Tools[i].Name == toolName {
			registered = &set.Tools[i]
			break
		}
	}
	if registered == nil || registered.Route.HarnessExecutor == nil || registered.Route.ConnectorBinding != nil {
		return Decision{Outcome: "deny", ReasonCode: "tool_not_registered", Reason: "harness tool is not registered in the policy bundle"}, nil
	}
	request := map[string]string{"tool": registered.Name, "source": registered.Source}
	if connectorID != "" {
		request["connector_id"] = connectorID
	}
	if capability != "" {
		request["capability"] = capability
	}
	if resource != "" {
		request["resource_id"] = resource
	}
	groups, roles := membershipValues(v.Payload.Identities, subject.UserID, now)
	decision, winner := evaluateV2CheckWinner(set.denyOverrides(), set.ToolPolicies, request, subject, groups, roles, agentID, v.Payload.Audience.OrgID, v.Payload.Audience.WorkspaceID, false)
	if winner != nil {
		return decision, winner
	}
	// No rule matched. A live access grant may still open the call
	// (ADR-038 §2); it decides without a check.
	return v.v2GrantOrRule(decision, v2ToolTarget(registered.Name), subject, groups, now), nil
}

// V2ToolRegistered reports whether a v2 policy set has a catalog registration
// for the named tool, regardless of its execution route.
func (v *Verified) V2ToolRegistered(toolName string) bool {
	if v == nil || v.Payload.Schema != "kei.policy-bundle/v2" {
		return false
	}
	var set v2PolicySet
	if strictJSON(v.Payload.PolicySet, &set) != nil {
		return false
	}
	for _, tool := range set.Tools {
		if tool.Name == toolName {
			return true
		}
	}
	return false
}

// EvaluateV2UnregisteredTool evaluates an unregistered tool name against the
// v2 tool policies for the verified installation-owner session.
func (v *Verified) EvaluateV2UnregisteredTool(toolName, agentID string, subject *SessionSubject, now time.Time) Decision {
	if decision, denied := v.v2SubjectDenial(subject, now); denied {
		return decision
	}
	if subject.Source != "installation_owner" {
		return Decision{Outcome: "deny", ReasonCode: "owner_session_required", Reason: "unregistered tool policy evaluation requires the verified installation owner session"}
	}
	if toolName == "" || v.V2ToolRegistered(toolName) {
		return Decision{Outcome: "deny", ReasonCode: "tool_not_registered", Reason: "tool is empty or already registered in the policy bundle"}
	}
	if agentID == "" {
		return Decision{Outcome: "deny", ReasonCode: "agent_not_assigned", Reason: "agent is not assigned to this installation"}
	}
	var set v2PolicySet
	if err := strictJSON(v.Payload.PolicySet, &set); err != nil {
		return invalidDecision()
	}
	groups, roles := membershipValues(v.Payload.Identities, subject.UserID, now)
	if subject.Source == "installation_owner" && v.Payload.Subject != nil && v.Payload.Subject.UserID == subject.UserID {
		groups = v.Payload.Subject.Groups
	}
	decision := evaluateV2Check(set.denyOverrides(), set.ToolPolicies, map[string]string{"tool": toolName}, subject, groups, roles, agentID, v.Payload.Audience.OrgID, v.Payload.Audience.WorkspaceID, false)
	return v.v2GrantOrRule(decision, v2ToolTarget(toolName), subject, groups, now)
}

// EvaluateV2Plan locally AND-authorizes a complete exact operation plan for a
// registered connector tool. The runtime derives operations from its validated
// cached bundle plan; caller capability declarations are never authority.
func (v *Verified) EvaluateV2Plan(toolName, agentID string, subject *SessionSubject, ops []Operation, now time.Time) Decision {
	if decision, denied := v.v2SubjectDenial(subject, now); denied {
		return decision
	}
	var set v2PolicySet
	if err := strictJSON(v.Payload.PolicySet, &set); err != nil {
		return invalidDecision()
	}
	var tool *v2Tool
	for i := range set.Tools {
		if set.Tools[i].Name == toolName {
			tool = &set.Tools[i]
			break
		}
	}
	if tool == nil || tool.Route.ConnectorBinding == nil || tool.Route.ConnectorBinding.ConnectorID == "" || ValidateV2Plan(tool.V2Tool) != nil {
		return Decision{Outcome: "deny", ReasonCode: "tool_not_registered", Reason: "connector tool is not registered in the policy bundle"}
	}
	if agentID == "" {
		return Decision{Outcome: "deny", ReasonCode: "agent_not_assigned", Reason: "agent is not assigned to this installation"}
	}
	connectorID := tool.Route.ConnectorBinding.ConnectorID
	if !set.connectorDeclares(connectorID, tool.RequiredCapabilities) {
		return Decision{Outcome: "deny", ReasonCode: "tool_not_registered", Reason: "the bound connector does not declare the tool's capabilities in the policy bundle"}
	}
	if len(ops) == 0 || len(tool.RequiredCapabilities) == 0 {
		return Decision{Outcome: "deny", ReasonCode: "operation_plan_invalid", Reason: "the operation plan is empty"}
	}
	covered := make(map[string]bool, len(tool.RequiredCapabilities))
	groups, roles := membershipValues(v.Payload.Identities, subject.UserID, now)
	for _, op := range ops {
		if op.ConnectorID != connectorID || op.Capability == "" || op.Action == "" {
			return Decision{Outcome: "deny", ReasonCode: "operation_plan_invalid", Reason: "the operation plan contains a malformed operation"}
		}
		if !containsExact(tool.RequiredCapabilities, op.Capability) || !v.operationResourceRegistered(&tool.V2Tool, op) {
			return Decision{Outcome: "deny", ReasonCode: "operation_plan_invalid", Reason: "the operation does not match the tool registration"}
		}
		if binding := tool.Route.ConnectorBinding; binding != nil {
			if binding.ResourceTemplate != "" && op.ProviderResource != "" && !MatchRenderedResource(binding.ResourceTemplate, op.ProviderResource) {
				return Decision{Outcome: "deny", ReasonCode: "resource_out_of_template", Reason: "the operation's rendered resource does not match the binding's resource template"}
			}
			if op.BindingVersion != "" && op.BindingVersion != binding.Version {
				return Decision{Outcome: "deny", ReasonCode: "binding_stale", Reason: "the requested connector binding version is not in the policy bundle"}
			}
		}
		covered[op.Capability] = true
		request := map[string]string{"source": tool.Source, "connector_id": connectorID, "tool": tool.Name, "capability": op.Capability, "operation_class": tool.OperationClass}
		if op.ResourceType != "" {
			request["resource_type"] = op.ResourceType
		}
		if op.ResourceID != "" {
			request["resource_id"] = op.ResourceID
		}
		if op.ResourceParent != "" {
			request["resource_parent"] = op.ResourceParent
		}
		decision := evaluateV2Check(set.denyOverrides(), set.Checks, request, subject, groups, roles, agentID, v.Payload.Audience.OrgID, v.Payload.Audience.WorkspaceID, true)
		// A rule that matched decided the operation. Where no rule matched, a
		// live access grant may still open the operation: by the tool target
		// first, then by the operation's capability target (M1/O1 — a grant
		// on capability:<operation id> covers every tool bound to that
		// operation on that connector; a family wildcard opens reads only).
		decision = v.v2GrantOrRule(decision, v2ToolTarget(tool.Name), subject, groups, now)
		if decision.Outcome != "allow" && (decision.ReasonCode == "no_matching_policy" || decision.ReasonCode == ReasonNoGrantMatched) {
			if grant, ok := v.v2CapabilityGrantDecision(op.Capability, tool.OperationClass, subject, groups, now); ok {
				decision = grant
			}
		}
		if decision.Outcome != "allow" {
			return decision
		}
	}
	for _, required := range tool.RequiredCapabilities {
		if !covered[required] {
			return Decision{Outcome: "deny", ReasonCode: "operation_plan_invalid", Reason: "the operation plan omits a required capability"}
		}
	}
	return Decision{Outcome: "allow", ReasonCode: "policy_permit"}
}

// connectorDeclares reports whether the policy set registers every capability
// for connectorID (HAI-1050: the bundle alone decides). A set with a
// connectors section must carry a descriptor for the connector that declares
// each capability; a set without one (an older catalog) registers a tool's
// capabilities only through its required_capabilities, which every operation
// is already checked against.
func (s v2PolicySet) connectorDeclares(connectorID string, capabilities []string) bool {
	if s.Connectors == nil {
		return true
	}
	for _, c := range s.Connectors {
		if c.ID != connectorID {
			continue
		}
		for _, wanted := range capabilities {
			declared := false
			for _, capability := range c.Capabilities {
				if capability.Name == wanted {
					declared = true
					break
				}
			}
			if !declared {
				return false
			}
		}
		return true
	}
	return false
}

func (v *Verified) operationResourceRegistered(tool *V2Tool, op Operation) bool {
	if op.ResourceType == "" {
		return op.ResourceID == "" && op.ResourceParent == "" && op.ResourceParentType == ""
	}
	for _, rt := range tool.ResourceTypes {
		if rt.Type == op.ResourceType && rt.ParentType == op.ResourceParentType {
			if rt.ParentType == "" && (op.ResourceParent != "" || op.ResourceParentType != "") {
				continue
			}
			if rt.ParentType != "" && (op.ResourceParent == "" || op.ResourceParentType != rt.ParentType) {
				continue
			}
			return true
		}
	}
	return false
}

// evaluateV2Check decides a request against the matching checks. Under
// deny_overrides any matching deny wins over every matching permit, priority is
// not read, and policy id ascending breaks ties (contracts policy.Precedence);
// otherwise the highest priority decides, then deny before permit, then id.
func evaluateV2Check(denyOverrides bool, checks []v2Check, request map[string]string, subject *SessionSubject, groups, roles []string, agentID, orgID, workspaceID string, capabilityPermits bool) Decision {
	decision, _ := evaluateV2CheckWinner(denyOverrides, checks, request, subject, groups, roles, agentID, orgID, workspaceID, capabilityPermits)
	return decision
}

// evaluateV2CheckWinner is evaluateV2Check that also returns the winning
// check, or nil when no check matched.
func evaluateV2CheckWinner(denyOverrides bool, checks []v2Check, request map[string]string, subject *SessionSubject, groups, roles []string, agentID, orgID, workspaceID string, capabilityPermits bool) (Decision, *v2Check) {
	matching := make([]v2Check, 0, len(checks))
	call := Call{AgentID: agentID, UserID: subject.UserID, Email: subject.Email}
	for _, check := range checks {
		// A direct capability permit is a separate compatibility grant and
		// cannot create the missing tool-call permit outside the operation
		// plan. Inside the plan (M1) it covers every tool whose
		// connector_binding operation is the named capability on that
		// connector — the permit is the op grant, no separate tool permit.
		// Direct capability denies remain effective everywhere.
		if !capabilityPermits && check.Selector["tool"] == "" && check.Effect == policyPermitAction {
			continue
		}
		if check.Effect != policyPermitAction && check.Effect != "deny" || !v2ScopeMatches(check.Scope, agentID, orgID, workspaceID) {
			continue
		}
		if !srcMatch(check.Selector["source_principal"], call, groups, roles) || !v2SelectorMatches(check.Selector, request) {
			continue
		}
		matching = append(matching, check)
	}
	if len(matching) == 0 {
		return Decision{Outcome: "deny", ReasonCode: "no_matching_policy", Reason: "no policy check matched the operation"}, nil
	}
	sort.Slice(matching, func(i, j int) bool {
		if denyOverrides {
			return pol.Precedence(v2CheckRule(matching[i]), v2CheckRule(matching[j])) < 0
		}
		if matching[i].Priority != matching[j].Priority {
			return matching[i].Priority > matching[j].Priority
		}
		if matching[i].Effect != matching[j].Effect {
			return matching[i].Effect == "deny"
		}
		return matching[i].PolicyID < matching[j].PolicyID
	})
	winner := matching[0]
	if winner.Effect == "deny" {
		return Decision{Outcome: "deny", PolicyID: winner.PolicyID, ReasonCode: "policy_deny", Reason: "policy denied"}, &winner
	}
	return Decision{Outcome: "allow", PolicyID: winner.PolicyID}, &winner
}

// v2CheckRule is the part of a check that deny-overrides precedence reads.
func v2CheckRule(c v2Check) pol.Rule {
	return pol.Rule{ID: c.PolicyID, Effect: pol.Effect(c.Effect)}
}

func v2ScopeMatches(scope struct {
	OrgID       *string `json:"org_id"`
	WorkspaceID *string `json:"workspace_id"`
	AgentID     *string `json:"agent_id"`
}, agentID, orgID, workspaceID string) bool {
	return (scope.OrgID == nil || *scope.OrgID == orgID) && (scope.WorkspaceID == nil || *scope.WorkspaceID == workspaceID) && (scope.AgentID == nil || *scope.AgentID == agentID)
}

func v2SelectorMatches(selector map[string]string, request map[string]string) bool {
	for dimension, expected := range selector {
		if dimension == "source_principal" {
			continue
		}
		actual, ok := request[dimension]
		if !ok || expected == "" {
			return false
		}
		if expected == "*" {
			continue
		}
		if dimension == "capability" && strings.HasSuffix(expected, ".*") && len(expected) > 2 {
			// A trailing .* capability selector is an operation-family
			// wildcard (O1): it matches by dot segment and never opens a
			// write — the plan request carries the tool's operation_class,
			// and without it in the request the wildcard matches nothing.
			if !capabilityDotSegmentMatch(expected, actual) || request["operation_class"] != "read" {
				return false
			}
			continue
		}
		if expected != actual {
			return false
		}
	}
	return true
}

func membershipValues(identities []Identity, userID string, now time.Time) (groups, roles []string) {
	groupSet, roleSet := map[string]bool{}, map[string]bool{}
	for _, identity := range identities {
		if identity.UserID != userID || identity.Status != SubjectLinked || (!identity.ExpireTime.IsZero() && !now.Before(identity.ExpireTime)) {
			continue
		}
		for _, group := range identity.Groups {
			groupSet[group] = true
		}
		for _, role := range identity.OrgRoles {
			roleSet[role] = true
		}
	}
	for group := range groupSet {
		groups = append(groups, group)
	}
	for role := range roleSet {
		roles = append(roles, role)
	}
	return groups, roles
}

func containsExact(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
