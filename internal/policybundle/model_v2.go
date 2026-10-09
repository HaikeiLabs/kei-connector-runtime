package policybundle

import "time"

// Model-call reason codes under a v2 bundle (ADR-035 §6, HAI-459).
const (
	ReasonModelAssigned        = "model_assigned"
	ReasonModelNotAssigned     = "model_not_assigned"
	ReasonModelProfileInactive = "model_profile_inactive"
)

// EvaluateV2Model decides one model call under a v2 bundle. The calling
// agent's model-profile assignment is the permission: model: policies are not
// consulted. The call is allowed only when the session subject passes the v2
// subject gate and agent_model_profiles assigns profileID to agentID with
// status active.
func (v *Verified) EvaluateV2Model(profileID, agentID string, subject *SessionSubject, now time.Time) Decision {
	if decision, denied := v.v2SubjectDenial(subject, now); denied {
		return decision
	}
	if profileID != "" && agentID != "" {
		for _, assigned := range v.Payload.AgentModelProfiles {
			if assigned.AgentID != agentID || assigned.ProfileID != profileID {
				continue
			}
			if assigned.Status != "active" {
				return Decision{Outcome: "deny", ReasonCode: ReasonModelProfileInactive, Reason: "the agent's assigned model profile is not active"}
			}
			return Decision{Outcome: "allow", ReasonCode: ReasonModelAssigned}
		}
	}
	return Decision{Outcome: "deny", ReasonCode: ReasonModelNotAssigned, Reason: "the model profile is not assigned to the calling agent"}
}
