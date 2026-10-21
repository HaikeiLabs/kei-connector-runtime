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
	return v.toBundle().EvaluateV2Model(profileID, agentID, subject, now)
}
