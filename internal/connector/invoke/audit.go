package invoke

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// executionRecord is the audit record of one connector call (contract
// section 8). Its first block is the decision-line shape the collector ships
// today (the root package's DecisionEvent JSON); the execution fields stay in
// the local spool until the catalog accepts a connector_execution record. It
// never carries input, results, tokens, secrets, references, or email
// addresses.
type executionRecord struct {
	SpanID           string    `json:"span_id"`
	InvokedAt        time.Time `json:"invoked_at"`
	InvokingSubject  string    `json:"invoking_subject"`
	ParentSpan       *string   `json:"parent_span,omitempty"`
	DelegationDepth  int       `json:"delegation_depth"`
	AgentID          string    `json:"agent_id"`
	Framework        string    `json:"framework"`
	ToolName         string    `json:"tool_name"`
	ToolArgsDigest   *string   `json:"tool_args_digest,omitempty"`
	ResourcesTouched []string  `json:"resources_touched"`
	Decision         string    `json:"decision"`
	PolicyReason     *string   `json:"policy_reason,omitempty"`
	OrgID            *string   `json:"org_id,omitempty"`
	WorkspaceID      *string   `json:"workspace_id,omitempty"`

	ConnectorID         string `json:"connector_id"`
	Provider            string `json:"provider,omitempty"`
	Capability          string `json:"capability"`
	CredentialSource    string `json:"credential_source,omitempty"`
	AccountModel        string `json:"account_model,omitempty"`
	CredentialSubject   string `json:"credential_subject,omitempty"`
	AccountEmailDigest  string `json:"account_email_digest,omitempty"`
	AssertionKID        string `json:"assertion_kid,omitempty"`
	InputDigest         string `json:"input_digest,omitempty"`
	ResultDigest        string `json:"result_digest,omitempty"`
	ResultBytes         int    `json:"result_bytes,omitempty"`
	ProviderStatusClass string `json:"provider_status_class,omitempty"`
	ReasonCode          string `json:"reason_code,omitempty"`
	DurationMS          int64  `json:"duration_ms"`
	ApprovalID          string `json:"approval_id,omitempty"`
	IdempotencyKey      string `json:"idempotency_key,omitempty"`
}

// emitAudit writes the call's execution record through env.Audit. Audit is
// fail-open (ADR-010): a write failure never changes the outcome.
func (env Env) emitAudit(plan connectorInvokePlan, exec *execution, out output, elapsed time.Duration) {
	if env.Audit == nil {
		return
	}
	req := plan.req
	parent := req.TraceID
	reason := "executed"
	if out.Decision != "allow" {
		reason = out.ReasonCode
	}
	rec := executionRecord{
		SpanID: uuid.NewString(), InvokedAt: time.Now().UTC(), ParentSpan: &parent,
		InvokingSubject: req.InvokingSubject, AgentID: req.AgentID, Framework: req.Framework,
		ResourcesTouched: []string{req.Resource}, Decision: out.Decision, PolicyReason: &reason,
		ConnectorID: req.ConnectorID, Capability: req.Capability,
		ReasonCode: out.ReasonCode, DurationMS: elapsed.Milliseconds(),
		ApprovalID: req.ApprovalID, IdempotencyKey: req.IdempotencyKey,
	}
	if req.InputDigest != "" {
		digest := req.InputDigest
		rec.ToolArgsDigest, rec.InputDigest = &digest, digest
	}
	if out.Audit != nil {
		rec.ResultDigest, rec.ResultBytes = out.Audit.ResultDigest, out.Audit.ResultBytes
	}
	if exec != nil {
		rec.Provider = string(exec.provider)
		rec.CredentialSubject, rec.AccountEmailDigest, rec.AssertionKID, rec.ProviderStatusClass = exec.credentialSubject, exec.accountEmailDigest, exec.assertionKID, exec.statusClass
		if exec.meta != nil {
			rec.CredentialSource, rec.AccountModel = string(exec.meta.EffectiveCredentialSource()), string(exec.meta.AccountModel)
		}
		if inv := exec.invocation; inv != nil {
			org, ws := inv.TenantID, inv.WorkspaceID
			rec.OrgID, rec.WorkspaceID, rec.AgentID, rec.InvokingSubject = &org, &ws, inv.AgentID, inv.Subject
		}
	}
	rec.ToolName = "connector:" + rec.Provider + ":" + req.Capability
	if rec.Provider == "" {
		rec.ToolName = "connector:" + req.Capability
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_ = env.Audit(data)
}
