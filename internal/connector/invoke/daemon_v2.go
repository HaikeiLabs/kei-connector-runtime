package invoke

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credrelease"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/denyhint"
)

type preparedOperation struct {
	operation policybundle.Operation
	secret    *policybundle.Connector
	meta      contract.Metadata
	inv       contract.Invocation
	conn      connector.Connector
	input     any
}

func (d *Daemon) invokeV2(ctx context.Context, dr daemonRequest, plan connectorInvokePlan, canonical json.RawMessage, started time.Time, out output) output {
	finish := func(denied *denial) output {
		if denied != nil {
			out.Decision, out.ReasonCode, out.Reason, out.Result, out.Audit = "deny", denied.code, denied.reason, nil, nil
			out.Hint = denyhint.Hint(denied.code)
		}
		d.Env.emitAudit(plan, nil, out, time.Since(started))
		return out
	}
	if dr.PreflightHandle == "" || d.PlanV2 == nil || d.ValidateV2 == nil || d.ConsumeV2Plan == nil || d.Authorize == nil || d.UseCredential == nil {
		return finish(deny("preflight_required", "v2 tool calls require a valid preflight handle"))
	}
	grant, err := d.Authorize(ctx, DaemonCall{Session: dr.SessionID, AgentID: dr.AgentID, ToolName: dr.ToolName})
	if err != nil {
		return finish(deny("request_canceled", "request canceled"))
	}
	if grant.ReasonCode == ReasonSessionNotFound {
		return finish(deny(ReasonSessionNotFound, "the session does not exist or has ended"))
	}
	if !grant.HasSession {
		return finish(deny("no_session", "no active session"))
	}
	if !grant.V2Tool || grant.Provider == "" || grant.ConnectorID == "" || grant.AgentID == "" || (dr.AgentID != "" && dr.AgentID != grant.AgentID) {
		return finish(deny("preflight_required", "the tool is not registered for v2 connector execution"))
	}
	if grant.Subject == "" {
		return finish(deny("subject_unlinked", "the session subject is not linked"))
	}
	agentID := grant.AgentID
	contextRaw := []byte(dr.Context)
	if len(contextRaw) == 0 {
		contextRaw = []byte("{}")
	}
	if policybundle.RejectDuplicateJSON(contextRaw) != nil {
		return finish(deny("input_invalid", "tool context contains ambiguous JSON"))
	}
	if len(contextRaw) > policybundle.MaxPlanDataBytes {
		return finish(deny("input_invalid", "context exceeds the v2 tool context size limit"))
	}
	canonicalContext, _, contextErr := input.Canonicalize(contextRaw)
	if contextErr != nil || len(canonicalContext) > policybundle.MaxPlanDataBytes {
		return finish(deny("input_invalid", "context must be one JSON object of at most 64 KiB"))
	}
	ops, err := d.PlanV2(ctx, dr.SessionID, dr.ToolName, agentID, append([]byte(nil), canonical...), append([]byte(nil), canonicalContext...), dr.ParentSpan, dr.DelegationDepth)
	if err != nil || len(ops) == 0 {
		return finish(deny("operation_plan_invalid", "the complete trusted operation plan is unavailable"))
	}

	// Strictly validate every provider request before consuming or calling any
	// operation. The only plan source is the runtime's registered planner.
	prepared := make([]preparedOperation, 0, len(ops))
	for _, op := range ops {
		if op.ConnectorID != grant.ConnectorID || op.Capability == "" || op.Action == "" || !contains(grant.Capabilities, op.Capability) || op.InputDigest != sha256Digest(op.ProviderInput) {
			return finish(deny("operation_plan_invalid", "the operation does not match the registered tool"))
		}
		opReq := dr
		opReq.AgentID = agentID
		opReq.ConnectorID, opReq.Capability, opReq.Action, opReq.Resource = op.ConnectorID, op.Capability, op.Action, op.Resource
		operationRequest := plan.req
		operationRequest.AgentID = agentID
		operationRequest.ConnectorID, operationRequest.Capability, operationRequest.Action, operationRequest.Resource = op.ConnectorID, op.Capability, op.Action, op.Resource
		operationRequest.ToolName, operationRequest.PreflightHandle = dr.ToolName, dr.PreflightHandle
		operationRequest.InputDigest = op.InputDigest
		operationRequest.InvokingSubject = grant.Subject
		meta, inv, secret, denied := daemonCall(grant, opReq)
		if denied != nil {
			return finish(denied)
		}
		conn, decoded, denied := d.Env.prepare(operationRequest, op.ProviderInput, meta, inv)
		if denied != nil {
			return finish(denied)
		}
		prepared = append(prepared, preparedOperation{operation: op, secret: secret, meta: meta, inv: inv, conn: conn, input: decoded})
	}

	// Confirm the caller did not substitute, omit, or add a plan item before
	// any provider side effect. Consumption remains immediately before each op.
	if err := d.ValidateV2(ctx, dr.PreflightHandle, dr.SessionID, dr.ToolName, agentID, canonical, canonicalContext, ops, dr.ParentSpan, dr.DelegationDepth); err != nil {
		return finish(deny("authorization_invalid", "the v2 operation plan is invalid or expired"))
	}
	if err := d.ConsumeV2Plan(ctx, dr.PreflightHandle, dr.SessionID, dr.ToolName, agentID, canonical, canonicalContext, ops, dr.ParentSpan, dr.DelegationDepth); err != nil {
		return finish(deny("authorization_invalid", "the v2 operation plan is invalid or expired"))
	}
	results := make([]json.RawMessage, 0, len(prepared))
	var lastExec *execution
	for _, item := range prepared {
		exec := &execution{provider: item.meta.Provider, meta: &item.meta, invocation: &item.inv, credentialSubject: contract.CredentialSubject(item.meta, item.inv)}
		var runDenial *denial
		err := d.useCredential(ctx, dr.SessionID, grant.Subject, item.meta, item.secret, func(token string) error {
			status, denied := d.Env.run(ctx, item.conn, item.meta, item.inv, item.input, token, exec)
			runDenial = denied
			if denied != nil && status == http.StatusUnauthorized {
				return credrelease.ErrProviderUnauthorized
			}
			return nil
		})
		if err != nil {
			connectDenial, connect := credentialDenial(err)
			out.Connect = connect
			return finish(connectDenial)
		}
		if runDenial != nil {
			return finish(runDenial)
		}
		results = append(results, append(json.RawMessage(nil), exec.result...))
		lastExec = exec
	}
	var result json.RawMessage
	if len(results) == 1 {
		result = results[0]
	} else {
		encoded, err := json.Marshal(results)
		if err != nil {
			return finish(deny("provider_error", "result could not be encoded"))
		}
		result = encoded
	}
	if len(result) > maxConnectorResultBytes {
		return finish(deny("result_too_large", "result exceeds the size limit"))
	}
	out.Decision, out.Provider, out.Result = "allow", string(prepared[0].meta.Provider), result
	out.ConnectorID = grant.ConnectorID
	out.Audit.ResultDigest, out.Audit.ResultBytes = sha256Digest(result), len(result)
	d.Env.emitAudit(plan, lastExec, out, time.Since(started))
	return out
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
