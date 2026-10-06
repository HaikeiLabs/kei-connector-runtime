package invoke

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credrelease"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

type preparedOperation struct {
	operation policybundle.Operation
	meta      contract.Metadata
	inv       contract.Invocation
	conn      connector.Connector
	input     any
}

func (d *Daemon) invokeV2(ctx context.Context, dr daemonRequest, plan connectorInvokePlan, canonical json.RawMessage, started time.Time, out output) output {
	finish := func(denied *denial) output {
		if denied != nil {
			out.Decision, out.ReasonCode, out.Reason, out.Result, out.Audit = "deny", denied.code, denied.reason, nil, nil
		}
		d.Env.emitAudit(plan, nil, out, time.Since(started))
		return out
	}
	if dr.PreflightHandle == "" || d.PlanV2 == nil || d.ValidateV2 == nil || d.ConsumeV2 == nil || d.Authorize == nil || d.UseCredential == nil {
		return finish(deny("preflight_required", "v2 tool calls require a valid preflight handle"))
	}
	grant, err := d.Authorize(ctx, DaemonCall{AgentID: dr.AgentID, ToolName: dr.ToolName})
	if err != nil {
		return finish(deny("request_canceled", "request canceled"))
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
	ops, err := d.PlanV2(ctx, dr.ToolName, agentID, append([]byte(nil), canonical...), dr.ParentSpan, dr.DelegationDepth)
	if err != nil || len(ops) == 0 {
		return finish(deny("operation_plan_invalid", "the complete trusted operation plan is unavailable"))
	}

	// Strictly validate every provider request before consuming or calling any
	// operation. The only plan source is the runtime's registered planner.
	prepared := make([]preparedOperation, 0, len(ops))
	for _, op := range ops {
		if op.ConnectorID != grant.ConnectorID || op.Capability == "" || op.Action == "" || !contains(grant.Capabilities, op.Capability) || op.InputDigest != plan.req.InputDigest {
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
		meta, inv, denied := sessionCall(grant, opReq)
		if denied != nil {
			return finish(denied)
		}
		conn, decoded, denied := d.Env.prepare(operationRequest, canonical, meta, inv)
		if denied != nil {
			return finish(denied)
		}
		prepared = append(prepared, preparedOperation{operation: op, meta: meta, inv: inv, conn: conn, input: decoded})
	}

	// Confirm the caller did not substitute, omit, or add a plan item before
	// any provider side effect. Consumption remains immediately before each op.
	if err := d.ValidateV2(ctx, dr.PreflightHandle, dr.ToolName, agentID, ops, dr.ParentSpan, dr.DelegationDepth); err != nil {
		return finish(deny("authorization_invalid", "the v2 operation plan is invalid or expired"))
	}
	results := make([]json.RawMessage, 0, len(prepared))
	var lastExec *execution
	for _, item := range prepared {
		if err := d.ConsumeV2(ctx, dr.PreflightHandle, dr.ToolName, agentID, item.operation, dr.ParentSpan, dr.DelegationDepth); err != nil {
			return finish(deny("authorization_invalid", "the v2 operation authorization is invalid or expired"))
		}
		exec := &execution{provider: item.meta.Provider, meta: &item.meta, invocation: &item.inv, credentialSubject: contract.CredentialSubject(item.meta, item.inv)}
		var runDenial *denial
		err := d.UseCredential(ctx, grant.Subject, string(item.meta.Provider), func(token string) error {
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
	out.Decision, out.Provider, out.Result = "allow", grant.Provider, result
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
