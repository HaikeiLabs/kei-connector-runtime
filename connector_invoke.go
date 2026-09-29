package connectorruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts"
	"github.com/google/uuid"
)

// ConnectorInvokeRequest is the wire shape a harness sends to ABAC's governed
// connector invocation endpoint. Tenant/workspace/agent are resolved
// server-side from the harness token; the proxy only forwards the capability,
// the resource, and the identity-propagation context.
type ConnectorInvokeRequest struct {
	HarnessToken    string `json:"harness_token"`
	AgentID         string `json:"agent_id,omitempty"`
	ConnectorID     string `json:"connector_id"`
	Capability      string `json:"capability"`
	Action          string `json:"action"`
	Resource        string `json:"resource"`
	TraceID         string `json:"trace_id"`
	IdempotencyKey  string `json:"idempotency_key,omitempty"`
	ApprovalID      string `json:"approval_id,omitempty"`
	InvokingSubject string `json:"invoking_subject,omitempty"`
	UserID          string `json:"user_id,omitempty"`
	Framework       string `json:"framework,omitempty"`
	// ProviderUserID is the chat-platform identity (e.g. a WhatsApp E.164
	// number); the catalog resolves it to the invoking Kei user.
	ProviderUserID string `json:"provider_user_id,omitempty"`
	// InputDigest binds the decision to the capability input without sending
	// it: "sha256:<hex>" of the canonical input JSON.
	InputDigest string `json:"input_digest,omitempty"`
}

// ConnectorInvokeResponse mirrors the ABAC invoke response. On an allow the
// envelope carries the full propagation chain as minted by the control plane,
// the connector descriptor, and, for an OAuth connector, the token proxied for
// this call. A deny carries a reason and, where known, a reason code.
type ConnectorInvokeResponse struct {
	Decision          string               `json:"decision"`
	Reason            string               `json:"reason,omitempty"`
	ReasonCode        string               `json:"reason_code,omitempty"`
	Envelope          *connectors.Envelope `json:"envelope,omitempty"`
	Connector         *ConnectorDescriptor `json:"connector,omitempty"`
	CredentialSubject string               `json:"credential_subject,omitempty"`
	OAuth             *OAuthCredential     `json:"oauth,omitempty"`
	Enrollment        *json.RawMessage     `json:"enrollment,omitempty"`
	Connect           *json.RawMessage     `json:"connect,omitempty"`
}

// InvokeConnector calls the governed connector invocation endpoint. The proxy
// authenticates itself with X-KEI-API-Key (ADR-009) and fails closed on any
// non-200 status, so a rejected or unavailable engine never yields a decision
// the harness could act on.
func (c *abacClient) InvokeConnector(ctx context.Context, req ConnectorInvokeRequest) (*ConnectorInvokeResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal connector invoke request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/data-connectors/invoke", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build connector invoke request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.secret != "" {
		httpReq.Header.Set("X-KEI-API-Key", c.secret)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("connector invoke request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read connector invoke response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("ABAC rejected proxy credentials (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("connector invoke returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var out ConnectorInvokeResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("unmarshal connector invoke response: %w", err)
	}
	return &out, nil
}

// connectorInvokeArgs is the parsed CLI input for `kei-proxy connector invoke`.
type connectorInvokeArgs struct {
	connectorID     string
	capability      string
	action          string
	resource        string
	traceID         string
	idempotencyKey  string
	approvalID      string
	invokingSubject string
	userID          string
	agentID         string
	framework       string
	input           string
	providerUser    string
}

// connectorInvokePlan is the resolved execution plan for `connector invoke`:
// the request plus the ABAC endpoint, credential, and timeout the caller
// should use, after applying CLI overrides and the runtime relay rules.
type connectorInvokePlan struct {
	req        ConnectorInvokeRequest
	abacURL    string
	abacSecret string
	timeout    time.Duration
	input      string
}

// parseConnectorInvokeArgs maps CLI flags and the identity-propagation
// environment to an execution plan. The harness token is taken from the
// environment, never from an argument.
func parseConnectorInvokeArgs(args []string) (connectorInvokePlan, error) {
	fs := flag.NewFlagSet("connector invoke", flag.ContinueOnError)
	connectorID := fs.String("connector", "", "connector id to invoke")
	capability := fs.String("capability", "", "capability to invoke (e.g. lead.read)")
	action := fs.String("action", "", "action (e.g. read, update)")
	resource := fs.String("resource", "", "resource/data being accessed")
	traceID := fs.String("trace-id", envOr("KEI_PROXY_SPAN_ID", ""), "trace id for the invocation (stable dedupe key)")
	idempotencyKey := fs.String("idempotency-key", "", "idempotency key (dedupe key, overrides trace id for audit)")
	approvalID := fs.String("approval-id", "", "approval reference for mutating capabilities")
	invokingSubject := fs.String("invoking-subject", envOr("KEI_PROXY_INVOKING_SUBJECT", ""), "invoking subject (defaults to --user-id)")
	userID := fs.String("user-id", "", "user id acting (defaults to --user)")
	user := fs.String("user", "", "alias for --user-id")
	agentID := fs.String("agent-id", envOr("KEI_PROXY_AGENT_ID", ""), "agent id making the call")
	framework := fs.String("framework", envOr("KEI_PROXY_FRAMEWORK", ""), "agent framework (e.g. claude, codex)")
	abacURL := fs.String("abac-url", "", "ABAC Engine URL (default $ABAC_URL)")
	timeout := fs.Int("timeout", 30, "whole-call deadline in seconds")
	input := fs.String("input", "", "capability input: a JSON object, @<file>, or - for stdin (default {})")
	providerUser := fs.String("provider-user", "", "chat-platform identity, e.g. a WhatsApp E.164 number (default $KEI_PROXY_PROVIDER_USER)")

	if err := fs.Parse(args); err != nil {
		return connectorInvokePlan{}, err
	}

	if *userID == "" && *user != "" {
		*userID = *user
	}
	cfg := configFromEnv()
	if *abacURL != "" {
		cfg.ABACURL = *abacURL
	}

	if *connectorID == "" || *capability == "" || *action == "" || *resource == "" {
		return connectorInvokePlan{}, fmt.Errorf("--connector, --capability, --action, and --resource are required")
	}
	if cfg.RuntimeToken == "" {
		return connectorInvokePlan{}, fmt.Errorf("KEI_RUNTIME_TOKEN is required")
	}
	if *traceID == "" {
		*traceID = uuid.NewString()
	}
	if *providerUser == "" {
		*providerUser = cfg.ProviderUserID
	}

	if *invokingSubject == "" {
		*invokingSubject = *userID
	}

	// Customer runtimes relay the self-authenticating request through the
	// public control-plane URL and never receive ABAC_API_SECRET.
	abacURLValue, secret := cfg.ABACURL, cfg.ABACSecret
	if cfg.IsRuntime() {
		abacURLValue = cfg.RuntimeControlPlaneURL
		secret = ""
	}

	return connectorInvokePlan{
		req: ConnectorInvokeRequest{
			HarnessToken:    cfg.RuntimeToken,
			AgentID:         *agentID,
			ConnectorID:     *connectorID,
			Capability:      *capability,
			Action:          *action,
			Resource:        *resource,
			TraceID:         *traceID,
			IdempotencyKey:  *idempotencyKey,
			ApprovalID:      *approvalID,
			InvokingSubject: *invokingSubject,
			UserID:          *userID,
			Framework:       *framework,
			ProviderUserID:  *providerUser,
		},
		abacURL:    abacURLValue,
		abacSecret: secret,
		timeout:    time.Duration(*timeout) * time.Second,
		input:      *input,
	}, nil
}

// runConnector dispatches the connector subcommand.
func runConnector(args []string) int {
	if len(args) > 0 && args[0] == "invoke" {
		return runConnectorInvoke(args[1:])
	}
	fmt.Fprintln(os.Stderr, "Error: unknown connector command\n\nUsage: kei-proxy connector invoke --connector <id> --capability <name> --action <action> --resource <resource> [--input <json>|@<file>|-] [--user <id> | --provider-user <id>]")
	return 1
}

func runConnectorInvoke(args []string) int {
	store, err := NewSecretStore()
	if err != nil {
		store = nil // opaque_ref connectors then deny credential_backend_unavailable
	}
	return runConnectorInvokeWith(args, connectorInvokeDeps{
		runtime: connectorRuntime{
			secrets:    store,
			httpClient: &http.Client{},
			assertion:  assertionKeyConfigFromEnv(),
		},
		stdin:         os.Stdin,
		auditPath:     configFromEnv().AuditPath,
		auditMaxBytes: configFromEnv().AuditMaxBytes,
	}, os.Stdout, os.Stderr)
}

// connectorInvokeDeps are the seams of one `connector invoke`; tests inject a
// fake catalog, store, and provider transport.
type connectorInvokeDeps struct {
	catalog         ABACClient
	controlPlaneURL string
	runtime         connectorRuntime
	stdin           io.Reader
	auditPath       string
	auditMaxBytes   int64
}

const catalogTimeout = 10 * time.Second

// connectorInvokeOutput is the one JSON object written to stdout.
type connectorInvokeOutput struct {
	Decision    string               `json:"decision"`
	ReasonCode  string               `json:"reason_code,omitempty"`
	Reason      string               `json:"reason,omitempty"`
	TraceID     string               `json:"trace_id,omitempty"`
	ConnectorID string               `json:"connector_id,omitempty"`
	Provider    string               `json:"provider,omitempty"`
	Capability  string               `json:"capability,omitempty"`
	Result      json.RawMessage      `json:"result,omitempty"`
	Audit       *connectorOutAudit   `json:"audit,omitempty"`
	Enrollment  *json.RawMessage     `json:"enrollment,omitempty"`
	Connect     *json.RawMessage     `json:"connect,omitempty"`
	Envelope    *connectors.Envelope `json:"envelope,omitempty"`
}

type connectorOutAudit struct {
	InputDigest  string `json:"input_digest,omitempty"`
	ResultDigest string `json:"result_digest,omitempty"`
	ResultBytes  int    `json:"result_bytes"`
}

// runConnectorInvokeWith runs one governed connector call: validate the input
// locally, ask the catalog, execute on allow, and write exactly one JSON
// object. Exit 0 only for an executed allow; every other outcome is a deny.
func runConnectorInvokeWith(args []string, deps connectorInvokeDeps, stdout, stderr io.Writer) int {
	plan, err := parseConnectorInvokeArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), plan.timeout)
	defer cancel()
	if deps.catalog == nil {
		deps.catalog = NewABACClient(plan.abacURL, plan.abacSecret, plan.timeout)
	}
	if deps.controlPlaneURL == "" {
		deps.controlPlaneURL = plan.abacURL
	}

	out := connectorInvokeOutput{TraceID: plan.req.TraceID, ConnectorID: plan.req.ConnectorID, Capability: plan.req.Capability}
	var exec *connectorExecution
	finish := func(d *connectorDeny) int {
		code := 0
		if d != nil {
			out.Decision, out.ReasonCode, out.Reason, out.Result, out.Audit = "deny", d.code, d.reason, nil, nil
			code = 1
		}
		emitConnectorExecution(deps.auditPath, deps.auditMaxBytes, plan, exec, out, time.Since(started))
		if err := writeJSON(stdout, out); err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		return code
	}

	raw, err := readConnectorInput(plan.input, deps.stdin)
	if err != nil {
		return finish(deny("input_invalid", "input must be a JSON object of at most 16 KiB"))
	}
	input, digest, err := canonicalizeConnectorInput(raw)
	if err != nil {
		return finish(deny("input_invalid", "input must be a JSON object of at most 16 KiB"))
	}
	plan.req.InputDigest = digest
	out.Audit = &connectorOutAudit{InputDigest: digest}

	catalogCtx, cancelCatalog := context.WithTimeout(ctx, catalogTimeout)
	resp, err := deps.catalog.InvokeConnector(catalogCtx, plan.req)
	cancelCatalog()
	if err != nil {
		fmt.Fprintln(stderr, "Error: connector decision unavailable (fail closed)")
		return finish(deny("catalog_unavailable", "the control plane did not return a decision"))
	}
	out.Enrollment, out.Connect, out.Envelope = resp.Enrollment, resp.Connect, resp.Envelope
	if resp.Decision != "allow" {
		return finish(deny(catalogReasonCode(resp), resp.Reason))
	}

	exec, d := deps.runtime.execute(ctx, plan.req, input, resp, deps.controlPlaneURL)
	out.Provider = string(exec.provider)
	if d != nil {
		return finish(d)
	}
	out.Decision, out.Result = "allow", exec.result
	out.Audit.ResultDigest, out.Audit.ResultBytes = sha256Digest(exec.result), len(exec.result)
	return finish(nil)
}

var reasonCodePattern = regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)

// catalogReasonCode classifies a catalog deny: its own reason code when it
// sent a well-formed one, otherwise enrollment, approval, or policy.
func catalogReasonCode(resp *ConnectorInvokeResponse) string {
	switch {
	case reasonCodePattern.MatchString(resp.ReasonCode):
		return resp.ReasonCode
	case resp.Enrollment != nil:
		return "enrollment_required"
	case resp.Reason == "approval required":
		return "approval_required"
	}
	return "policy_deny"
}

// connectorExecutionEvent is the audit record of one connector call. The
// embedded DecisionEvent fields ship through the existing collector flush;
// the execution fields stay in the local spool until the catalog accepts a
// connector_execution record. It never carries input, results, tokens,
// secrets, references, or email addresses.
type connectorExecutionEvent struct {
	DecisionEvent
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

func emitConnectorExecution(path string, maxBytes int64, plan connectorInvokePlan, exec *connectorExecution, out connectorInvokeOutput, elapsed time.Duration) {
	if path == "" {
		return
	}
	req := plan.req
	parent := req.TraceID
	reason := "executed"
	if out.Decision != "allow" {
		reason = out.ReasonCode
	}
	subject := req.InvokingSubject
	provider := ""
	e := connectorExecutionEvent{
		DecisionEvent: DecisionEvent{
			SpanID: uuid.NewString(), InvokedAt: time.Now().UTC(), ParentSpan: &parent,
			AgentID: req.AgentID, Framework: req.Framework,
			ResourcesTouched: []string{req.Resource}, Decision: out.Decision, PolicyReason: &reason,
		},
		ConnectorID: req.ConnectorID, Capability: req.Capability,
		ReasonCode: out.ReasonCode, DurationMS: elapsed.Milliseconds(),
		ApprovalID: req.ApprovalID, IdempotencyKey: req.IdempotencyKey,
	}
	if req.InputDigest != "" {
		digest := req.InputDigest
		e.ToolArgsDigest, e.InputDigest = &digest, digest
	}
	if out.Audit != nil {
		e.ResultDigest, e.ResultBytes = out.Audit.ResultDigest, out.Audit.ResultBytes
	}
	if exec != nil {
		provider = string(exec.provider)
		e.CredentialSubject, e.AccountEmailDigest, e.AssertionKID, e.ProviderStatusClass = exec.credentialSubject, exec.accountEmailDigest, exec.assertionKID, exec.statusClass
		if exec.meta != nil {
			e.CredentialSource, e.AccountModel = string(exec.meta.EffectiveCredentialSource()), string(exec.meta.AccountModel)
		}
		if inv := exec.invocation; inv != nil {
			org, ws := inv.TenantID, inv.WorkspaceID
			e.OrgID, e.WorkspaceID, e.AgentID, subject = &org, &ws, inv.AgentID, inv.Subject
		}
	}
	e.Provider, e.InvokingSubject = provider, subject
	e.ToolName = "connector:" + provider + ":" + req.Capability
	if provider == "" {
		e.ToolName = "connector:" + req.Capability
	}
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	_ = newAuditSpool(path, maxBytes).Append(eventClassDecision, data)
}
