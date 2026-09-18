package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

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
}

// ConnectorInvokeResponse mirrors the ABAC invoke response. On an allow the
// envelope carries the full propagation chain as minted by the control plane;
// a deny carries a reason.
type ConnectorInvokeResponse struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
	Envelope *struct {
		Version    string `json:"version"`
		MintedBy   string `json:"minted_by"`
		Invocation struct {
			TenantID       string `json:"tenant_id"`
			WorkspaceID    string `json:"workspace_id"`
			Subject        string `json:"subject"`
			AgentID        string `json:"agent_id"`
			ConnectorID    string `json:"connector_id"`
			Capability     string `json:"capability"`
			Resource       string `json:"resource"`
			TraceID        string `json:"trace_id"`
			IdempotencyKey string `json:"idempotency_key"`
		} `json:"invocation"`
	} `json:"envelope,omitempty"`
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
}

// connectorInvokePlan is the resolved execution plan for `connector invoke`:
// the request plus the ABAC endpoint, credential, and timeout the caller
// should use, after applying CLI overrides and the runtime relay rules.
type connectorInvokePlan struct {
	req        ConnectorInvokeRequest
	abacURL    string
	abacSecret string
	timeout    time.Duration
}

// parseConnectorInvokeArgs maps CLI flags and the identity-propagation
// environment to an execution plan. The harness token is taken from the
// environment (or --key), never from an argument.
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
	key := fs.String("key", "", "harness key (alias for KEI_HARNESS_TOKEN env)")
	abacURL := fs.String("abac-url", "", "ABAC Engine URL (default $ABAC_URL)")
	timeout := fs.Int("timeout", 30, "ABAC request timeout in seconds")

	if err := fs.Parse(args); err != nil {
		return connectorInvokePlan{}, err
	}

	if *userID == "" && *user != "" {
		*userID = *user
	}
	if *key != "" {
		os.Setenv("KEI_HARNESS_TOKEN", *key)
	}

	cfg := configFromEnv()
	if *abacURL != "" {
		cfg.ABACURL = *abacURL
	}

	if *connectorID == "" || *capability == "" || *action == "" || *resource == "" {
		return connectorInvokePlan{}, fmt.Errorf("--connector, --capability, --action, and --resource are required")
	}
	if cfg.AuthorizationToken() == "" {
		return connectorInvokePlan{}, fmt.Errorf("KEI_RUNTIME_TOKEN or KEI_HARNESS_TOKEN is required")
	}
	if *traceID == "" {
		*traceID = uuid.NewString()
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
			HarnessToken:    cfg.AuthorizationToken(),
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
		},
		abacURL:    abacURLValue,
		abacSecret: secret,
		timeout:    time.Duration(*timeout) * time.Second,
	}, nil
}

// runConnector dispatches the connector subcommand.
func runConnector(args []string) int {
	if len(args) > 0 && args[0] == "invoke" {
		return runConnectorInvoke(args[1:])
	}
	fmt.Fprintln(os.Stderr, "Error: unknown connector command\n\nUsage: kei-proxy connector invoke --connector <id> --capability <name> --action <action> --resource <resource>")
	return 1
}

func runConnectorInvoke(args []string) int {
	plan, err := parseConnectorInvokeArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), plan.timeout)
	defer cancel()

	client := NewABACClient(plan.abacURL, plan.abacSecret, plan.timeout)
	resp, err := client.InvokeConnector(ctx, plan.req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if err := writeJSON(os.Stdout, resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Fail closed: anything other than an explicit allow is a failure.
	if resp.Decision != "allow" {
		return 1
	}
	return 0
}
