// Package invoke is `kei-proxy connector invoke`: it parses the command,
// asks the control plane's governed connector endpoint for a decision, and
// prints it. The root package supplies the runtime configuration (Env).
package invoke

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

	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
	"github.com/google/uuid"
)

// Request is the wire shape a harness sends to ABAC's governed
// connector invocation endpoint. Tenant/workspace/agent are resolved
// server-side from the harness token; the proxy only forwards the capability,
// the resource, and the identity-propagation context.
type Request struct {
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

// Response mirrors the ABAC invoke response. On an allow the
// envelope carries the full propagation chain as minted by the control plane;
// a deny carries a reason.
type Response struct {
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

// Env is the runtime configuration the command needs, taken from the root
// package's Config so the two never disagree.
type Env struct {
	RuntimeToken           string
	RuntimeControlPlaneURL string
	ABACURL                string
	ABACSecret             string
	// ProviderUserID is the default --provider-user ($KEI_PROXY_PROVIDER_USER).
	ProviderUserID string
	// Stdin is read for --input -.
	Stdin io.Reader
}

// isRuntime reports customer-runtime mode, which the runtime token decides.
func (e Env) isRuntime() bool { return e.RuntimeToken != "" }

// Client calls the control plane's governed connector endpoint.
type Client struct {
	baseURL string
	secret  string
	client  *http.Client
}

// NewClient returns a Client for baseURL. secret is sent as X-KEI-API-Key when
// set; customer runtimes never have one.
func NewClient(baseURL, secret string, timeout time.Duration) *Client {
	return &Client{baseURL: baseURL, secret: secret, client: &http.Client{Timeout: timeout}}
}

// Invoke calls the governed connector invocation endpoint. The proxy
// authenticates itself with X-KEI-API-Key (ADR-009) and fails closed on any
// non-200 status, so a rejected or unavailable engine never yields a decision
// the harness could act on.
func (c *Client) Invoke(ctx context.Context, req Request) (*Response, error) {
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

	var out Response
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
	req        Request
	abacURL    string
	abacSecret string
	timeout    time.Duration
	input      string
}

// parseConnectorInvokeArgs maps CLI flags and the identity-propagation
// environment to an execution plan. The harness token is taken from the
// environment, never from an argument.
func parseConnectorInvokeArgs(args []string, env Env) (connectorInvokePlan, error) {
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
	timeout := fs.Int("timeout", 30, "ABAC request timeout in seconds")
	inputArg := fs.String("input", "", "capability input: a JSON object, @<file>, or - for stdin (default {})")
	providerUser := fs.String("provider-user", "", "chat-platform identity, e.g. a WhatsApp E.164 number (default $KEI_PROXY_PROVIDER_USER)")

	if err := fs.Parse(args); err != nil {
		return connectorInvokePlan{}, err
	}

	if *userID == "" && *user != "" {
		*userID = *user
	}
	cfg := env
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

	if *invokingSubject == "" {
		*invokingSubject = *userID
	}
	if *providerUser == "" {
		*providerUser = env.ProviderUserID
	}

	// Customer runtimes relay the self-authenticating request through the
	// public control-plane URL and never receive ABAC_API_SECRET.
	abacURLValue, secret := cfg.ABACURL, cfg.ABACSecret
	if cfg.isRuntime() {
		abacURLValue = cfg.RuntimeControlPlaneURL
		secret = ""
	}

	return connectorInvokePlan{
		req: Request{
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
		input:      *inputArg,
	}, nil
}

// Run executes `connector invoke` with args (after "invoke"). It prints the
// decision JSON to stdout and exits non-zero on anything but an allow.
func Run(args []string, env Env, stdout, stderr io.Writer) int {
	plan, err := parseConnectorInvokeArgs(args, env)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	// The input is shape-checked here, before the control plane is asked
	// anything; only its digest leaves the runtime.
	raw, err := input.Read(plan.input, env.Stdin)
	if err == nil {
		_, plan.req.InputDigest, err = input.Canonicalize(raw)
	}
	if err != nil {
		fmt.Fprintln(stderr, "Error: --input must be one JSON object of at most 16 KiB")
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), plan.timeout)
	defer cancel()

	client := NewClient(plan.abacURL, plan.abacSecret, plan.timeout)
	resp, err := client.Invoke(ctx, plan.req)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	if err := writeJSON(stdout, resp); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	// Fail closed: anything other than an explicit allow is a failure.
	if resp.Decision != "allow" {
		return 1
	}
	return 0
}

// envOr and writeJSON mirror the root package's helpers of the same names.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func writeJSON(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}
