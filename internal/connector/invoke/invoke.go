// Package invoke is `kei-proxy connector invoke`: it parses the command,
// validates the input, asks the control plane's governed connector endpoint
// for a decision, executes an allowed read through the provider's connector
// package, and prints one JSON result or deny. The root package supplies the
// runtime configuration and seams (Env).
package invoke

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/envelope"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/credentials"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/crm"
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

// Response mirrors the ABAC invoke response. On an allow the envelope
// carries the propagation chain minted by the control plane, the connector
// descriptor, and, for an OAuth connector, the token proxied for this call
// (D2). A deny carries a reason and, where known, a reason code.
type Response struct {
	Decision          string                  `json:"decision"`
	Reason            string                  `json:"reason,omitempty"`
	ReasonCode        string                  `json:"reason_code,omitempty"`
	Envelope          *envelope.Envelope      `json:"envelope,omitempty"`
	Connector         *Descriptor             `json:"connector,omitempty"`
	CredentialSubject string                  `json:"credential_subject,omitempty"`
	OAuth             *credentials.OAuthToken `json:"oauth,omitempty"`
	Enrollment        *json.RawMessage        `json:"enrollment,omitempty"`
	Connect           *json.RawMessage        `json:"connect,omitempty"`
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

	// Store and BackendUnavailable resolve opaque_ref credentials and the CRM
	// assertion key; AssertionKey names that key.
	Store              credentials.Store
	BackendUnavailable func(error) bool
	AssertionKey       crm.KeyConfig
	// Audit appends one audit record (a JSON line) to the local spool.
	Audit func(record []byte) error

	// Test seams: nil means the real network, DNS, and clock.
	CatalogTransport  http.RoundTripper
	ProviderTransport http.RoundTripper
	LookupIP          func(context.Context, string) ([]net.IP, error)
	Now               func() time.Time
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

func (c *Client) withTransport(t http.RoundTripper) *Client {
	if t != nil {
		c.client.Transport = t
	}
	return c
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

// output is the one JSON object written to stdout.
type output struct {
	Decision    string             `json:"decision"`
	ReasonCode  string             `json:"reason_code,omitempty"`
	Reason      string             `json:"reason,omitempty"`
	TraceID     string             `json:"trace_id,omitempty"`
	ConnectorID string             `json:"connector_id,omitempty"`
	Provider    string             `json:"provider,omitempty"`
	Capability  string             `json:"capability,omitempty"`
	Result      json.RawMessage    `json:"result,omitempty"`
	Audit       *outputAudit       `json:"audit,omitempty"`
	Enrollment  *json.RawMessage   `json:"enrollment,omitempty"`
	Connect     *json.RawMessage   `json:"connect,omitempty"`
	Envelope    *envelope.Envelope `json:"envelope,omitempty"`
}

type outputAudit struct {
	InputDigest  string `json:"input_digest,omitempty"`
	ResultDigest string `json:"result_digest,omitempty"`
	ResultBytes  int    `json:"result_bytes"`
}

// Run executes `connector invoke` with args (after "invoke"): validate the
// input locally, ask the control plane, execute on allow, and write exactly
// one JSON object. Exit 0 only for an executed allow; every other outcome is
// a deny.
func Run(args []string, env Env, stdout, stderr io.Writer) int {
	plan, err := parseConnectorInvokeArgs(args, env)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), plan.timeout)
	defer cancel()

	out := output{TraceID: plan.req.TraceID, ConnectorID: plan.req.ConnectorID, Capability: plan.req.Capability}
	var exec *execution
	finish := func(d *denial) int {
		code := 0
		if d != nil {
			out.Decision, out.ReasonCode, out.Reason, out.Result, out.Audit = "deny", d.code, d.reason, nil, nil
			code = 1
		}
		env.emitAudit(plan, exec, out, time.Since(started))
		if err := writeJSON(stdout, out); err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		return code
	}

	// The input is shape-checked here, before the control plane is asked
	// anything; only its digest leaves the runtime.
	raw, err := input.Read(plan.input, env.Stdin)
	var canonical json.RawMessage
	if err == nil {
		canonical, plan.req.InputDigest, err = input.Canonicalize(raw)
	}
	if err != nil {
		fmt.Fprintln(stderr, "Error: --input must be one JSON object of at most 16 KiB")
		return finish(deny("input_invalid", "input must be one JSON object of at most 16 KiB"))
	}
	out.Audit = &outputAudit{InputDigest: plan.req.InputDigest}

	catalogCtx, cancelCatalog := context.WithTimeout(ctx, catalogTimeout)
	resp, err := NewClient(plan.abacURL, plan.abacSecret, plan.timeout).withTransport(env.CatalogTransport).Invoke(catalogCtx, plan.req)
	cancelCatalog()
	if err != nil {
		fmt.Fprintln(stderr, "Error: connector decision unavailable (fail closed)")
		return finish(deny("catalog_unavailable", "the control plane did not return a decision"))
	}
	out.Enrollment, out.Connect, out.Envelope = resp.Enrollment, resp.Connect, resp.Envelope
	if resp.Decision != "allow" {
		return finish(deny(catalogReasonCode(resp), resp.Reason))
	}

	exec, d := env.execute(ctx, plan.req, canonical, resp, plan.abacURL)
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
// sent a well-formed one, otherwise enrollment or policy.
func catalogReasonCode(resp *Response) string {
	switch {
	case reasonCodePattern.MatchString(resp.ReasonCode):
		return resp.ReasonCode
	case resp.Enrollment != nil:
		return "enrollment_required"
	}
	return "policy_deny"
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
