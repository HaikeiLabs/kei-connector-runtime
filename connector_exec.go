package connectorruntime

// Tenant-side connector execution (docs/connector-execution-contract.md). On a
// catalog allow the runtime checks the descriptor, resolves the credential by
// exactly one path (a shared secret from the tenant secret store, or the OAuth
// token the catalog proxied for this call), runs the provider client from
// kei-connector-contracts, and returns a redacted, size-capped result. Every
// failure is a deny with a reason code and no data.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts"
	"github.com/HaikeiLabs/kei-connector-contracts/providers"
)

const (
	maxProviderResponseBytes = 4 << 20
	maxConnectorResultBytes  = 1 << 20
	credentialTimeout        = 5 * time.Second
	providerTimeout          = 15 * time.Second
)

// supportedConnectorProviders are the connectors Kei builds (contract
// section 1). Anything else is denied before a credential is resolved.
var supportedConnectorProviders = map[connectors.Provider]bool{
	connectors.ProviderGmail: true, connectors.ProviderGoogle: true,
	connectors.ProviderLinear: true, connectors.ProviderGitHub: true,
	connectors.ProviderTito: true, connectors.ProviderCRM: true,
	connectors.ProviderHTTPAPI: true,
}

// ConnectorDescriptor is the catalog's non-secret connector metadata on an
// allow, plus the secret backend its opaque_ref resolves in.
type ConnectorDescriptor struct {
	connectors.Metadata
	CredentialBackend string `json:"credential_backend,omitempty"`
}

// OAuthCredential is the access token the catalog proxies for one allowed
// call. It is never persisted or logged: it marshals and prints redacted.
type OAuthCredential struct {
	AccessToken        string    `json:"access_token"`
	TokenType          string    `json:"token_type"`
	ExpiresAt          time.Time `json:"expires_at"`
	AccountEmailDigest string    `json:"account_email_digest,omitempty"`
}

func (OAuthCredential) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }
func (OAuthCredential) String() string               { return "[REDACTED]" }
func (c OAuthCredential) GoString() string           { return c.String() }

// connectorRuntime holds the execution seams; tests inject fakes.
type connectorRuntime struct {
	secrets    SecretStore
	httpClient *http.Client
	lookupIP   func(context.Context, string) ([]net.IP, error)
	now        func() time.Time
	assertion  assertionKeyConfig
}

// connectorDeny is a fail-closed outcome with a contract reason code.
type connectorDeny struct {
	code   string
	reason string
}

func (d *connectorDeny) Error() string { return d.code + ": " + d.reason }

func deny(code, reason string) *connectorDeny { return &connectorDeny{code: code, reason: reason} }

// connectorExecution is what one call produced, for stdout and audit.
type connectorExecution struct {
	provider           connectors.Provider
	meta               *connectors.Metadata
	invocation         *connectors.Invocation
	result             json.RawMessage
	credentialSubject  string
	accountEmailDigest string
	assertionKID       string
	statusClass        string
}

func (r connectorRuntime) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// execute runs an allowed invocation. It returns the execution record even on
// a deny, so audit carries whatever was known.
func (r connectorRuntime) execute(ctx context.Context, req ConnectorInvokeRequest, input json.RawMessage, resp *ConnectorInvokeResponse, controlPlaneURL string) (*connectorExecution, *connectorDeny) {
	exec := &connectorExecution{}
	if resp.Connector == nil || resp.Envelope == nil {
		return exec, deny("descriptor_invalid", "allow without a connector descriptor")
	}
	if err := resp.Envelope.Validate(); err != nil {
		return exec, deny("descriptor_invalid", "envelope is invalid")
	}
	meta, inv := resp.Connector.Metadata, resp.Envelope.Invocation
	exec.provider, exec.meta, exec.invocation = meta.Provider, &meta, &inv
	if meta.ID != req.ConnectorID || inv.ConnectorID != req.ConnectorID || inv.Capability != req.Capability ||
		string(inv.Action) != req.Action || inv.Resource != req.Resource || inv.TraceID != req.TraceID ||
		inv.TenantID != meta.TenantID || inv.WorkspaceID != meta.WorkspaceID {
		return exec, deny("descriptor_invalid", "descriptor does not match the request")
	}
	if !supportedConnectorProviders[meta.Provider] {
		return exec, deny("provider_not_supported", "provider is not supported by this runtime")
	}
	if err := meta.Validate(); err != nil {
		return exec, deny("descriptor_invalid", "connector metadata is invalid")
	}
	capability, ok := declaredCapability(meta, req.Capability)
	if !ok {
		return exec, deny("descriptor_invalid", "capability is not declared on the connector")
	}
	if capability.Action != connectors.ActionRead {
		return exec, deny("capability_not_supported", "only read capabilities are executed")
	}
	if meta.AccountModel == connectors.AccountModelDomainDelegation {
		return exec, deny("account_model_not_supported", "domain-wide delegation is not executed yet")
	}
	decoded, err := decodeConnectorInput(meta.Provider, req.Capability, input)
	if err != nil {
		return exec, deny("input_invalid", "input does not match the capability schema")
	}
	inv.HTTP = decoded.http
	exec.credentialSubject = connectors.CredentialSubject(meta, inv)

	credential, d := r.resolveCredential(ctx, meta, resp, controlPlaneURL)
	if d != nil {
		return exec, d
	}
	if resp.OAuth != nil {
		exec.accountEmailDigest = resp.OAuth.AccountEmailDigest
	}

	var signer *assertionSigner
	if meta.Provider == connectors.ProviderCRM {
		credCtx, cancel := context.WithTimeout(ctx, credentialTimeout)
		signer, err = loadAssertionSigner(credCtx, r.secrets, r.assertion)
		cancel()
		if err != nil {
			return exec, deny("assertion_key_unavailable", "service assertion key is not available")
		}
		exec.assertionKID = signer.kid
	}

	providerCtx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()
	transport := &recordingTransport{base: r.baseTransport(), limit: maxProviderResponseBytes}
	client := &http.Client{Transport: transport}
	data, err := r.invokeProvider(providerCtx, client, meta, inv, decoded, credential, signer)
	exec.statusClass = transport.statusClass(providerCtx)
	if errors.Is(err, errCRMConfig) {
		return exec, deny("descriptor_invalid", "crm connector config is incomplete")
	}
	if err != nil {
		return exec, transport.classify(providerCtx, err)
	}
	result, err := json.Marshal(data)
	if err != nil {
		return exec, deny("provider_error", "result could not be encoded")
	}
	if len(result) > maxConnectorResultBytes {
		return exec, deny("result_too_large", "result exceeds the size limit")
	}
	exec.result = result
	return exec, nil
}

func declaredCapability(meta connectors.Metadata, name string) (connectors.Capability, bool) {
	for _, c := range meta.Capabilities {
		if c.Name == name {
			return c, true
		}
	}
	return connectors.Capability{}, false
}

// resolveCredential applies exactly one credential path for the connector's
// source and never falls back to the other.
func (r connectorRuntime) resolveCredential(ctx context.Context, meta connectors.Metadata, resp *ConnectorInvokeResponse, controlPlaneURL string) (string, *connectorDeny) {
	if meta.EffectiveCredentialSource() == connectors.CredentialSourceOAuth {
		if resp.OAuth == nil || resp.OAuth.AccessToken == "" {
			return "", deny("descriptor_invalid", "oauth connector allow without a token")
		}
		if !secureControlPlane(controlPlaneURL) {
			return "", deny("insecure_transport", "oauth token received over an insecure channel")
		}
		if !r.clock().Before(resp.OAuth.ExpiresAt) {
			return "", deny("oauth_token_expired", "oauth token is past its use-by time")
		}
		return resp.OAuth.AccessToken, nil
	}
	if resp.OAuth != nil {
		return "", deny("descriptor_invalid", "opaque_ref connector allow carried a token")
	}
	if r.secrets == nil || resp.Connector.CredentialBackend == "" {
		return "", deny("credential_backend_unavailable", "credential backend is not available")
	}
	if connectors.ValidateCredentialRef(meta.CredentialRef) != nil {
		return "", deny("credential_unavailable", "credential reference is invalid")
	}
	credCtx, cancel := context.WithTimeout(ctx, credentialTimeout)
	defer cancel()
	value, err := r.secrets.Get(credCtx, resp.Connector.CredentialBackend, meta.CredentialRef)
	if err != nil {
		if errors.Is(err, errSecretStore) {
			return "", deny("credential_backend_unavailable", "credential backend is not available")
		}
		return "", deny("credential_unavailable", "credential is not available")
	}
	if value == nil || *value == "" {
		return "", deny("credential_unavailable", "credential is not available")
	}
	return *value, nil
}

// secureControlPlane reports whether an OAuth token may be accepted from the
// control plane at raw: https, or a loopback host for local tests.
func secureControlPlane(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (r connectorRuntime) baseTransport() http.RoundTripper {
	if r.httpClient != nil && r.httpClient.Transport != nil {
		return r.httpClient.Transport
	}
	return http.DefaultTransport
}

func (r connectorRuntime) invokeProvider(ctx context.Context, client *http.Client, meta connectors.Metadata, inv connectors.Invocation, in decodedInput, credential string, signer *assertionSigner) (any, error) {
	resolver := staticCredentialResolver{value: credential}
	config := providers.RuntimeConfig{HTTPClient: client, Credentials: resolver}
	var c providers.Client
	switch meta.Provider {
	case connectors.ProviderGmail:
		c = providers.NewAuthenticatedGmail(config)
	case connectors.ProviderGoogle:
		c = providers.NewAuthenticatedGoogle(config)
	case connectors.ProviderGitHub:
		c = providers.NewAuthenticatedGitHub(config)
	case connectors.ProviderTito:
		c = providers.NewAuthenticatedTito(config)
	case connectors.ProviderLinear:
		c = providers.NewLinearRuntime(providers.HTTPLinearGraphQLTransport{Client: client}, staticLinearResolver{value: credential})
	case connectors.ProviderCRM:
		cfg, err := crmConfigFrom(meta)
		if err != nil {
			return nil, err
		}
		if err := (HTTPExecutor{LookupIP: r.lookupIP}).checkHost(ctx, cfg.baseURL.Hostname()); err != nil {
			return nil, err
		}
		assertion, err := signer.sign(crmAssertionClaims(signer, cfg, meta, inv, r.clock()))
		if err != nil {
			return nil, errInvocationRejected
		}
		return invokeCRM(ctx, client, cfg, credential, assertion)
	case connectors.ProviderHTTPAPI:
		return r.invokeHTTPAPI(ctx, client, meta, inv, credential)
	default:
		return nil, errInvocationRejected
	}
	result, err := c.Invoke(ctx, meta, inv, in.payload)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

// errInvocationRejected marks a failure before any provider request.
var errInvocationRejected = errors.New("invocation rejected before the provider call")

func (r connectorRuntime) invokeHTTPAPI(ctx context.Context, client *http.Client, meta connectors.Metadata, inv connectors.Invocation, credential string) (any, error) {
	out, err := (HTTPExecutor{Credentials: staticRefResolver{value: credential}, Client: client, LookupIP: r.lookupIP}).ExecuteHTTP(ctx, meta, inv)
	if err != nil {
		return nil, err
	}
	body := any(string(out.Body))
	if json.Valid(out.Body) {
		body = json.RawMessage(out.Body)
	}
	return map[string]any{"status_code": out.StatusCode, "headers": out.Headers, "body": body}, nil
}

type staticCredentialResolver struct{ value string }

func (s staticCredentialResolver) Resolve(context.Context, string, string, string, string) (string, error) {
	return s.value, nil
}

type staticLinearResolver struct{ value string }

func (s staticLinearResolver) Resolve(context.Context, string, providers.LinearCredentialScope) (string, error) {
	return s.value, nil
}

type staticRefResolver struct{ value string }

func (s staticRefResolver) Resolve(context.Context, string) (string, error) { return s.value, nil }

// recordingTransport records the provider's last HTTP status and caps each
// response body, so failures map to reason codes without reading provider
// error text.
type recordingTransport struct {
	base     http.RoundTripper
	limit    int64
	mu       sync.Mutex
	calls    int
	status   int
	tooLarge bool
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.calls++
	t.mu.Unlock()
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.status = resp.StatusCode
	t.mu.Unlock()
	resp.Body = &cappedBody{rc: resp.Body, remaining: t.limit, onExceed: func() {
		t.mu.Lock()
		t.tooLarge = true
		t.mu.Unlock()
	}}
	return resp, nil
}

func (t *recordingTransport) statusClass(ctx context.Context) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "timeout"
	case t.status >= 500:
		return "5xx"
	case t.status >= 400:
		return "4xx"
	case t.status >= 200:
		return "2xx"
	}
	return ""
}

func (t *recordingTransport) classify(ctx context.Context, err error) *connectorDeny {
	t.mu.Lock()
	calls, status, tooLarge := t.calls, t.status, t.tooLarge
	t.mu.Unlock()
	switch {
	case tooLarge || errors.Is(err, errHTTPResponseTooLarge):
		return deny("result_too_large", "provider response exceeds the size limit")
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return deny("provider_timeout", "provider did not respond in time")
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return deny("provider_denied", "provider refused the credential")
	case status == http.StatusNotFound:
		return deny("provider_not_found", "provider resource was not found")
	case status == http.StatusTooManyRequests:
		return deny("provider_rate_limited", "provider rate limit reached")
	case calls == 0 && !errors.Is(err, errHTTPReservedTarget):
		return deny("input_invalid", "the provider rejected the resource or input")
	}
	return deny("provider_error", "provider call failed")
}

type cappedBody struct {
	rc        io.ReadCloser
	remaining int64
	onExceed  func()
}

var errProviderBodyTooLarge = errors.New("provider response exceeds the size limit")

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		// Probe one byte: a body that ends exactly at the limit is fine.
		var one [1]byte
		if n, _ := b.rc.Read(one[:]); n > 0 {
			b.onExceed()
			return 0, errProviderBodyTooLarge
		}
		return 0, io.EOF
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.rc.Read(p)
	b.remaining -= int64(n)
	return n, err
}

func (b *cappedBody) Close() error { return b.rc.Close() }

func sha256Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
