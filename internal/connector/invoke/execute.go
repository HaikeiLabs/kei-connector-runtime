package invoke

// Tenant-side execution of an allowed connector call
// (docs/connector-execution-contract.md). On a catalog allow the runtime
// checks the descriptor against the request, decodes the input strictly,
// resolves the credential by exactly one path, runs the provider's connector
// package, and returns a size-capped result. Every failure is a deny with a
// contract reason code and no data.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/access"
	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-contracts/setup"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/credentials"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/crm"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/discord"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/github"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/gmail"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/googledrive"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/grafana"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/httpapi"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/linear"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/notion"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/tito"
)

const (
	maxProviderResponseBytes = 4 << 20
	maxResultBytes           = 1 << 20
	catalogTimeout           = 10 * time.Second
	providerTimeout          = 15 * time.Second
)

// Descriptor is the catalog's non-secret connector metadata on an allow, plus
// the secret backend an opaque_ref resolves in.
type Descriptor struct {
	contract.Metadata
	CredentialBackend string `json:"credential_backend,omitempty"`
	// CredentialSecretRef is where the control plane's connector secret
	// delivery wrote the credential (HAI-262), when it did.
	CredentialSecretRef string `json:"credential_secret_ref,omitempty"`
}

// connectors maps each provider Kei builds to its connector (contract
// section 1). A provider absent here is denied before any credential is
// resolved.
func (e Env) connectors() map[contract.Provider]connector.Connector {
	return map[contract.Provider]connector.Connector{
		contract.ProviderGmail:   gmail.Connector{},
		contract.ProviderGoogle:  googledrive.Connector{},
		contract.ProviderLinear:  linear.Connector{},
		contract.ProviderGitHub:  github.Connector{},
		contract.ProviderTito:    tito.Connector{},
		contract.ProviderNotion:  notion.Connector{},
		contract.ProviderDiscord: discord.Connector{},
		contract.ProviderGrafana: grafana.Connector{},
		contract.ProviderCRM:     crm.Connector{Store: e.Store, Key: e.AssertionKey},
		contract.ProviderHTTPAPI: httpapi.Connector{},
	}
}

// denial is a fail-closed outcome with a contract reason code.
type denial struct {
	code   string
	reason string
}

func deny(code, reason string) *denial { return &denial{code: code, reason: reason} }

// execution is what one call produced, for stdout and audit.
type execution struct {
	provider           contract.Provider
	meta               *contract.Metadata
	invocation         *contract.Invocation
	result             json.RawMessage
	credentialSubject  string
	accountEmailDigest string
	assertionKID       string
	statusClass        string
}

func (e Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// execute runs an allowed invocation. It returns the execution record even on
// a deny, so audit carries whatever was known.
func (e Env) execute(ctx context.Context, req Request, raw json.RawMessage, resp *Response, controlPlaneURL string) (*execution, *denial) {
	exec := &execution{}
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
		inv.IdempotencyKey != req.IdempotencyKey ||
		inv.TenantID != meta.TenantID || inv.WorkspaceID != meta.WorkspaceID {
		return exec, deny("descriptor_invalid", "descriptor does not match the request")
	}
	conn, in, d := e.prepare(req, raw, meta, inv)
	if d != nil {
		return exec, d
	}
	exec.credentialSubject = contract.CredentialSubject(meta, inv)

	credential, err := credentials.Resolver{
		Store: e.Store, BackendUnavailable: e.BackendUnavailable, Now: e.Now,
	}.Resolve(ctx, credentials.Request{
		Source: credentials.Source(meta.EffectiveCredentialSource()), Backend: resp.Connector.CredentialBackend,
		Ref: meta.CredentialRef, SecretRef: resp.Connector.CredentialSecretRef, OAuth: resp.OAuth, ControlPlaneURL: controlPlaneURL,
	})
	if err != nil {
		var ce *credentials.Error
		if errors.As(err, &ce) {
			return exec, deny(ce.Code, ce.Reason)
		}
		return exec, deny("credential_unavailable", "credential is not available")
	}
	if resp.OAuth != nil {
		exec.accountEmailDigest = resp.OAuth.AccountEmailDigest
	}
	_, d = e.run(ctx, conn, meta, inv, in, credential, exec)
	return exec, d
}

// prepare runs every check that needs no credential: the provider is one
// this runtime executes, the metadata is valid, the capability is declared and
// executable here, and the input decodes for it.
func (e Env) prepare(req Request, raw json.RawMessage, meta contract.Metadata, inv contract.Invocation) (connector.Connector, any, *denial) {
	conn, ok := e.connectors()[meta.Provider]
	if !ok {
		return nil, nil, deny("provider_not_supported", "provider is not supported by this runtime")
	}
	if err := setup.ValidateMetadata(meta); err != nil {
		return nil, nil, deny("descriptor_invalid", "connector metadata is invalid")
	}
	capability, ok := declaredCapability(meta, req.Capability)
	if !ok {
		return nil, nil, deny("descriptor_invalid", "capability is not declared on the connector")
	}
	// Writes run only where the contract's api mode lists them (every crm
	// write; linear issue.create and comment.create). A Linear write needs an
	// idempotency key: the connector derives the new entity's id from it, so
	// a replay cannot create a duplicate (contract section 10).
	if capability.Action != contract.ActionRead {
		if !access.APIWrite(meta.Provider, capability.Name) {
			return nil, nil, deny("capability_not_supported", "this write capability is not executed")
		}
		if meta.Provider != contract.ProviderCRM && inv.IdempotencyKey == "" {
			return nil, nil, deny("input_invalid", "writes require an idempotency key")
		}
	}
	if meta.AccountModel == contract.AccountModelDomainDelegation {
		return nil, nil, deny("account_model_not_supported", "domain-wide delegation is not executed yet")
	}
	in, err := input.Decode(string(meta.Provider), req.Capability, raw)
	if err != nil {
		return nil, nil, deny("input_invalid", "input does not match the capability schema")
	}
	// http_api: the catalog authorized exactly one resource, the request
	// path. Calling any other path would bypass per-resource policy, so this
	// is checked before a credential is fetched (HAI-256).
	if h, ok := in.(input.HTTPRequest); ok && !sameRequestPath(h.Path, inv.Resource) {
		return nil, nil, deny("input_invalid", "http_api path must equal the authorized resource")
	}
	return conn, in, nil
}

// run makes the provider call with credential and records its outcome on
// exec. It returns the provider's last HTTP status alongside any denial, so a
// caller can tell a rejected credential (401) from other failures.
func (e Env) run(ctx context.Context, conn connector.Connector, meta contract.Metadata, inv contract.Invocation, in any, credential string, exec *execution) (int, *denial) {
	providerCtx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()
	transport := &recordingTransport{base: e.ProviderTransport, limit: maxProviderResponseBytes}
	if transport.base == nil {
		transport.base = http.DefaultTransport
	}
	data, err := conn.Execute(providerCtx, connector.Call{
		Meta: meta, Invocation: inv, Input: in, Credential: credential,
		HTTPClient: &http.Client{Transport: transport}, LookupIP: e.LookupIP, Now: e.Now,
	})
	exec.statusClass = transport.statusClass(providerCtx)
	if meta.Provider == contract.ProviderCRM && transport.requests() > 0 {
		exec.assertionKID = e.AssertionKey.KID
	}
	transport.mu.Lock()
	status := transport.status
	transport.mu.Unlock()
	if err != nil {
		return status, classify(providerCtx, transport, err)
	}
	result, err := json.Marshal(data)
	if err != nil {
		return status, deny("provider_error", "result could not be encoded")
	}
	if len(result) > maxResultBytes {
		return status, deny("result_too_large", "result exceeds the size limit")
	}
	exec.result = result
	return status, nil
}

func declaredCapability(meta contract.Metadata, name string) (contract.Capability, bool) {
	for _, c := range meta.Capabilities {
		if c.Name == name {
			return c, true
		}
	}
	return contract.Capability{}, false
}

// classify maps a connector error to a reason code: the connector sentinels
// first, then the recorded provider status. Provider error text is never
// read or surfaced.
func classify(ctx context.Context, t *recordingTransport, err error) *denial {
	t.mu.Lock()
	calls, status, tooLarge := t.calls, t.status, t.tooLarge
	t.mu.Unlock()
	switch {
	case errors.Is(err, connector.ErrConfig):
		return deny("descriptor_invalid", "connector config is incomplete")
	case errors.Is(err, crm.ErrAssertionKey):
		return deny("assertion_key_unavailable", "service assertion key is not available")
	case tooLarge || errors.Is(err, connector.ErrTooLarge):
		return deny("result_too_large", "result exceeds the size limit")
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return deny("provider_timeout", "provider did not respond in time")
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return deny("provider_denied", "provider refused the credential")
	case status == http.StatusNotFound:
		return deny("provider_not_found", "provider resource was not found")
	case status == http.StatusTooManyRequests:
		return deny("provider_rate_limited", "provider rate limit reached")
	case errors.Is(err, connector.ErrInput) || calls == 0:
		return deny("input_invalid", "the provider rejected the resource or input")
	}
	return deny("provider_error", "provider call failed")
}

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

func (t *recordingTransport) requests() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.calls
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

type cappedBody struct {
	rc        io.ReadCloser
	remaining int64
	onExceed  func()
}

var errBodyTooLarge = errors.New("provider response exceeds the size limit")

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		// Probe one byte: a body that ends exactly at the limit is fine.
		var one [1]byte
		if n, _ := b.rc.Read(one[:]); n > 0 {
			b.onExceed()
			return 0, errBodyTooLarge
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

// sameRequestPath reports whether path is exactly the authorized resource and
// both are a plain absolute request path: a leading "/", no query, fragment,
// backslash, "." or ".." segment, percent-encoded dot, slash, or backslash,
// and no scheme or host. Nothing is normalized; any difference denies.
func sameRequestPath(path, resource string) bool {
	return path == resource && plainRequestPath(path)
}

func plainRequestPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "?#\\") {
		return false
	}
	lower := strings.ToLower(p)
	for _, encoded := range []string{"%2e", "%2f", "%5c"} {
		if strings.Contains(lower, encoded) {
			return false
		}
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	u, err := url.Parse(p)
	return err == nil && !u.IsAbs() && u.Host == ""
}
