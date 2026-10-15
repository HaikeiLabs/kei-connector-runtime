// Package obo is the runtime's generic on_behalf_of grant (ADR-036 amendment
// 2026-10-15, HAI-669): it exchanges a signed-in user's Entra token for a
// token whose audience is a connector's API resource, using the
// organization's own app registration. Everything provider-shaped (tenant,
// client ID, resource, delegated scopes, client secret reference) comes from
// the connector's bundle descriptor; there is no provider code here.
//
// The client secret, the user's assertion and the exchanged token are never
// logged, audited, written to disk or put in an error. The exchanged token
// lives only in this process's memory.
package obo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/mcproute"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

const (
	// DefaultAuthority is the Microsoft Entra login authority; the token
	// endpoint is <authority>/<tenant id>/oauth2/v2.0/token.
	DefaultAuthority = "https://login.microsoftonline.com"
	// DefaultExpirySkew is how long before its expiry a cached token is
	// exchanged again.
	DefaultExpirySkew = 2 * time.Minute
	// DefaultTimeout bounds one token request.
	DefaultTimeout = 10 * time.Second

	grantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	maxResponseBytes   = 64 << 10
)

// Descriptors returns the bundle in force's descriptor for a connector.
type Descriptors interface {
	ConnectorDescriptor(id string) (policybundle.Connector, bool)
}

// SecretResolver resolves an opaque_ref descriptor's credential from the
// tenant credential store (invoke.SecretResolver in serve). The exchanger
// passes the descriptor with credential_ref set to the on_behalf_of block's
// client_secret_ref. An *Error it returns keeps its code; any other error is
// credential_unavailable.
type SecretResolver interface {
	Resolve(ctx context.Context, c policybundle.Connector) (string, error)
}

// Config configures an Exchanger. Descriptors and Secrets are required.
type Config struct {
	Descriptors Descriptors
	Secrets     SecretResolver
	// Client sends the token request; nil means an SSRF-guarded client
	// (ADR-036 §4.10 dial rules, no proxy, no redirects). Tests only.
	Client *http.Client
	// Authority overrides DefaultAuthority. Tests only; it must be https.
	Authority string
	// Skew overrides DefaultExpirySkew.
	Skew   time.Duration
	Now    func() time.Time
	Logger *slog.Logger
}

// Error is a fail-closed exchange outcome. It never carries the client
// secret, the assertion, the exchanged token or a token endpoint response
// body.
type Error struct {
	Code   string
	Reason string
}

func (e *Error) Error() string { return e.Code + ": " + e.Reason }

// Reason codes.
const (
	CodeDescriptorInvalid     = "descriptor_invalid"
	CodeAssertionInvalid      = "assertion_invalid"
	CodeCredentialUnavailable = "credential_unavailable"
	CodeExchangeFailed        = "exchange_failed"
	CodeAudienceMismatch      = "credential_audience_mismatch"
	CodeClaimsMismatch        = "credential_claims_mismatch"
)

func fail(code, reason string) *Error { return &Error{Code: code, Reason: reason} }

// Exchanger runs on_behalf_of exchanges and caches their tokens in memory,
// per (subject, connector, resource and scopes).
type Exchanger struct {
	descriptors Descriptors
	secrets     SecretResolver
	client      *http.Client
	authority   string
	skew        time.Duration
	now         func() time.Time
	log         *slog.Logger

	mu sync.Mutex
	// configs is each connector's exchange configuration as last seen; a
	// change purges the connector's entries.
	configs map[string]string
	cache   map[cacheKey]cacheEntry
}

type cacheKey struct {
	subject   string
	connector string
	// config is the connector's resource, scopes, tenant and client.
	config string
}

type cacheEntry struct {
	token  string
	oid    string
	expiry time.Time
}

// New returns an Exchanger.
func New(cfg Config) *Exchanger {
	e := &Exchanger{
		descriptors: cfg.Descriptors,
		secrets:     cfg.Secrets,
		client:      cfg.Client,
		authority:   cfg.Authority,
		skew:        cfg.Skew,
		now:         cfg.Now,
		log:         cfg.Logger,
		configs:     map[string]string{},
		cache:       map[cacheKey]cacheEntry{},
	}
	if e.client == nil {
		e.client = guardedClient()
	}
	if e.authority == "" {
		e.authority = DefaultAuthority
	}
	if e.skew <= 0 {
		e.skew = DefaultExpirySkew
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.log == nil {
		e.log = slog.Default()
	}
	return e
}

// guardedClient is the default token client: the MCP route's dial guard on
// every connection, no environment proxy, and no redirects.
func guardedClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: DefaultTimeout,
		Control: mcproute.GuardedDialControl,
	}
	return &http.Client{
		Timeout:   DefaultTimeout,
		Transport: &http.Transport{Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Exchange returns an access token for connectorID's resource acting as the
// user whose Entra token is assertion, and when it expires. subject is the
// session subject the token is cached for. The assertion is used for this
// exchange only and is not kept.
func (e *Exchanger) Exchange(ctx context.Context, subject, connectorID, assertion string) (string, time.Time, error) {
	token, expiry, err := e.exchange(ctx, subject, connectorID, assertion)
	if err != nil {
		var xe *Error
		if errors.As(err, &xe) {
			e.log.Warn("on_behalf_of exchange denied", "connector_id", connectorID, "reason_code", xe.Code)
		}
		return "", time.Time{}, err
	}
	return token, expiry, nil
}

func (e *Exchanger) exchange(ctx context.Context, subject, connectorID, assertion string) (string, time.Time, error) {
	if subject == "" {
		return "", time.Time{}, fail(CodeAssertionInvalid, "no session subject")
	}
	d, err := e.descriptor(connectorID)
	if err != nil {
		e.purge(connectorID)
		return "", time.Time{}, err
	}
	o := d.OnBehalfOf
	config := exchangeConfig(o)
	e.observe(connectorID, config)

	oid, err := assertionUser(assertion, o.TenantID)
	if err != nil {
		return "", time.Time{}, err
	}
	key := cacheKey{subject: subject, connector: connectorID, config: config}
	now := e.now()
	if entry, ok := e.cached(key); ok && entry.oid == oid && now.Add(e.skew).Before(entry.expiry) {
		return entry.token, entry.expiry, nil
	}

	secretDescriptor := d
	secretDescriptor.CredentialSource, secretDescriptor.CredentialRef = string(contract.CredentialSourceOpaqueRef), o.ClientSecretRef
	secret, err := e.secrets.Resolve(ctx, secretDescriptor)
	if err != nil {
		var xe *Error
		if errors.As(err, &xe) {
			return "", time.Time{}, xe
		}
		return "", time.Time{}, fail(CodeCredentialUnavailable, "the client secret is not available")
	}

	token, expiresIn, err := e.request(ctx, o, secret, assertion)
	if err != nil {
		return "", time.Time{}, err
	}
	if err := checkClaims(token, o, oid); err != nil {
		return "", time.Time{}, err
	}
	expiry := now.Add(expiresIn)
	if !now.Add(e.skew).Before(expiry) {
		return "", time.Time{}, fail(CodeExchangeFailed, "the exchanged token expires too soon")
	}
	e.store(key, cacheEntry{token: token, oid: oid, expiry: expiry})
	return token, expiry, nil
}

// descriptor returns connectorID's descriptor if it is a valid on_behalf_of
// descriptor under the contract.
func (e *Exchanger) descriptor(connectorID string) (policybundle.Connector, error) {
	if e.descriptors == nil || connectorID == "" {
		return policybundle.Connector{}, fail(CodeDescriptorInvalid, "the policy bundle has no descriptor for this connector")
	}
	d, ok := e.descriptors.ConnectorDescriptor(connectorID)
	if !ok || d.ID != connectorID {
		return policybundle.Connector{}, fail(CodeDescriptorInvalid, "the policy bundle has no descriptor for this connector")
	}
	if contract.CredentialSource(d.CredentialSource) != contract.CredentialSourceOnBehalfOf || d.OnBehalfOf == nil {
		return policybundle.Connector{}, fail(CodeDescriptorInvalid, "the connector does not use on_behalf_of")
	}
	if err := d.OnBehalfOf.Validate(d.ID); err != nil {
		return policybundle.Connector{}, fail(CodeDescriptorInvalid, "the on_behalf_of descriptor fails the contract")
	}
	if d.CredentialBackend == "" {
		return policybundle.Connector{}, fail(CodeDescriptorInvalid, "the descriptor names no credential backend")
	}
	return d, nil
}

// exchangeConfig identifies everything a cached token depends on.
func exchangeConfig(o *contract.OnBehalfOf) string {
	scopes := slices.Clone(o.Scopes)
	slices.Sort(scopes)
	return strings.Join([]string{o.Resource, o.TenantID, o.ClientID, strings.Join(scopes, " ")}, "\n")
}

// observe records connectorID's exchange configuration and purges its
// cached tokens when the configuration (the resource first of all) changed.
func (e *Exchanger) observe(connectorID, config string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if prev, ok := e.configs[connectorID]; ok && prev != config {
		e.purgeLocked(connectorID)
	}
	e.configs[connectorID] = config
}

func (e *Exchanger) purge(connectorID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.purgeLocked(connectorID)
}

func (e *Exchanger) purgeLocked(connectorID string) {
	delete(e.configs, connectorID)
	for k := range e.cache {
		if k.connector == connectorID {
			delete(e.cache, k)
		}
	}
}

func (e *Exchanger) cached(k cacheKey) (cacheEntry, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	entry, ok := e.cache[k]
	return entry, ok
}

func (e *Exchanger) store(k cacheKey, entry cacheEntry) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// The connector may have been purged while the request was in flight.
	if e.configs[k.connector] != k.config {
		return
	}
	e.cache[k] = entry
}

// request sends the jwt-bearer on_behalf_of grant to the tenant's token
// endpoint and returns the access token and its lifetime.
func (e *Exchanger) request(ctx context.Context, o *contract.OnBehalfOf, secret, assertion string) (string, time.Duration, error) {
	endpoint, err := url.Parse(strings.TrimSuffix(e.authority, "/") + "/" + url.PathEscape(o.TenantID) + "/oauth2/v2.0/token")
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Host == "" {
		return "", 0, fail(CodeExchangeFailed, "the token endpoint is not an https URL")
	}
	form := url.Values{
		"grant_type":          {grantTypeJWTBearer},
		"requested_token_use": {"on_behalf_of"},
		"client_id":           {o.ClientID},
		"client_secret":       {secret},
		"assertion":           {assertion},
		"scope":               {strings.Join(o.Scopes, " ")},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fail(CodeExchangeFailed, "the token request could not be built")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		// The transport error names the endpoint, never the form.
		return "", 0, fail(CodeExchangeFailed, "the token endpoint could not be reached")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", 0, fail(CodeExchangeFailed, "the token response could not be read")
	}
	if resp.StatusCode != http.StatusOK {
		// The body may echo the request; only the status is kept.
		return "", 0, fail(CodeExchangeFailed, "the token endpoint answered "+strconv.Itoa(resp.StatusCode))
	}
	var out struct {
		AccessToken string          `json:"access_token"`
		TokenType   string          `json:"token_type"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", 0, fail(CodeExchangeFailed, "the token response has no access token")
	}
	if out.TokenType != "" && !strings.EqualFold(out.TokenType, "Bearer") {
		return "", 0, fail(CodeExchangeFailed, "the token response is not a bearer token")
	}
	seconds, ok := expiresIn(out.ExpiresIn)
	if !ok {
		return "", 0, fail(CodeExchangeFailed, "the token response has no lifetime")
	}
	return out.AccessToken, time.Duration(seconds) * time.Second, nil
}

// expiresIn reads expires_in as a JSON number or numeric string.
func expiresIn(raw json.RawMessage) (int64, bool) {
	s := strings.Trim(string(raw), `"`)
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil && n > 0
}

// claims are the token claims the exchange checks. The tokens are read, not
// verified: the assertion is checked again by Entra, and the exchanged token
// arrived over TLS from the tenant's token endpoint. The checks keep a
// misconfigured or substituted token from being used.
type claims struct {
	Aud audience `json:"aud"`
	Scp string   `json:"scp"`
	Tid string   `json:"tid"`
	Oid string   `json:"oid"`
}

// audience is a JWT aud claim: a string or an array of strings.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

func readClaims(token string) (claims, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims{}, false
	}
	var c claims
	if json.Unmarshal(payload, &c) != nil {
		return claims{}, false
	}
	return c, true
}

// assertionUser returns the user (oid) of an assertion issued in tenant. An
// assertion from another tenant is never sent to the token endpoint.
func assertionUser(assertion, tenant string) (string, error) {
	c, ok := readClaims(assertion)
	if !ok {
		return "", fail(CodeAssertionInvalid, "the user token is not a JWT")
	}
	if !strings.EqualFold(c.Tid, tenant) {
		return "", fail(CodeAssertionInvalid, "the user token is from another tenant")
	}
	if c.Oid == "" {
		return "", fail(CodeAssertionInvalid, "the user token names no user")
	}
	return c.Oid, nil
}

// checkClaims fails closed unless the exchanged token is for the
// descriptor's resource, carries every requested scope, and is issued in the
// descriptor's tenant to the assertion's user.
func checkClaims(token string, o *contract.OnBehalfOf, oid string) error {
	c, ok := readClaims(token)
	if !ok {
		return fail(CodeExchangeFailed, "the exchanged token is not a JWT")
	}
	if !slices.Contains(c.Aud, o.Resource) {
		return fail(CodeAudienceMismatch, "the exchanged token is not for the connector's resource")
	}
	granted := strings.Fields(c.Scp)
	for _, scope := range o.Scopes {
		if !slices.Contains(granted, strings.TrimPrefix(scope, o.Resource+"/")) {
			return fail(CodeClaimsMismatch, fmt.Sprintf("the exchanged token lacks a requested scope (%d requested)", len(o.Scopes)))
		}
	}
	if !strings.EqualFold(c.Tid, o.TenantID) {
		return fail(CodeClaimsMismatch, "the exchanged token is from another tenant")
	}
	if c.Oid == "" || !strings.EqualFold(c.Oid, oid) {
		return fail(CodeClaimsMismatch, "the exchanged token is for another user")
	}
	return nil
}
