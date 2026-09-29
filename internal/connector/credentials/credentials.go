// Package credentials resolves a connector's credential for one allowed
// invocation (docs/connector-execution-contract.md, section 3). There are two
// paths and they never mix:
//
//   - opaque_ref (shared secret): the connector's opaque reference is read
//     from the tenant secret store, the same store model profiles use.
//   - oauth (user-delegated): the access token the catalog proxied in its
//     invoke response for this call (D2). It is accepted only over TLS and
//     before its use-by time, and is never persisted or printed.
//
// Every failure is an *Error carrying a contract reason code; no error text
// ever contains a credential, a reference, or a token.
package credentials

import (
	"context"
	"net"
	"net/url"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
)

// Source is the connector's typed credential source.
type Source string

const (
	SourceOAuth     Source = "oauth"
	SourceOpaqueRef Source = "opaque_ref"
)

// DefaultTimeout bounds one secret-store lookup.
const DefaultTimeout = 5 * time.Second

// Store reads a secret value; the runtime's SecretStore satisfies it.
type Store interface {
	Get(ctx context.Context, backend, ref string) (*string, error)
}

// OAuthToken is the access token the catalog proxies for one allowed call.
// It encodes and prints as a placeholder so it cannot be re-emitted by
// accident.
type OAuthToken struct {
	AccessToken        string    `json:"access_token"`
	TokenType          string    `json:"token_type"`
	ExpiresAt          time.Time `json:"expires_at"`
	AccountEmailDigest string    `json:"account_email_digest,omitempty"`
}

func (OAuthToken) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }
func (OAuthToken) String() string               { return "[REDACTED]" }
func (t OAuthToken) GoString() string           { return t.String() }

// Error is a fail-closed resolution outcome with a contract reason code.
type Error struct {
	Code   string
	Reason string
}

func (e *Error) Error() string { return e.Code + ": " + e.Reason }

func deny(code, reason string) *Error { return &Error{Code: code, Reason: reason} }

// Request names the credential for one invocation.
type Request struct {
	// Source is the connector's credential source; empty means opaque_ref.
	Source Source
	// Backend and Ref locate an opaque_ref secret.
	Backend string
	Ref     string
	// OAuth is the token from the catalog's invoke response, if any.
	OAuth *OAuthToken
	// ControlPlaneURL is where OAuth came from; it must be TLS.
	ControlPlaneURL string
}

// Resolver resolves credentials. BackendUnavailable classifies a store error
// as "this backend is not usable here" rather than "this secret is missing".
type Resolver struct {
	Store              Store
	BackendUnavailable func(error) bool
	Now                func() time.Time
	Timeout            time.Duration
}

// Resolve returns the credential value for req, or an *Error.
func (r Resolver) Resolve(ctx context.Context, req Request) (string, error) {
	switch req.Source {
	case SourceOAuth:
		return r.oauth(req)
	case SourceOpaqueRef, "":
		return r.sharedSecret(ctx, req)
	}
	return "", deny("descriptor_invalid", "unknown credential source")
}

func (r Resolver) oauth(req Request) (string, error) {
	if req.OAuth == nil || req.OAuth.AccessToken == "" {
		return "", deny("descriptor_invalid", "oauth connector allow without a token")
	}
	if !SecureControlPlane(req.ControlPlaneURL) {
		return "", deny("insecure_transport", "oauth token received over an insecure channel")
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	if !now().Before(req.OAuth.ExpiresAt) {
		return "", deny("oauth_token_expired", "oauth token is past its use-by time")
	}
	return req.OAuth.AccessToken, nil
}

func (r Resolver) sharedSecret(ctx context.Context, req Request) (string, error) {
	if req.OAuth != nil {
		return "", deny("descriptor_invalid", "opaque_ref connector allow carried a token")
	}
	if r.Store == nil || req.Backend == "" {
		return "", deny("credential_backend_unavailable", "credential backend is not available")
	}
	if contract.ValidateCredentialRef(req.Ref) != nil {
		return "", deny("credential_unavailable", "credential reference is invalid")
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	value, err := r.Store.Get(lookupCtx, req.Backend, req.Ref)
	if err != nil {
		if r.BackendUnavailable != nil && r.BackendUnavailable(err) {
			return "", deny("credential_backend_unavailable", "credential backend is not available")
		}
		return "", deny("credential_unavailable", "credential is not available")
	}
	if value == nil || *value == "" {
		return "", deny("credential_unavailable", "credential is not available")
	}
	return *value, nil
}

// SecureControlPlane reports whether a token may be accepted from the control
// plane at raw: https, or a loopback host for local tests.
func SecureControlPlane(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme == "https" && u.Host != "" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
