package connectorruntime

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RuntimeIdentity is the authoritative installation scope returned for a
// customer-hosted runtime. These fields are observed from Kei; configuration
// values such as KEI_ORG_ID are intentionally not part of this contract.
type RuntimeIdentity struct {
	ID    string `json:"id"`
	OrgID string `json:"org_id"`
	// WorkspaceID is the workspace the authenticating harness key is bound to.
	// It is a pointer because the server omits the field for a legacy key that
	// carries no workspace; the distinction between absent and empty matters
	// for scope resolution.
	WorkspaceID *string `json:"workspace_id,omitempty"`
	// AgentID is the legacy/default assignment. New runtimes may use Agents
	// to route to any assigned agent and leave this field empty.
	AgentID       string         `json:"agent_id,omitempty"`
	Agents        []RuntimeAgent `json:"agents,omitempty"`
	Platform      string         `json:"platform"`
	Status        string         `json:"status"`
	BindingStatus string         `json:"binding_status"`
}

type RuntimeAgent struct {
	InstallationID string    `json:"installation_id"`
	AgentID        string    `json:"agent_id"`
	IsDefault      bool      `json:"is_default"`
	CreatedAt      time.Time `json:"created_at"`
}

// WhoamiFailureCategory distinguishes why a WhoAmI call failed, without
// leaking the token or any secret material.
type WhoamiFailureCategory int

const (
	WhoamiFailureTransport  WhoamiFailureCategory = iota + 1
	WhoamiFailureHTTPStatus WhoamiFailureCategory = iota + 1
	WhoamiFailureDecode     WhoamiFailureCategory = iota + 1
	WhoamiFailureIncomplete WhoamiFailureCategory = iota + 1
)

func (c WhoamiFailureCategory) String() string {
	switch c {
	case WhoamiFailureTransport:
		return "transport"
	case WhoamiFailureHTTPStatus:
		return "http_status"
	case WhoamiFailureDecode:
		return "decode"
	case WhoamiFailureIncomplete:
		return "incomplete"
	default:
		return "unknown"
	}
}

// WhoamiFailure carries a structured category alongside the wrapped error so
// callers can distinguish failure modes at startup or in diagnostics without
// inspecting error strings or leaking credentials.
type WhoamiFailure struct {
	Category   WhoamiFailureCategory
	StatusCode int // non-zero only for WhoamiFailureHTTPStatus
	Wrapped    error
}

func (f *WhoamiFailure) Error() string { return f.Wrapped.Error() }
func (f *WhoamiFailure) Unwrap() error { return f.Wrapped }

// DiagnoseWhoamiError extracts WhoamiFailureCategory from err, which may be
// wrapped in additional context. It returns WhoamiFailureTransport when err is
// nil or not a WhoamiFailure.
func DiagnoseWhoamiError(err error) WhoamiFailureCategory {
	var f *WhoamiFailure
	if errors.As(err, &f) {
		return f.Category
	}
	return WhoamiFailureTransport
}

type RuntimeClient interface {
	WhoAmI(ctx context.Context, token string) (*RuntimeIdentity, error)
	Heartbeat(ctx context.Context, token string, report HeartbeatReport) error
	RegisterCredentialSyncKey(ctx context.Context, token, storeID, keyID, publicKey string) error
	StartIdentityClaim(ctx context.Context, token string, request IdentityClaimStartRequest) (*IdentityClaimStartResponse, error)
}

type runtimeClient struct {
	baseURL string
	client  *http.Client
}

func NewRuntimeClient(baseURL string, timeout time.Duration) RuntimeClient {
	return &runtimeClient{baseURL: strings.TrimRight(baseURL, "/"), client: &http.Client{Timeout: timeout}}
}

func (c *runtimeClient) WhoAmI(ctx context.Context, token string) (*RuntimeIdentity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/runtime/whoami", nil)
	if err != nil {
		return nil, &WhoamiFailure{Category: WhoamiFailureTransport, Wrapped: fmt.Errorf("build runtime identity request: %w", err)}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := c.client.Do(req)
	if err != nil {
		return nil, &WhoamiFailure{Category: WhoamiFailureTransport, Wrapped: fmt.Errorf("runtime identity request failed: %w", err)}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, &WhoamiFailure{Category: WhoamiFailureHTTPStatus, StatusCode: response.StatusCode, Wrapped: fmt.Errorf("runtime identity request returned %d", response.StatusCode)}
	}
	var identity RuntimeIdentity
	if err := json.NewDecoder(response.Body).Decode(&identity); err != nil {
		return nil, &WhoamiFailure{Category: WhoamiFailureDecode, Wrapped: fmt.Errorf("decode runtime identity response: %w", err)}
	}
	if identity.ID == "" || identity.OrgID == "" || identity.Platform == "" {
		return nil, &WhoamiFailure{Category: WhoamiFailureIncomplete, Wrapped: fmt.Errorf("runtime identity response is incomplete")}
	}
	return &identity, nil
}

func (c *runtimeClient) Heartbeat(ctx context.Context, token string, report HeartbeatReport) error {
	body, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode runtime heartbeat: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/runtime/heartbeat", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build runtime heartbeat: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(req)
	if err != nil {
		return &HeartbeatFailure{Outcome: classifyTransportError(err), Wrapped: fmt.Errorf("runtime heartbeat request failed: %w", err)}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	if response.StatusCode != http.StatusNoContent {
		return &HeartbeatFailure{
			Outcome:    classifyHeartbeatStatus(response.StatusCode),
			StatusCode: response.StatusCode,
			RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"), time.Now()),
			Wrapped:    fmt.Errorf("runtime heartbeat returned %d", response.StatusCode),
		}
	}
	return nil
}

func (c *runtimeClient) RegisterCredentialSyncKey(ctx context.Context, token, storeID, keyID, publicKey string) error {
	body, err := json.Marshal(map[string]string{
		"credential_store_installation_id": storeID,
		"key_id":                           keyID,
		"public_key":                       publicKey,
	})
	if err != nil {
		return fmt.Errorf("encode credential sync key: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/api/v1/runtime/credential-sync-keys", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build credential sync key request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("credential sync key request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("credential sync key registration returned %d", response.StatusCode)
	}
	return nil
}

func credentialSyncPublicKey(encodedPrivateKey string) (string, error) {
	privateBytes, err := base64.RawStdEncoding.DecodeString(encodedPrivateKey)
	if err != nil {
		privateBytes, err = base64.StdEncoding.DecodeString(encodedPrivateKey)
	}
	if err != nil || len(privateBytes) != 32 {
		return "", errors.New("invalid credential sync private key")
	}
	key, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return "", errors.New("invalid credential sync private key")
	}
	return base64.RawStdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// bootstrapRuntime proves the runtime credential resolves to an installation
// before normal proxy work begins and records a liveness heartbeat. It does
// not turn a pending installation active; only the verified deployment flow
// may perform that lifecycle transition.
func bootstrapRuntime(ctx context.Context, cfg Config, timeout time.Duration) (*RuntimeIdentity, error) {
	if !cfg.IsRuntime() {
		return nil, nil
	}
	return bootstrapRuntimeWithClient(ctx, cfg, timeout, NewRuntimeClient)
}
