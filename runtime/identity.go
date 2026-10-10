package runtime

import (
	"bytes"
	"context"
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

// RuntimeAgent is one agent assignment the runtime installation is scoped to.
type RuntimeAgent struct {
	InstallationID string    `json:"installation_id"`
	AgentID        string    `json:"agent_id"`
	IsDefault      bool      `json:"is_default"`
	CreatedAt      time.Time `json:"created_at"`
}

// DefaultAgentID returns the agent assigned as the default for this
// installation. The legacy top-level field remains authoritative when set;
// otherwise exactly one default assignment for this installation is required.
func (i *RuntimeIdentity) DefaultAgentID() string {
	if i == nil {
		return ""
	}
	if i.AgentID != "" {
		return i.AgentID
	}

	defaultID := ""
	for _, agent := range i.Agents {
		if !agent.IsDefault {
			continue
		}
		if agent.InstallationID != i.ID || agent.AgentID == "" || defaultID != "" {
			return ""
		}
		defaultID = agent.AgentID
	}
	return defaultID
}

// WhoamiFailureCategory is a coarse classification of the failure source.
type WhoamiFailureCategory int

const (
	WhoamiFailureTransport  WhoamiFailureCategory = iota + 1 // network / DNS / TLS
	WhoamiFailureHTTPStatus WhoamiFailureCategory = iota + 1 // non-200 status
	WhoamiFailureDecode     WhoamiFailureCategory = iota + 1 // JSON decode error
	WhoamiFailureIncomplete WhoamiFailureCategory = iota + 1 // missing required fields
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

// WhoamiFailure is a typed error from the whoami endpoint. Transport errors
// carry no HTTP status; HTTP errors carry status and may or may not have a
// useful body.
type WhoamiFailure struct {
	Category   WhoamiFailureCategory
	StatusCode int
	Wrapped    error
}

func (e *WhoamiFailure) Error() string { return e.Wrapped.Error() }

func (e *WhoamiFailure) Unwrap() error { return e.Wrapped }

// DiagnoseWhoamiError wraps an error in the most specific WhoamiFailure
// category when the callers know the concrete type would not add value.
func DiagnoseWhoamiError(err error) WhoamiFailureCategory {
	var f *WhoamiFailure
	if errors.As(err, &f) {
		return f.Category
	}
	return WhoamiFailureTransport
}

// RuntimeClient is the HTTP client for the Kei runtime control-plane API.
type RuntimeClient interface {
	WhoAmI(ctx context.Context, token string) (*RuntimeIdentity, error)
	Heartbeat(ctx context.Context, token string, report HeartbeatReport) error
	RegisterCredentialSyncKey(ctx context.Context, token, storeID, keyID, publicKey string) error
	StartIdentityClaim(ctx context.Context, token string, request IdentityClaimStartRequest) (*IdentityClaimStartResponse, error)
	SyncTools(ctx context.Context, token string, manifest *ToolManifest) error
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/runtime:heartbeat", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build runtime heartbeat: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(req)
	if err != nil {
		return &HeartbeatFailure{Outcome: ClassifyHeartbeatTransportError(err), Wrapped: fmt.Errorf("runtime heartbeat request failed: %w", err)}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	if response.StatusCode != http.StatusNoContent {
		return &HeartbeatFailure{
			Outcome:    ClassifyHeartbeatStatus(response.StatusCode),
			StatusCode: response.StatusCode,
			RetryAfter: ParseHeartbeatRetryAfter(response.Header.Get("Retry-After"), time.Now()),
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

const (
	ToolManifestProtocolHeader  = "X-Kei-Tool-Manifest-Schema"
	ToolManifestSupportedHeader = "X-Kei-Supported-Tool-Manifest-Schemas"
)

func toolManifestMediaType(schema string) string {
	switch schema {
	case ToolManifestSchemaV2:
		return "application/vnd.kei.tool-manifest.v2+json"
	case ToolManifestSchemaV3:
		return "application/vnd.kei.tool-manifest.v3+json"
	case ToolManifestSchemaV4:
		return "application/vnd.kei.tool-manifest.v4+json"
	default:
		return ""
	}
}

// ToolSyncResponse is the catalog response for PUT /api/v1/runtime/tools.
type ToolSyncResponse struct {
	Added     int `json:"added"`
	Updated   int `json:"updated"`
	Removed   int `json:"removed"`
	Unchanged int `json:"unchanged"`
}

// SyncTools proposes the exact manifest schema in Accept. V3 and v4 require
// an explicit catalog acknowledgment; missing acknowledgments remain
// compatible only for v2 peers predating negotiation.
func (c *runtimeClient) SyncTools(ctx context.Context, token string, manifest *ToolManifest) error {
	if manifest == nil || (manifest.Schema != ToolManifestSchemaV2 && manifest.Schema != ToolManifestSchemaV3 && manifest.Schema != ToolManifestSchemaV4) {
		return fmt.Errorf("unsupported tool manifest protocol")
	}
	if err := validateToolManifestSyncMode(manifest.Schema, manifest.SyncMode); err != nil {
		return fmt.Errorf("invalid tool manifest sync mode")
	}
	if manifest.Schema == ToolManifestSchemaV4 {
		if err := validateToolManifest(manifest); err != nil {
			return fmt.Errorf("invalid v4 tool manifest")
		}
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode tool manifest: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/api/v1/runtime/tools", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build tool sync request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, "+toolManifestMediaType(manifest.Schema))
	response, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("tool sync request failed: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	if response.StatusCode == http.StatusConflict {
		return &ToolSyncError{StatusCode: response.StatusCode, Conflict: true}
	}
	if response.StatusCode != http.StatusOK {
		return &ToolSyncError{StatusCode: response.StatusCode}
	}
	ack := response.Header.Get(ToolManifestProtocolHeader)
	if ack != "" && ack != manifest.Schema {
		return fmt.Errorf("tool sync protocol acknowledgment mismatch")
	}
	supportedHeader := response.Header.Get(ToolManifestSupportedHeader)
	if supportedHeader != "" && !containsManifestSchema(supportedHeader, manifest.Schema) {
		return fmt.Errorf("tool sync protocol is not in the catalog's supported schemas")
	}
	if supportedHeader != "" && (ack != manifest.Schema || response.Header.Get("Content-Type") != "application/json") {
		return fmt.Errorf("tool sync protocol was advertised but not explicitly selected")
	}
	if (manifest.Schema == ToolManifestSchemaV3 || manifest.Schema == ToolManifestSchemaV4) && (ack != manifest.Schema || !containsManifestSchema(supportedHeader, manifest.Schema) || response.Header.Get("Content-Type") != "application/json") {
		return fmt.Errorf("tool sync protocol was not explicitly negotiated")
	}
	return nil
}

func containsManifestSchema(header, schema string) bool {
	for _, value := range strings.Split(header, ",") {
		if strings.TrimSpace(value) == schema {
			return true
		}
	}
	return false
}

// ToolSyncError is a non-fatal error from SyncTools. Callers log it and
// continue bootstrap.
type ToolSyncError struct {
	StatusCode int
	Conflict   bool
	Wrapped    error
}

func (e *ToolSyncError) Error() string {
	if e.Wrapped != nil {
		return e.Wrapped.Error()
	}
	if e.Conflict {
		return fmt.Sprintf("tool sync conflict (HTTP %d)", e.StatusCode)
	}
	return fmt.Sprintf("tool sync failed (HTTP %d)", e.StatusCode)
}

func (e *ToolSyncError) Unwrap() error { return e.Wrapped }
