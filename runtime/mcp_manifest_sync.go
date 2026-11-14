package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/HaikeiLabs/kei-connector-contracts/manifest"
)

const (
	mcpManifestSyncPath           = "/v1/mcp-manifests:sync"
	mcpManifestSyncRequestSchema  = "kei.mcp-manifest-sync-request/v1"
	mcpManifestSyncResponseSchema = "kei.mcp-manifest-sync-response/v1"
	mcpManifestMaxBytes           = 4 << 20
)

type mcpManifestSyncRequest struct {
	Schema     string            `json:"schema"`
	ServerSlug string            `json:"server_slug"`
	Tools      []json.RawMessage `json:"tools"`
}

type mcpManifestSyncResponse struct {
	Schema       string `json:"schema"`
	ManifestHash string `json:"manifest_hash"`
	Status       string `json:"status"`
	Approved     bool   `json:"approved"`
	ReasonCode   string `json:"reason_code,omitempty"`
}

type catalogMCPManifest struct {
	ManifestHash string `json:"manifest_hash"`
	Status       string `json:"status"`
}

type mcpManifestSubmitter interface {
	SubmitMCPManifest(ctx context.Context, token, orgID, workspaceID, connectorID string, tools []json.RawMessage, manifestHash string) (catalogMCPManifest, error)
}

// SubmitMCPManifest registers MCP tool metadata under the authenticated
// installation's org/workspace scope. It submits metadata only; MCP calls and
// their arguments/results stay between the harness and the upstream server.
func (c *runtimeClient) SubmitMCPManifest(ctx context.Context, token, orgID, workspaceID, connectorID string, tools []json.RawMessage, manifestHash string) (catalogMCPManifest, error) {
	body, err := json.Marshal(struct {
		Tools        []json.RawMessage `json:"tools"`
		ManifestHash string            `json:"manifest_hash"`
	}{Tools: tools, ManifestHash: manifestHash})
	if err != nil {
		return catalogMCPManifest{}, fmt.Errorf("encode MCP manifest: %w", err)
	}
	if len(body) > mcpManifestMaxBytes {
		return catalogMCPManifest{}, fmt.Errorf("MCP manifest exceeds the catalog request limit")
	}
	path := "/api/v1/organizations/" + url.PathEscape(orgID) + "/workspaces/" + url.PathEscape(workspaceID) +
		"/data-connectors/" + url.PathEscape(connectorID) + "/tool-manifests"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return catalogMCPManifest{}, fmt.Errorf("build MCP manifest request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := *c.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(req)
	if err != nil {
		return catalogMCPManifest{}, fmt.Errorf("MCP manifest request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		return catalogMCPManifest{}, fmt.Errorf("MCP manifest submission returned HTTP %d", response.StatusCode)
	}
	var result catalogMCPManifest
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&result); err != nil {
		return catalogMCPManifest{}, fmt.Errorf("decode MCP manifest response: %w", err)
	}
	if result.ManifestHash != manifestHash || (result.Status != "candidate" && result.Status != "approved") {
		return catalogMCPManifest{}, fmt.Errorf("catalog returned an invalid MCP manifest acknowledgment")
	}
	return result, nil
}

func validMCPManifestHash(value string) bool {
	if len(value) != len("sha256:")+64 || value[:len("sha256:")] != "sha256:" {
		return false
	}
	for _, r := range value[len("sha256:"):] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func (l *LocalPDP) handleMCPManifestSync(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, code, message string) {
		writeRuntimeError(w, status, code, message)
	}
	if l.cfg == nil || l.cfg.Token() == "" {
		fail(http.StatusServiceUnavailable, "runtime_credentials_unavailable", "runtime credentials are unavailable")
		return
	}
	if l.mcpManifestRegistrar == nil {
		fail(http.StatusServiceUnavailable, "mcp_manifest_sync_unavailable", "MCP manifest sync is unavailable")
		return
	}
	var req mcpManifestSyncRequest
	if err := decodeSocketJSONLimit(w, r, &req, mcpManifestMaxBytes); err != nil || req.Schema != mcpManifestSyncRequestSchema {
		fail(http.StatusBadRequest, "invalid_mcp_manifest", "request must be a valid kei.mcp-manifest-sync-request/v1 object")
		return
	}
	if len(req.ServerSlug) < 2 || len(req.ServerSlug) > 48 || req.ServerSlug[0] < 'a' || req.ServerSlug[0] > 'z' {
		fail(http.StatusBadRequest, "invalid_mcp_manifest", "server_slug is invalid")
		return
	}
	for _, r := range req.ServerSlug[1:] {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_') {
			fail(http.StatusBadRequest, "invalid_mcp_manifest", "server_slug is invalid")
			return
		}
	}
	if len(req.Tools) == 0 {
		fail(http.StatusBadRequest, "invalid_mcp_manifest", "tools must contain at least one MCP tool")
		return
	}
	manifestHash, err := manifest.Hash(req.Tools)
	if err != nil {
		fail(http.StatusBadRequest, "invalid_mcp_manifest", "tools do not form a valid MCP manifest")
		return
	}

	identity := l.identity.Load()
	evaluator := l.evaluator.Load()
	if identity == nil || identity.OrgID == "" || identity.WorkspaceID == nil || *identity.WorkspaceID == "" || evaluator == nil {
		fail(http.StatusServiceUnavailable, "runtime_identity_unavailable", "verified runtime identity or policy bundle is unavailable")
		return
	}
	verified, ok := evaluator.Bundle()
	if !ok {
		fail(http.StatusServiceUnavailable, "policy_bundle_unavailable", "a verified policy bundle is required to sync MCP manifests")
		return
	}
	connector, ok := verified.MCPConnector(req.ServerSlug)
	if !ok || connector.ID == "" || connector.MCP == nil {
		fail(http.StatusNotFound, "mcp_connector_not_registered", "server_slug does not identify an MCP connector in the verified policy bundle")
		return
	}

	catalog, err := l.mcpManifestRegistrar.SubmitMCPManifest(r.Context(), l.cfg.Token(), identity.OrgID, *identity.WorkspaceID, connector.ID, req.Tools, manifestHash)
	if err != nil {
		fail(http.StatusBadGateway, "mcp_manifest_sync_failed", "catalog did not accept the MCP manifest")
		return
	}
	approved := catalog.Status == "approved" && connector.MCP.ApprovedManifestHash == manifestHash
	result := mcpManifestSyncResponse{
		Schema: mcpManifestSyncResponseSchema, ManifestHash: manifestHash, Status: catalog.Status, Approved: approved,
	}
	if !approved {
		if catalog.Status == "approved" {
			result.ReasonCode = "approved_manifest_not_loaded"
		} else {
			result.ReasonCode = "manifest_approval_required"
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
