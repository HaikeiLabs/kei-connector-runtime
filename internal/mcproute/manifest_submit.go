package mcproute

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/manifest"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// ManifestSubmitter sends an observed manifest the route could not verify to
// the catalog as a candidate for admin review (ADR-036 §5.4 step 1).
type ManifestSubmitter interface {
	Submit(ctx context.Context, connectorID, manifestHash string, tools []json.RawMessage) error
}

// submitTimeout bounds one candidate submission. It runs off the request path.
const submitTimeout = 10 * time.Second

// submitCandidate submits tools, the upstream listing of connector d, once
// per (connector, manifest_hash) while this process runs. A manifest that is
// invalid under §5.2 rule 6 is not submitted: the catalog would reject it. A
// failed submission is retried the next time the listing is observed.
func (h *Handler) submitCandidate(d policybundle.Connector, tools []json.RawMessage) {
	if h.config.Submitter == nil {
		return
	}
	hash, err := manifest.Hash(tools)
	if err != nil {
		return
	}
	canonical, err := canonicalTools(tools)
	if err != nil {
		return
	}
	key := d.ID + "|" + hash
	h.mu.Lock()
	if h.submitted[key] {
		h.mu.Unlock()
		return
	}
	h.submitted[key] = true
	h.mu.Unlock()

	h.submits.Add(1)
	go func() {
		defer h.submits.Done()
		ctx, cancel := context.WithTimeout(context.Background(), submitTimeout)
		defer cancel()
		if err := h.config.Submitter.Submit(ctx, d.ID, hash, canonical); err != nil {
			h.mu.Lock()
			delete(h.submitted, key)
			h.mu.Unlock()
			h.config.Logger.Warn("mcp_manifest_submit_failed", "slug", d.Slug, "connector_id", d.ID, "manifest_hash", hash, "error", err)
			return
		}
		h.config.Logger.Info("mcp_manifest_submitted", "slug", d.Slug, "connector_id", d.ID, "manifest_hash", hash)
	}()
}

// CatalogManifestClient submits candidates to the catalog's
// POST /api/v1/organizations/{org}/workspaces/{ws}/data-connectors/{id}/tool-manifests
// (kei-policy-catalog HAI-485), authenticated with the runtime token. The
// body is exactly {manifest_hash, tools}, the tools as canonical objects.
type CatalogManifestClient struct {
	// BaseURL is the control plane (KEI_RUNTIME_CONTROL_PLANE_URL).
	BaseURL      string
	RuntimeToken string
	// Scope returns the installation's org and workspace ids.
	Scope func() (orgID, workspaceID, installationID string)
	// HTTPClient defaults to a client with a 10 s timeout.
	HTTPClient *http.Client
}

// Submit posts one candidate. It fails without a request until the runtime
// identity names an org and workspace. Errors never quote the response.
func (c CatalogManifestClient) Submit(ctx context.Context, connectorID, manifestHash string, tools []json.RawMessage) error {
	var org, ws string
	if c.Scope != nil {
		org, ws, _ = c.Scope()
	}
	if org == "" || ws == "" || connectorID == "" {
		return errors.New("manifest submit: the runtime identity names no org and workspace yet")
	}
	canonical, err := canonicalTools(tools)
	if err != nil {
		return fmt.Errorf("manifest submit: %w", err)
	}
	body, err := json.Marshal(struct {
		ManifestHash string            `json:"manifest_hash"`
		Tools        []json.RawMessage `json:"tools"`
	}{manifestHash, canonical})
	if err != nil {
		return fmt.Errorf("manifest submit: %w", err)
	}
	endpoint := strings.TrimRight(c.BaseURL, "/") + "/api/v1/organizations/" + url.PathEscape(org) +
		"/workspaces/" + url.PathEscape(ws) + "/data-connectors/" + url.PathEscape(connectorID) + "/tool-manifests"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return errors.New("manifest submit: cannot build the request")
	}
	req.Header.Set("Authorization", "Bearer "+c.RuntimeToken)
	req.Header.Set("Content-Type", "application/json")
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: submitTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("manifest submit: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK: // a new candidate, or an idempotent resubmission
		return nil
	}
	return fmt.Errorf("manifest submit: catalog answered %d", resp.StatusCode)
}

// canonicalTools reduces tools to the §5.2 canonical objects
// {name, description, inputSchema}, as the catalog stores them.
func canonicalTools(tools []json.RawMessage) ([]json.RawMessage, error) {
	canon, err := manifest.Canonicalize(tools)
	if err != nil {
		return nil, err
	}
	out := make([]json.RawMessage, len(canon))
	for i, t := range canon {
		b, err := json.Marshal(map[string]any{"name": t.Name, "description": t.Description, "inputSchema": t.InputSchema})
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}
