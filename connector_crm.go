package connectorruntime

// The crm provider targets the MarketingSite Worker's governed endpoint,
// POST <base_url>/api/crm/v1/invoke (connector execution contract, section 5).
// Each call carries the connector's API key (shared secret) and a service
// assertion the runtime signs. Results are projected to a fixed Lead
// allowlist, so free text the Worker returns never leaves the runtime.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts"
	"github.com/google/uuid"
)

const crmInvokePath = "/api/crm/v1/invoke"

var errCRMConfig = errors.New("crm connector config is incomplete")

// crmLeadFields is the Lead allowlist returned to the harness.
var crmLeadFields = []string{"id", "company_name", "contact_name", "email", "role", "status", "priority", "source", "tier", "created_at", "updated_at"}

type crmConfig struct {
	baseURL          *url.URL
	audience         string
	allowedActions   []string
	allowedResources []string
}

func crmConfigFrom(meta connectors.Metadata) (crmConfig, error) {
	base, _ := meta.Config["base_url"].(string)
	aud, _ := meta.Config["assertion_audience"].(string)
	u, err := url.Parse(base)
	if base == "" || aud == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return crmConfig{}, errCRMConfig
	}
	return crmConfig{
		baseURL:          u,
		audience:         aud,
		allowedActions:   configStrings(meta.Config["allowed_actions"], []string{"read"}),
		allowedResources: configStrings(meta.Config["allowed_resources"], []string{"leads", "customers"}),
	}, nil
}

func configStrings(value any, fallback []string) []string {
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		return fallback
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return fallback
		}
		out = append(out, s)
	}
	return out
}

// crmAssertionClaims maps the catalog-minted envelope and descriptor onto the
// Worker's claimsSchema. requires_approval mirrors the Worker's fixed
// registry: every non-read CRM capability needs an approval.
func crmAssertionClaims(signer *assertionSigner, cfg crmConfig, meta connectors.Metadata, inv connectors.Invocation, now time.Time) map[string]any {
	capabilities := make([]map[string]any, 0, len(meta.Capabilities))
	for _, c := range meta.Capabilities {
		capabilities = append(capabilities, map[string]any{"name": c.Name, "action": string(c.Action), "requires_approval": c.Action != connectors.ActionRead})
	}
	claims := map[string]any{
		"iss": signer.issuer, "aud": cfg.audience,
		"iat": now.Unix(), "exp": now.Unix() + 60, "jti": uuid.NewString(),
		"tenant_id": inv.TenantID, "workspace_id": inv.WorkspaceID, "subject": inv.Subject,
		"agent_id": inv.AgentID, "connector_id": inv.ConnectorID,
		"provider": "crm", "connector_status": string(meta.Status),
		"capabilities": capabilities,
		"policy":       map[string]any{"allowed_actions": cfg.allowedActions, "allowed_resources": cfg.allowedResources},
		"capability":   inv.Capability, "action": string(inv.Action), "resource": inv.Resource,
		"trace_id": inv.TraceID,
	}
	if inv.IdempotencyKey != "" {
		claims["idempotency_key"] = inv.IdempotencyKey
	}
	if inv.ApprovalID != "" {
		claims["approval_id"] = inv.ApprovalID
	}
	return claims
}

// invokeCRM calls the Worker and returns the projected result. A non-200
// status is an error; the caller maps it by the recorded status.
func invokeCRM(ctx context.Context, client *http.Client, cfg crmConfig, apiKey, assertion string) (any, error) {
	endpoint := *cfg.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + crmInvokePath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, errors.New("build CRM request failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-KEI-API-Key", apiKey)
	req.Header.Set("Authorization", "Bearer "+assertion)
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		return nil, errors.New("CRM request failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("read CRM response failed")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("CRM request was not successful")
	}
	var out struct {
		Success bool `json:"success"`
		Data    struct {
			Records []map[string]any `json:"records"`
			Record  map[string]any   `json:"record"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil || !out.Success {
		return nil, errors.New("CRM response was not successful")
	}
	if out.Data.Record != nil {
		return map[string]any{"record": projectLead(out.Data.Record)}, nil
	}
	records := make([]map[string]any, 0, len(out.Data.Records))
	for _, r := range out.Data.Records {
		records = append(records, projectLead(r))
	}
	return map[string]any{"records": records}, nil
}

func projectLead(in map[string]any) map[string]any {
	out := make(map[string]any, len(crmLeadFields))
	for _, f := range crmLeadFields {
		if v, ok := in[f]; ok {
			out[f] = v
		}
	}
	return out
}
