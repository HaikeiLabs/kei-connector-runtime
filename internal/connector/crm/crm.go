// Package crm is the crm connector. It targets the MarketingSite Worker's
// governed endpoint, POST <base_url>/api/crm/v1/invoke (contract section 5,
// HAI-221). Each call carries the connector's API key (shared secret) and a
// service assertion the runtime signs with its installation key (D3).
// It executes lead.read, investor.list and investor.read (HAI-210). Results
// are projected to a fixed Lead or Investor allowlist, so free text the
// Worker returns never leaves the runtime.
package crm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/credentials"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/httpapi"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
	"github.com/google/uuid"
)

const invokePath = "/api/crm/v1/invoke"

// leadFields is the Lead allowlist returned to the harness.
var leadFields = []string{"id", "company_name", "contact_name", "email", "role", "status", "priority", "source", "tier", "created_at", "updated_at"}

// investorFields is the Investor allowlist returned to the harness.
var investorFields = []string{"id", "name", "firm", "email", "stage", "created_at", "updated_at"}

var investorResource = regexp.MustCompile(`^investors/[^/]+$`)

// request is one checked crm read: the body sent to the Worker and the
// allowlist its records are projected to.
type request struct {
	body   []byte
	fields []string
}

// requestFor checks the input type and resource against the capability.
// Empty inputs send {}; investor.list sends its input as the body's data
// (contract section 5).
func requestFor(inv contract.Invocation, in any) (request, error) {
	_, empty := in.(input.Empty)
	switch inv.Capability {
	case "lead.read":
		if empty {
			return request{body: []byte("{}"), fields: leadFields}, nil
		}
	case "investor.read":
		if empty && investorResource.MatchString(inv.Resource) {
			return request{body: []byte("{}"), fields: investorFields}, nil
		}
	case "investor.list":
		if list, ok := in.(input.CRMInvestorList); ok && inv.Resource == "investors" {
			body, err := json.Marshal(map[string]any{"data": list})
			if err != nil {
				return request{}, connector.ErrInput
			}
			return request{body: body, fields: investorFields}, nil
		}
	}
	return request{}, connector.ErrInput
}

// Connector executes crm reads. Store and Key locate the installation's
// assertion signing key.
type Connector struct {
	Store credentials.Store
	Key   KeyConfig
}

type config struct {
	baseURL          *url.URL
	audience         string
	allowedActions   []string
	allowedResources []string
}

func configFrom(meta contract.Metadata) (config, error) {
	base, _ := meta.Config["base_url"].(string)
	aud, _ := meta.Config["assertion_audience"].(string)
	u, err := url.Parse(base)
	if base == "" || aud == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return config{}, connector.ErrConfig
	}
	return config{
		baseURL:          u,
		audience:         aud,
		allowedActions:   stringList(meta.Config["allowed_actions"], []string{"read"}),
		allowedResources: stringList(meta.Config["allowed_resources"], []string{"leads", "customers"}),
	}, nil
}

func stringList(value any, fallback []string) []string {
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

// Execute runs one crm read.
func (c Connector) Execute(ctx context.Context, call connector.Call) (any, error) {
	req, err := requestFor(call.Invocation, call.Input)
	if err != nil {
		return nil, err
	}
	cfg, err := configFrom(call.Meta)
	if err != nil {
		return nil, err
	}
	s, err := loadSigner(ctx, c.Store, c.Key)
	if err != nil {
		return nil, err
	}
	if err := httpapi.CheckHost(ctx, call.LookupIP, cfg.baseURL.Hostname()); err != nil {
		return nil, err
	}
	now := time.Now
	if call.Now != nil {
		now = call.Now
	}
	assertion, err := s.sign(claims(s, cfg, call.Meta, call.Invocation, now()))
	if err != nil {
		return nil, ErrAssertionKey
	}
	return invoke(ctx, call.HTTPClient, cfg, call.Credential, assertion, req)
}

// claims maps the catalog-minted envelope and descriptor onto the Worker's
// claimsSchema.
func claims(s *signer, cfg config, meta contract.Metadata, inv contract.Invocation, now time.Time) map[string]any {
	capabilities := make([]map[string]any, 0, len(meta.Capabilities))
	for _, c := range meta.Capabilities {
		capabilities = append(capabilities, map[string]any{"name": c.Name, "action": string(c.Action)})
	}
	out := map[string]any{
		"iss": s.issuer, "aud": cfg.audience,
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
		out["idempotency_key"] = inv.IdempotencyKey
	}
	return out
}

func invoke(ctx context.Context, client *http.Client, cfg config, apiKey, assertion string, r request) (any, error) {
	endpoint := *cfg.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + invokePath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(r.body))
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
			Records    []map[string]any `json:"records"`
			Record     map[string]any   `json:"record"`
			NextCursor *string          `json:"next_cursor"`
			HasMore    *bool            `json:"has_more"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil || !out.Success {
		return nil, errors.New("CRM response was not successful")
	}
	if out.Data.Record != nil {
		return map[string]any{"record": project(out.Data.Record, r.fields)}, nil
	}
	records := make([]map[string]any, 0, len(out.Data.Records))
	for _, rec := range out.Data.Records {
		records = append(records, project(rec, r.fields))
	}
	result := map[string]any{"records": records}
	// Paged lists (investor.list) carry their page state.
	if out.Data.HasMore != nil {
		result["has_more"], result["next_cursor"] = *out.Data.HasMore, out.Data.NextCursor
	}
	return result, nil
}

func project(in map[string]any, fields []string) map[string]any {
	out := make(map[string]any, len(fields))
	for _, f := range fields {
		if v, ok := in[f]; ok {
			out[f] = v
		}
	}
	return out
}
