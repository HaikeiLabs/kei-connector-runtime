package runtime

// GET /v1/agent-config (plan 2026-11-25, option C): the configuration the
// platform assigned to this installation's agent, so a harness names no model
// and no connector ID. It is answered from memory only: the verified policy
// bundle and a model-profile metadata snapshot that the policy refresher
// keeps current. The route makes no provider and no control-plane call
// (ADR-039) and is metadata only: credentials come solely from
// POST /v1/credentials:release after an allow.

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

const (
	agentConfigPath   = "/v1/agent-config"
	agentConfigSchema = "kei.agent-config/v1"
	// modelProfileMetadataMaxAge bounds how long an unchanged assignment's
	// model/endpoint snapshot is reused before the refresher fetches it again.
	modelProfileMetadataMaxAge = 10 * time.Minute
)

// ModelProfileMetadata is the non-secret part of the agent's assigned model
// profile: never its API key, secret reference or backend.
type ModelProfileMetadata struct {
	ProfileID string
	Model     string
	Endpoint  string
	IsDefault bool
}

type modelProfileSnapshot struct {
	ModelProfileMetadata
	fetched time.Time
}

// SetModelProfileMetadata replaces the model-profile metadata snapshot (nil
// clears it). It is served only while its profile is the trusted agent's
// active assignment in the verified bundle.
func (l *LocalPDP) SetModelProfileMetadata(m *ModelProfileMetadata) {
	if m == nil {
		l.modelMetadata.Store(nil)
		return
	}
	l.modelMetadata.Store(&modelProfileSnapshot{ModelProfileMetadata: *m, fetched: time.Now()})
}

// ModelProfileMetadataSnapshot is a copy of the held snapshot, or nil.
func (l *LocalPDP) ModelProfileMetadataSnapshot() *ModelProfileMetadata {
	snap := l.modelMetadata.Load()
	if snap == nil {
		return nil
	}
	m := snap.ModelProfileMetadata
	return &m
}

// ModelProfileMetadataDue reports whether the refresher should fetch the
// snapshot again: none is held, the bundle assigns the agent another profile,
// or the snapshot is older than modelProfileMetadataMaxAge.
func (l *LocalPDP) ModelProfileMetadataDue(now time.Time) bool {
	snap := l.modelMetadata.Load()
	if snap == nil || now.Sub(snap.fetched) > modelProfileMetadataMaxAge {
		return true
	}
	verified, agentID, ok := l.agentConfigBundle(now)
	if !ok {
		return false
	}
	assigned, ok := assignedModelProfile(verified, agentID)
	return !ok || assigned.ProfileID != snap.ProfileID
}

type agentConfigResponse struct {
	Schema       string                   `json:"schema"`
	ModelProfile *agentConfigModelProfile `json:"model_profile,omitempty"`
	Connectors   []agentConfigConnector   `json:"connectors"`
}

type agentConfigModelProfile struct {
	ProfileID string `json:"profile_id"`
	Status    string `json:"status"`
	Model     string `json:"model,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	IsDefault *bool  `json:"is_default,omitempty"`
}

type agentConfigConnector struct {
	ConnectorID string `json:"connector_id"`
	Name        string `json:"name,omitempty"`
	Kind        string `json:"kind,omitempty"`
	// Connection is the contract connection the installation uses; set once
	// the bundle descriptor carries it (catalog projection, contracts bump).
	Connection string            `json:"connection,omitempty"`
	BaseURL    string            `json:"base_url,omitempty"`
	Tools      []agentConfigTool `json:"tools"`
}

type agentConfigTool struct {
	Tool             string   `json:"tool"`
	Operations       []string `json:"operations"`
	BindingVersion   string   `json:"binding_version,omitempty"`
	ResourceTemplate string   `json:"resource_template,omitempty"`
}

// agentConfigBundle is the verified v2 bundle and the trusted agent, or ok
// false when either is unavailable or the bundle's subject snapshot is stale.
func (l *LocalPDP) agentConfigBundle(now time.Time) (*policybundle.Verified, string, bool) {
	identity, e := l.identity.Load(), l.evaluator.Load()
	if identity == nil || identity.AgentID == "" || e == nil {
		return nil, "", false
	}
	verified, ok := e.Bundle()
	if !ok || verified.Payload.Schema != "kei.policy-bundle/v2" || !verified.SubjectSnapshotFresh(now) {
		return nil, "", false
	}
	return verified, identity.AgentID, true
}

func assignedModelProfile(verified *policybundle.Verified, agentID string) (agentConfigModelProfile, bool) {
	for _, a := range verified.Payload.AgentModelProfiles {
		if a.AgentID == agentID {
			return agentConfigModelProfile{ProfileID: a.ProfileID, Status: a.Status}, true
		}
	}
	return agentConfigModelProfile{}, false
}

// connectorBaseURL is the descriptor's non-secret tenant origin, if any.
func connectorBaseURL(c policybundle.Connector) string {
	switch {
	case c.Grafana != nil && c.Grafana.BaseURL != "":
		return c.Grafana.BaseURL
	case c.HTTPAPI != nil && c.HTTPAPI.RegisteredBaseURL != "":
		return c.HTTPAPI.RegisteredBaseURL
	}
	return ""
}

func (l *LocalPDP) handleAgentConfig(w http.ResponseWriter) {
	now := time.Now().UTC()
	verified, agentID, ok := l.agentConfigBundle(now)
	if !ok {
		writeRuntimeError(w, http.StatusServiceUnavailable, "agent_config_unavailable", "runtime identity or verified v2 policy bundle is unavailable")
		return
	}
	resp := agentConfigResponse{Schema: agentConfigSchema, Connectors: []agentConfigConnector{}}
	if profile, ok := assignedModelProfile(verified, agentID); ok {
		if snap := l.modelMetadata.Load(); snap != nil && snap.ProfileID == profile.ProfileID && profile.Status == "active" {
			isDefault := snap.IsDefault
			profile.Model, profile.Endpoint, profile.IsDefault = snap.Model, snap.Endpoint, &isDefault
		}
		resp.ModelProfile = &profile
	}
	tools := map[string][]agentConfigTool{}
	for _, t := range verified.V2ConnectorToolSummaries(now) {
		tools[t.ConnectorID] = append(tools[t.ConnectorID], agentConfigTool{
			Tool: t.Name, Operations: t.OperationIDs, BindingVersion: t.BindingVersion, ResourceTemplate: t.ResourceTemplate,
		})
	}
	for _, c := range verified.Connectors() {
		if !verified.AgentBoundToConnector(agentID, c.ID) {
			continue
		}
		bound := tools[c.ID]
		if bound == nil {
			bound = []agentConfigTool{}
		}
		resp.Connectors = append(resp.Connectors, agentConfigConnector{
			ConnectorID: c.ID, Name: c.Name, Kind: c.Kind, BaseURL: connectorBaseURL(c), Tools: bound,
		})
	}
	sort.Slice(resp.Connectors, func(i, j int) bool { return resp.Connectors[i].ConnectorID < resp.Connectors[j].ConnectorID })
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}
