package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// Supported catalog tool-manifest schemas.
const (
	ToolManifestSchemaV3 = "kei.tool-manifest/v3"
	ToolManifestSchemaV4 = "kei.tool-manifest/v4"
	maxToolManifestBytes = 1 << 20
)

// ToolManifest is a schema-tagged catalog sync request. SyncMode is v4-only;
// raw JSON preserves the distinction between an omitted field and an invalid
// explicit null or non-string value.
type ToolManifest struct {
	Schema   string           `json:"schema"`
	SyncMode json.RawMessage  `json:"sync_mode,omitempty"`
	Tools    []ToolDefinition `json:"tools"`
}

type ToolRoute struct {
	ConnectorBinding *ConnectorBindingRoute `json:"connector_binding,omitempty"`
	HarnessExecutor  *HarnessExecutorRoute  `json:"harness_executor,omitempty"`
}

type ConnectorBindingRoute struct {
	AgentID     string `json:"agent_id"`
	ConnectorID string `json:"connector_id"`
}

type HarnessExecutorRoute struct {
	Executor     string `json:"executor"`
	Registration string `json:"registration"`
}

// ToolDefinition is an entry in a v3 or v4 tool manifest.
type ToolDefinition struct {
	Name                 string            `json:"name"`
	Description          string            `json:"description,omitempty"`
	Parameters           json.RawMessage   `json:"parameters,omitempty"`
	Permission           string            `json:"permission,omitempty"`
	Category             string            `json:"category,omitempty"`
	Version              string            `json:"version,omitempty"`
	Tags                 []string          `json:"tags,omitempty"`
	Route                *ToolRoute        `json:"route,omitempty"`
	Source               string            `json:"source,omitempty"`
	RequiredCapabilities []string          `json:"required_capabilities,omitempty"`
	ResourceTypes        []KeiResourceType `json:"resource_types,omitempty"`
	OperationClass       string            `json:"operation_class,omitempty"`
	Service              string            `json:"service,omitempty"`
	Enabled              *bool             `json:"enabled,omitempty"`
	Plan                 json.RawMessage   `json:"plan,omitempty"`
}

// KeiResourceType identifies a resource kind and optional parent kind.
// Both are plain identifiers (no globs).
type KeiResourceType struct {
	Type       string `json:"type"`
	ParentType string `json:"parent_type,omitempty"`
}

var (
	toolManifestToolNameRe = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*$`)
	toolManifestServiceRe  = regexp.MustCompile(`^\S{1,64}$`)
	toolManifestSourceRe   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	operationClassValues   = map[string]bool{"read": true, "write": true}
)

// validateToolManifest checks the manifest against catalog constraints without
// echoing field values in error messages.
func validateToolManifest(m *ToolManifest) error {
	if m == nil {
		return fmt.Errorf("tool manifest is nil")
	}
	switch m.Schema {
	case ToolManifestSchemaV3:
		if len(m.SyncMode) != 0 {
			return fmt.Errorf("v3 manifest must omit sync_mode")
		}
	case ToolManifestSchemaV4:
		if err := validateV4SyncMode(m.SyncMode); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported manifest schema: supported %s and %s, received %q", ToolManifestSchemaV3, ToolManifestSchemaV4, m.Schema)
	}
	if len(m.Tools) > 256 {
		return fmt.Errorf("too many tools: %d (max 256)", len(m.Tools))
	}
	seen := make(map[string]bool, len(m.Tools))
	for i, td := range m.Tools {
		prefix := fmt.Sprintf("tools[%d]", i)
		if td.Name == "" {
			return fmt.Errorf("%s: name is required", prefix)
		}
		if len(td.Name) > 128 || !toolManifestToolNameRe.MatchString(td.Name) {
			return fmt.Errorf("%s: invalid name", prefix)
		}
		if seen[td.Name] {
			return fmt.Errorf("%s: duplicate name %q", prefix, td.Name)
		}
		seen[td.Name] = true
		if m.Schema == ToolManifestSchemaV4 && len(td.Description) > 1024 {
			return fmt.Errorf("%s: description is too long", prefix)
		}
		if err := validateToolRoute(td, prefix); err != nil {
			return err
		}
		if m.Schema == ToolManifestSchemaV3 {
			if len(td.Plan) != 0 {
				return fmt.Errorf("%s: v3 manifest must omit plan", prefix)
			}
		} else if err := validateV4Plan(td, prefix); err != nil {
			return err
		}
	}
	return nil
}

func validateV4SyncMode(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var mode string
	if err := json.Unmarshal(raw, &mode); err != nil || (mode != "replace" && mode != "merge") {
		return fmt.Errorf("v4 sync_mode must be replace or merge")
	}
	return nil
}

func validateV4Plan(td ToolDefinition, prefix string) error {
	if td.Route.HarnessExecutor != nil {
		if len(td.Plan) != 0 {
			return fmt.Errorf("%s: harness_executor route must omit plan", prefix)
		}
		return nil
	}
	if len(td.Plan) == 0 || len(td.Plan) > policybundle.MaxPlanDataBytes {
		return fmt.Errorf("%s: connector_binding route requires a bounded plan", prefix)
	}
	for _, resource := range td.ResourceTypes {
		if strings.TrimSpace(resource.Type) == "" || (resource.ParentType != "" && strings.TrimSpace(resource.ParentType) == "") {
			return fmt.Errorf("%s: invalid resource type", prefix)
		}
	}
	tool := policybundle.V2Tool{
		Name:                 td.Name,
		Source:               td.Source,
		OperationClass:       td.OperationClass,
		RequiredCapabilities: td.RequiredCapabilities,
		Plan:                 td.Plan,
	}
	for _, resource := range td.ResourceTypes {
		tool.ResourceTypes = append(tool.ResourceTypes, policybundle.V2ResourceType{
			Type:       resource.Type,
			ParentType: resource.ParentType,
		})
	}
	if err := policybundle.ValidateV2Plan(tool); err != nil {
		return fmt.Errorf("%s: invalid v4 connector plan", prefix)
	}
	return nil
}

func validateToolRoute(td ToolDefinition, prefix string) error {
	if strings.TrimSpace(td.Service) == "" {
		return fmt.Errorf("%s: service is required", prefix)
	}
	if !toolManifestServiceRe.MatchString(td.Service) {
		return fmt.Errorf("%s: invalid service", prefix)
	}
	if td.Source == "" || !toolManifestSourceRe.MatchString(td.Source) {
		return fmt.Errorf("%s: invalid source", prefix)
	}
	if !operationClassValues[td.OperationClass] {
		return fmt.Errorf("%s: invalid operation_class", prefix)
	}
	r := td.Route
	if r == nil || (r.ConnectorBinding == nil) == (r.HarnessExecutor == nil) {
		return fmt.Errorf("%s: route must contain exactly one branch", prefix)
	}
	if c := r.ConnectorBinding; c != nil {
		if strings.TrimSpace(c.AgentID) == "" || strings.TrimSpace(c.ConnectorID) == "" || len(td.RequiredCapabilities) == 0 || td.ResourceTypes != nil && len(td.ResourceTypes) == 0 {
			return fmt.Errorf("%s: invalid connector_binding route", prefix)
		}
		for _, capability := range td.RequiredCapabilities {
			if strings.TrimSpace(capability) == "" || !toolManifestServiceRe.MatchString(capability) {
				return fmt.Errorf("%s: invalid required capability", prefix)
			}
		}
		for _, resource := range td.ResourceTypes {
			if resource.Type == "" {
				return fmt.Errorf("%s: invalid resource type", prefix)
			}
		}
	}
	if h := r.HarnessExecutor; h != nil && (strings.TrimSpace(h.Executor) == "" || strings.TrimSpace(h.Registration) == "" || td.RequiredCapabilities != nil || td.ResourceTypes != nil) {
		return fmt.Errorf("%s: invalid harness_executor route", prefix)
	}
	return nil
}

// LoadToolManifest reads and strictly validates a v3 or v4 tool manifest.
func LoadToolManifest(path string) (*ToolManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tool manifest: %w", err)
	}
	if len(data) > maxToolManifestBytes {
		return nil, fmt.Errorf("tool manifest exceeds %d bytes", maxToolManifestBytes)
	}
	var header struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("decode tool manifest: %w", err)
	}
	if header.Schema != ToolManifestSchemaV3 && header.Schema != ToolManifestSchemaV4 {
		return nil, fmt.Errorf("unsupported manifest schema: supported %s and %s, received %q", ToolManifestSchemaV3, ToolManifestSchemaV4, header.Schema)
	}
	var m ToolManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return nil, fmt.Errorf("decode tool manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("decode tool manifest: expected one JSON object")
	}
	if m.Schema != ToolManifestSchemaV3 && m.Schema != ToolManifestSchemaV4 {
		return nil, fmt.Errorf("unsupported manifest schema: supported %s and %s, received %q", ToolManifestSchemaV3, ToolManifestSchemaV4, m.Schema)
	}
	if m.Schema == ToolManifestSchemaV4 && m.Tools == nil {
		return nil, fmt.Errorf("invalid tool manifest: v4 tools is required")
	}
	if m.Tools == nil {
		m.Tools = []ToolDefinition{}
	}
	if err := validateToolManifest(&m); err != nil {
		return nil, fmt.Errorf("invalid tool manifest: %w", err)
	}
	return &m, nil
}
