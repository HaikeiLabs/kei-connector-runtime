package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// Manifest schemas accepted during the v2-to-v3 migration.
const (
	ToolManifestSchemaV2 = "kei.tool-manifest/v2"
	ToolManifestSchemaV3 = "kei.tool-manifest/v3"
)

// ToolManifest is the schema-tagged catalog sync request. V2 fields remain
// readable for migration; v3 routes are typed and closed.
type ToolManifest struct {
	Schema string           `json:"schema"`
	Tools  []ToolDefinition `json:"tools"`
}

type ToolRoute struct {
	ConnectorBinding *ConnectorBindingRoute `json:"connector_binding,omitempty"`
	HarnessExecutor  *HarnessExecutorRoute  `json:"harness_executor,omitempty"`
}

type ConnectorBindingRoute struct {
	ConnectorID string `json:"connector_id"`
}

type HarnessExecutorRoute struct {
	Executor     string `json:"executor"`
	Registration string `json:"registration"`
}

// ToolDefinition is either a v2 metadata entry or a v3 typed route entry.
type ToolDefinition struct {
	Name  string     `json:"name"`
	Route *ToolRoute `json:"route,omitempty"`
	// Deprecated v2 fields are decoded only when schema is v2.
	Source               string            `json:"source,omitempty"`
	RequiredCapabilities []string          `json:"required_capabilities,omitempty"`
	ResourceTypes        []KeiResourceType `json:"resource_types,omitempty"`
	OperationClass       string            `json:"operation_class,omitempty"`
	Service              string            `json:"service,omitempty"`
	Description          string            `json:"description,omitempty"`
	Enabled              *bool             `json:"enabled,omitempty"`
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
		if m.Schema == ToolManifestSchemaV3 {
			if err := validateToolRoute(td, prefix); err != nil {
				return err
			}
		} else if err := validateToolDefinition(td, prefix); err != nil {
			return err
		}
	}
	return nil
}

func validateToolDefinition(td ToolDefinition, prefix string) error {
	if td.Source == "" {
		return fmt.Errorf("%s: source is required", prefix)
	}
	if !toolManifestSourceRe.MatchString(td.Source) {
		return fmt.Errorf("%s: invalid source", prefix)
	}
	if len(td.RequiredCapabilities) == 0 {
		return fmt.Errorf("%s: required_capabilities is required and must be non-empty", prefix)
	}
	for j, cap := range td.RequiredCapabilities {
		if cap == "" {
			return fmt.Errorf("%s: required_capabilities[%d] is empty", prefix, j)
		}
	}
	if len(td.ResourceTypes) == 0 {
		return fmt.Errorf("%s: resource_types is required and must be non-empty", prefix)
	}
	for j, rt := range td.ResourceTypes {
		if rt.Type == "" {
			return fmt.Errorf("%s: resource_types[%d]: type is required", prefix, j)
		}
	}
	if td.OperationClass == "" {
		return fmt.Errorf("%s: operation_class is required", prefix)
	}
	if !operationClassValues[td.OperationClass] {
		return fmt.Errorf("%s: invalid operation_class %q (must be read or write)", prefix, td.OperationClass)
	}
	if len(td.Description) > 1024 {
		return fmt.Errorf("%s: description too long", prefix)
	}
	if td.Service != "" && !toolManifestServiceRe.MatchString(td.Service) {
		return fmt.Errorf("%s: invalid service", prefix)
	}
	return nil
}

func validateToolRoute(td ToolDefinition, prefix string) error {
	if strings.TrimSpace(td.Service) == "" || !toolManifestServiceRe.MatchString(td.Service) {
		return fmt.Errorf("%s: service is required", prefix)
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
		if strings.TrimSpace(c.ConnectorID) == "" || len(td.RequiredCapabilities) == 0 || td.ResourceTypes != nil && len(td.ResourceTypes) == 0 {
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

// LoadToolManifest reads and validates v2 or v3 tool-manifest JSON. The schema
// is mandatory; v2 remains readable during migration.
func LoadToolManifest(path string) (*ToolManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tool manifest: %w", err)
	}
	var header struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("decode tool manifest: %w", err)
	}
	if header.Schema != ToolManifestSchemaV2 && header.Schema != ToolManifestSchemaV3 {
		return nil, fmt.Errorf("unsupported manifest schema %q", header.Schema)
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
	if m.Schema != ToolManifestSchemaV2 && m.Schema != ToolManifestSchemaV3 {
		return nil, fmt.Errorf("unsupported manifest schema %q", m.Schema)
	}
	if m.Tools == nil {
		m.Tools = []ToolDefinition{}
	}
	if err := validateToolManifest(&m); err != nil {
		return nil, fmt.Errorf("invalid tool manifest: %w", err)
	}
	return &m, nil
}
