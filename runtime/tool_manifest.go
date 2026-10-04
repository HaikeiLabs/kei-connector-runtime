package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// ToolManifestSchemaV2 is the only manifest schema this build syncs. The
// contract is v2-only: v1 and schema-less manifests are rejected at load and
// never translated into v2 fields. Legacy v1-producing harnesses must be
// upgraded to export v2 before this path is enabled.
const ToolManifestSchemaV2 = "kei.tool-manifest/v2"

// ToolManifest is the agentware tool-manifest v2 shape. Harnesses export it
// at build time; the kei-proxy runtime syncs it into the catalog tool registry
// at bootstrap. The schema is required, must be kei.tool-manifest/v2, and is
// passed through unchanged in the PUT body.
type ToolManifest struct {
	Schema string           `json:"schema,omitempty"`
	Tools  []ToolDefinition `json:"tools"`
}

// ToolDefinition is one entry in a tool manifest v2. Fields match the catalog
// POST /api/v1/tools create body minus server-generated fields. v1 fields
// (action, resources) are not parsed.
type ToolDefinition struct {
	Name                 string            `json:"name"`
	Source               string            `json:"source"`
	RequiredCapabilities []string          `json:"required_capabilities"`
	ResourceTypes        []KeiResourceType `json:"resource_types"`
	OperationClass       string            `json:"operation_class"`
	Service              string            `json:"service,omitempty"`
	Description          string            `json:"description"`
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
		if err := validateToolDefinition(td, prefix); err != nil {
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

// LoadToolManifest reads and validates a tool-manifest v2 JSON file. The
// schema must be exactly kei.tool-manifest/v2; v1, schema-less, and other
// schemas are rejected.
func LoadToolManifest(path string) (*ToolManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tool manifest: %w", err)
	}
	var m ToolManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("decode tool manifest: %w", err)
	}
	if m.Schema != ToolManifestSchemaV2 {
		return nil, fmt.Errorf("unsupported manifest schema %q (expected %s)", m.Schema, ToolManifestSchemaV2)
	}
	if m.Tools == nil {
		m.Tools = []ToolDefinition{}
	}
	if err := validateToolManifest(&m); err != nil {
		return nil, fmt.Errorf("invalid tool manifest: %w", err)
	}
	return &m, nil
}
