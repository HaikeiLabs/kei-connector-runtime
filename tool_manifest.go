package connectorruntime

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// ToolManifestSchemaV1 is the only manifest schema this build syncs. v2
// (policy field contract, ADR-028) arrives with HAI-279.
const ToolManifestSchemaV1 = "kei.tool-manifest/v1"

// ToolManifest is the agentware tool-manifest v1 shape. Harnesses export it
// at build time; the kei-proxy runtime syncs it into the catalog tool registry
// at bootstrap. Schema is optional and passed through unchanged in the PUT
// body.
type ToolManifest struct {
	Schema string           `json:"schema,omitempty"`
	Tools  []ToolDefinition `json:"tools"`
}

// ToolDefinition is one entry in a tool manifest. Fields match the catalog
// POST /api/v1/tools create body minus server-generated fields.
type ToolDefinition struct {
	Name        string   `json:"name"`
	Service     string   `json:"service"`
	Description string   `json:"description"`
	Action      string   `json:"action,omitempty"`
	Resources   []string `json:"resources,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
}

var (
	toolManifestToolNameRe = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*$`)
	toolManifestServiceRe  = regexp.MustCompile(`^\S{1,64}$`)
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
		if td.Service == "" {
			return fmt.Errorf("%s: service is required", prefix)
		}
		if !toolManifestServiceRe.MatchString(td.Service) {
			return fmt.Errorf("%s: invalid service", prefix)
		}
		if len(td.Description) > 1024 {
			return fmt.Errorf("%s: description too long", prefix)
		}
		if td.Action != "" {
			if len(td.Action) > 255 {
				return fmt.Errorf("%s: action too long", prefix)
			}
			for _, b := range []byte(td.Action) {
				if b < 0x20 || b > 0x7E {
					return fmt.Errorf("%s: invalid action (non-printable)", prefix)
				}
			}
		}
		if len(td.Resources) > 32 {
			return fmt.Errorf("%s: too many resources (max 32)", prefix)
		}
		for j, res := range td.Resources {
			if len(res) > 255 {
				return fmt.Errorf("%s: resources[%d]: too long", prefix, j)
			}
			for _, b := range []byte(res) {
				if b < 0x20 || b > 0x7E {
					return fmt.Errorf("%s: resources[%d]: non-printable", prefix, j)
				}
			}
		}
	}
	return nil
}

// LoadToolManifest reads and validates a tool-manifest v1 JSON file.
func LoadToolManifest(path string) (*ToolManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tool manifest: %w", err)
	}
	var m ToolManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("decode tool manifest: %w", err)
	}
	if m.Tools == nil {
		m.Tools = []ToolDefinition{}
	}
	if err := validateToolManifest(&m); err != nil {
		return nil, fmt.Errorf("invalid tool manifest: %w", err)
	}
	return &m, nil
}
