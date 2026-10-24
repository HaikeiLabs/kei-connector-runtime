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

// Supported catalog manifest schemas. V4 connector entries carry a closed declarative plan.
const (
	ToolDefinitionSchemaV1 = "kei.tool-definition/v1"
	ToolManifestSchemaV1   = "kei.tool-manifest/v1"
	ToolManifestSchemaV2   = "kei.tool-manifest/v2"
	ToolManifestSchemaV3   = "kei.tool-manifest/v3"
	ToolManifestSchemaV4   = "kei.tool-manifest/v4"
)

// ToolManifest is the schema-tagged catalog sync request. V2/v3 remain
// compatible; v4 connector routes add a strictly validated declarative plan.
type ToolManifest struct {
	Schema   string           `json:"schema"`
	SyncMode string           `json:"sync_mode,omitempty"`
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

// ToolDefinition is a manifest entry; v4 connector entries include a v4 plan.
type ToolDefinition struct {
	Schema      string          `json:"schema,omitempty"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	Permission  string          `json:"permission,omitempty"`
	Category    string          `json:"category,omitempty"`
	Version     string          `json:"version,omitempty"`
	Tags        []string        `json:"tags,omitempty"`
	Binding     *ToolBindingV1  `json:"binding,omitempty"`
	Route       *ToolRoute      `json:"route,omitempty"`
	// Deprecated v2 fields are decoded only when schema is v2.
	Source               string            `json:"source,omitempty"`
	RequiredCapabilities []string          `json:"required_capabilities,omitempty"`
	ResourceTypes        []KeiResourceType `json:"resource_types,omitempty"`
	OperationClass       string            `json:"operation_class,omitempty"`
	Service              string            `json:"service,omitempty"`
	Enabled              *bool             `json:"enabled,omitempty"`
	Plan                 json.RawMessage   `json:"plan,omitempty"`
}

type ToolBindingV1 struct {
	ConnectorID      string           `json:"connector_id"`
	Config           map[string]any   `json:"config,omitempty"`
	DelegatedContext []string         `json:"delegated_context,omitempty"`
	Transport        *ToolTransportV1 `json:"transport,omitempty"`
}
type ToolTransportV1 struct {
	Method      string                        `json:"method,omitempty"`
	URLTemplate string                        `json:"url_template,omitempty"`
	Auth        *ToolTransportAuthV1          `json:"auth,omitempty"`
	Args        map[string]ToolTransportArgV1 `json:"args,omitempty"`
}
type ToolTransportAuthV1 struct {
	Placement string `json:"placement,omitempty"`
	Name      string `json:"name,omitempty"`
	Scheme    string `json:"scheme,omitempty"`
}
type ToolTransportArgV1 struct {
	In   string `json:"in"`
	Name string `json:"name,omitempty"`
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
	if err := validateToolManifestSyncMode(m.Schema, m.SyncMode); err != nil {
		return err
	}
	if len(m.Tools) > 256 {
		return fmt.Errorf("too many tools: %d (max 256)", len(m.Tools))
	}
	seen := make(map[string]bool, len(m.Tools))
	for i, td := range m.Tools {
		prefix := fmt.Sprintf("tools[%d]", i)
		if m.Schema == ToolManifestSchemaV1 {
			if err := validateToolDefinitionV1(td, prefix); err != nil {
				return err
			}
			continue
		}
		if m.Schema != ToolManifestSchemaV4 && len(td.Plan) != 0 {
			return fmt.Errorf("%s: plan is only supported by manifest v4", prefix)
		}
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
		} else if m.Schema == ToolManifestSchemaV4 {
			if err := validateToolV4(td, prefix); err != nil {
				return err
			}
		} else if err := validateToolDefinition(td, prefix); err != nil {
			return err
		}
	}
	return nil
}

func validateToolDefinitionV1(td ToolDefinition, prefix string) error {
	if td.Schema != ToolDefinitionSchemaV1 {
		return fmt.Errorf("%s: schema must be %s", prefix, ToolDefinitionSchemaV1)
	}
	if td.Name == "" {
		return fmt.Errorf("%s: name is required", prefix)
	}
	if len(td.Name) > 128 || !toolManifestToolNameRe.MatchString(td.Name) {
		return fmt.Errorf("%s: invalid name", prefix)
	}
	if td.Description == "" {
		return fmt.Errorf("%s: description is required", prefix)
	}
	if len(td.Description) > 1024 {
		return fmt.Errorf("%s: description too long", prefix)
	}
	if td.Service != "" && !regexp.MustCompile(`^[a-z0-9_]*$`).MatchString(td.Service) {
		return fmt.Errorf("%s: invalid service", prefix)
	}
	if len(td.Tags) > 0 {
		seenTags := map[string]bool{}
		for _, tag := range td.Tags {
			if seenTags[tag] {
				return fmt.Errorf("%s: tags must be unique", prefix)
			}
			seenTags[tag] = true
		}
	}
	if len(td.Parameters) != 0 {
		var params any
		if json.Unmarshal(td.Parameters, &params) != nil {
			return fmt.Errorf("%s: invalid parameters", prefix)
		}
		if items, ok := params.([]any); ok {
			for _, item := range items {
				parameter, ok := item.(map[string]any)
				if !ok || len(parameter) == 0 {
					return fmt.Errorf("%s: invalid parameter", prefix)
				}
				name, ok := parameter["name"].(string)
				if !ok || !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(name) {
					return fmt.Errorf("%s: invalid parameter name", prefix)
				}
				for key := range parameter {
					if key != "name" && key != "type" && key != "description" && key != "required" && key != "enum" && key != "default" {
						return fmt.Errorf("%s: invalid parameter field", prefix)
					}
				}
			}
		} else {
			if _, objectOK := params.(map[string]any); !objectOK {
				return fmt.Errorf("%s: parameters must be an array or object", prefix)
			}
		}
	}
	if td.Binding != nil {
		if td.Binding.ConnectorID == "" {
			return fmt.Errorf("%s: binding connector_id is required", prefix)
		}
		for _, field := range td.Binding.DelegatedContext {
			if !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(field) {
				return fmt.Errorf("%s: invalid delegated_context", prefix)
			}
		}
		if transport := td.Binding.Transport; transport != nil {
			if transport.Method != "" && !map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}[transport.Method] {
				return fmt.Errorf("%s: invalid transport method", prefix)
			}
			if transport.Auth != nil && transport.Auth.Placement != "" && !map[string]bool{"header": true, "query": true, "none": true}[transport.Auth.Placement] {
				return fmt.Errorf("%s: invalid transport auth placement", prefix)
			}
			for _, arg := range transport.Args {
				if !map[string]bool{"path": true, "query": true, "body": true, "header": true}[arg.In] {
					return fmt.Errorf("%s: invalid transport argument location", prefix)
				}
			}
		}
	}
	return nil
}

func validateToolManifestSyncMode(schema, mode string) error {
	if mode == "" {
		return nil // omitted means the catalog's legacy replace behavior
	}
	if schema != ToolManifestSchemaV4 || mode != "merge" {
		return fmt.Errorf("sync_mode is unsupported for this manifest schema or value")
	}
	return nil
}

func validateToolV4(td ToolDefinition, prefix string) error {
	if strings.TrimSpace(td.Service) == "" || !toolManifestServiceRe.MatchString(td.Service) || len(td.Description) > 1024 {
		return fmt.Errorf("%s: service or description is invalid", prefix)
	}
	if err := validateToolRoute(td, prefix); err != nil {
		return err
	}
	if td.Route.ConnectorBinding == nil {
		if len(td.Plan) != 0 || td.RequiredCapabilities != nil || td.ResourceTypes != nil {
			return fmt.Errorf("%s: harness route cannot carry a connector plan", prefix)
		}
		return nil
	}
	if len(td.Plan) == 0 || len(td.RequiredCapabilities) == 0 {
		return fmt.Errorf("%s: v4 connector route requires a closed plan and capabilities", prefix)
	}
	resources := make([]policybundle.V2ResourceType, len(td.ResourceTypes))
	for i, resource := range td.ResourceTypes {
		resources[i] = policybundle.V2ResourceType{Type: resource.Type, ParentType: resource.ParentType}
	}
	tool := policybundle.V2Tool{Name: td.Name, Source: td.Source, OperationClass: td.OperationClass, RequiredCapabilities: td.RequiredCapabilities, ResourceTypes: resources, Plan: td.Plan}
	tool.Route.ConnectorBinding = &struct {
		ConnectorID string `json:"connector_id"`
	}{ConnectorID: td.Route.ConnectorBinding.ConnectorID}
	if err := policybundle.ValidateV2Plan(tool); err != nil {
		return fmt.Errorf("%s: invalid v4 plan", prefix)
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

// LoadToolManifest reads and strictly validates supported tool-manifest versions.
func LoadToolManifest(path string) (*ToolManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tool manifest: %w", err)
	}
	var header struct {
		Schema string          `json:"schema"`
		Tools  json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("decode tool manifest: %w", err)
	}
	if header.Schema != ToolManifestSchemaV1 && header.Schema != ToolManifestSchemaV2 && header.Schema != ToolManifestSchemaV3 && header.Schema != ToolManifestSchemaV4 {
		return nil, fmt.Errorf("unsupported manifest schema %q", header.Schema)
	}
	if header.Schema == ToolManifestSchemaV4 && policybundle.RejectDuplicateJSON(data) != nil {
		return nil, fmt.Errorf("decode tool manifest: duplicate or malformed JSON")
	}
	if header.Schema == ToolManifestSchemaV4 && (len(header.Tools) == 0 || string(header.Tools) == "null") {
		return nil, fmt.Errorf("invalid tool manifest: v4 tools array is required")
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
	if m.Schema != ToolManifestSchemaV1 && m.Schema != ToolManifestSchemaV2 && m.Schema != ToolManifestSchemaV3 && m.Schema != ToolManifestSchemaV4 {
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
