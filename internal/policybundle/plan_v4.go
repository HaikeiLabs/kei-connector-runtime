package policybundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	MaxPlanDataBytes          = 64 << 10
	MaxPlanSchemaBytes        = 64 << 10
	MaxPlanOperations         = 32
	MaxPlanTemplateNodes      = 256
	MaxPlanDepth              = 16
	MaxPlanProviderInputBytes = 64 << 10
)

type V2Plan struct {
	ArgsSchema    json.RawMessage   `json:"args_schema"`
	ContextSchema json.RawMessage   `json:"context_schema"`
	Operations    []V2PlanOperation `json:"operations"`
}

type V2PlanOperation struct {
	ID                       string          `json:"id"`
	Capability               string          `json:"capability"`
	Resource                 *V2PlanResource `json:"resource,omitempty"`
	ProviderResourceTemplate string          `json:"provider_resource_template,omitempty"`
	ProviderInput            json.RawMessage `json:"provider_input"`
}

type V2PlanResource struct {
	Type   string           `json:"type"`
	ID     *V2PlanReference `json:"id,omitempty"`
	Parent *V2PlanParent    `json:"parent,omitempty"`
}

type V2PlanParent struct {
	Type string           `json:"type"`
	ID   *V2PlanReference `json:"id,omitempty"`
}

type V2PlanReference struct {
	From    string `json:"from"`
	Pointer string `json:"pointer,omitempty"`
	Field   string `json:"field,omitempty"`
	Type    string `json:"type"`
}

var planOperationID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var planResourceTemplateSegment = regexp.MustCompile(`^[A-Za-z0-9_.~-]+$`)
var allowedSchemaKeywords = map[string]bool{
	"type": true, "properties": true, "required": true, "additionalProperties": true,
	"minimum": true, "maximum": true, "minLength": true, "maxLength": true,
	"minItems": true, "maxItems": true, "items": true, "pattern": true, "enum": true,
}

// ValidateV2Plan rejects plans outside the closed declarative v4 profile
// before a policy bundle can be accepted.
func ValidateV2Plan(tool V2Tool) error {
	if len(tool.Plan) == 0 || len(tool.Plan) > MaxPlanDataBytes {
		return errors.New("v2 connector tool plan is missing or too large")
	}
	var plan V2Plan
	if err := strictJSON(tool.Plan, &plan); err != nil {
		return errors.New("v2 connector tool plan is malformed")
	}
	argsSchema, err := validateAndCompileObjectSchema(plan.ArgsSchema)
	if err != nil {
		return errors.New("v2 tool args schema is invalid")
	}
	contextSchema, err := validateAndCompileObjectSchema(plan.ContextSchema)
	if err != nil {
		return errors.New("v2 tool context schema is invalid")
	}
	_ = argsSchema
	_ = contextSchema
	if len(plan.Operations) == 0 || len(plan.Operations) > MaxPlanOperations {
		return errors.New("v2 tool plan operation count is invalid")
	}
	covered := make(map[string]bool, len(tool.RequiredCapabilities))
	for _, capability := range tool.RequiredCapabilities {
		if capability == "" || covered[capability] {
			return errors.New("v2 tool required capabilities are invalid")
		}
		covered[capability] = false
	}
	ids := make(map[string]bool, len(plan.Operations))
	for _, op := range plan.Operations {
		if !planOperationID.MatchString(op.ID) || ids[op.ID] || !containsPlanCapability(tool.RequiredCapabilities, op.Capability) || !capabilityRegistered(tool.Source, op.Capability) {
			return errors.New("v2 tool plan operation identity or capability is invalid")
		}
		ids[op.ID] = true
		covered[op.Capability] = true
		if op.Resource == nil {
			if !validProviderResourceTemplate(op.ProviderResourceTemplate, false, false) {
				return errors.New("v2 resource-less operation requires a literal provider resource")
			}
		} else {
			resource := op.Resource
			if resource.Type == "" || !declaredPlanResource(tool.ResourceTypes, resource.Type, parentType(resource.Parent)) {
				return errors.New("v2 tool plan resource/parent type pair is undeclared")
			}
			if resource.ID != nil {
				typ, ok := validateScalarPlanReference(plan.ArgsSchema, plan.ContextSchema, *resource.ID)
				if !ok || (typ != "string" && typ != "integer" && typ != "number") {
					return errors.New("v2 tool plan resource reference is invalid")
				}
			}
			if resource.Parent != nil {
				if resource.Parent.ID == nil {
					return errors.New("v2 tool plan parent id reference is missing")
				}
				typ, ok := validateScalarPlanReference(plan.ArgsSchema, plan.ContextSchema, *resource.Parent.ID)
				if !ok || (typ != "string" && typ != "integer" && typ != "number") {
					return errors.New("v2 tool plan parent reference is invalid")
				}
			}
			if op.ProviderResourceTemplate == "" || !validProviderResourceTemplate(op.ProviderResourceTemplate, resource.ID != nil, resource.Parent != nil && resource.Parent.ID != nil) {
				return errors.New("v2 tool plan provider resource template is invalid")
			}
		}
		if len(op.ProviderInput) == 0 || len(op.ProviderInput) > MaxPlanProviderInputBytes || !json.Valid(op.ProviderInput) {
			return errors.New("v2 tool plan provider input is invalid")
		}
		var template any
		dec := json.NewDecoder(bytes.NewReader(op.ProviderInput))
		dec.UseNumber()
		if dec.Decode(&template) != nil {
			return errors.New("v2 tool plan provider input is invalid")
		}
		if _, ok := template.(map[string]any); !ok {
			return errors.New("provider input template root must be an object")
		}
		nodes := 0
		if err := validatePlanTemplate(template, plan.ArgsSchema, plan.ContextSchema, 0, &nodes); err != nil || nodes > MaxPlanTemplateNodes {
			return errors.New("v2 tool plan provider input template is invalid")
		}
	}
	for _, present := range covered {
		if !present {
			return errors.New("v2 tool plan does not cover every required capability")
		}
	}
	return nil
}

func ParseV2Plan(tool V2Tool) (V2Plan, error) {
	if err := ValidateV2Plan(tool); err != nil {
		return V2Plan{}, err
	}
	var plan V2Plan
	if err := strictJSON(tool.Plan, &plan); err != nil {
		return V2Plan{}, errors.New("v2 tool plan is malformed")
	}
	return plan, nil
}

// ValidatePlanData canonicalizes and validates model args and hidden context
// independently against their closed JSON Schema documents.
func ValidatePlanData(tool V2Tool, argsRaw, contextRaw []byte) (args, context []byte, err error) {
	if len(argsRaw) == 0 {
		argsRaw = []byte("{}")
	}
	if len(contextRaw) == 0 {
		contextRaw = []byte("{}")
	}
	if len(argsRaw) > MaxPlanDataBytes || len(contextRaw) > MaxPlanDataBytes {
		return nil, nil, errors.New("plan input exceeds limit")
	}
	args, argsValue, err := canonicalPlanObject(argsRaw)
	if err != nil {
		return nil, nil, err
	}
	context, contextValue, err := canonicalPlanObject(contextRaw)
	if err != nil {
		return nil, nil, err
	}
	plan, err := ParseV2Plan(tool)
	if err != nil {
		return nil, nil, err
	}
	argsSchema, err := compileObjectSchema(plan.ArgsSchema)
	if err != nil || argsSchema.Validate(argsValue) != nil {
		return nil, nil, errors.New("tool arguments do not match the declared schema")
	}
	contextSchema, err := compileObjectSchema(plan.ContextSchema)
	if err != nil || contextSchema.Validate(contextValue) != nil {
		return nil, nil, errors.New("tool context does not match the declared schema")
	}
	return args, context, nil
}

func canonicalPlanObject(raw []byte) ([]byte, any, error) {
	if RejectDuplicateJSON(raw) != nil {
		return nil, nil, errors.New("plan input is invalid")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if dec.Decode(&value) != nil {
		return nil, nil, errors.New("plan input is invalid")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, nil, errors.New("plan input must contain one JSON object")
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, nil, errors.New("plan input must be a JSON object")
	}
	canonical, err := json.Marshal(value)
	if err != nil || len(canonical) > MaxPlanDataBytes {
		return nil, nil, errors.New("plan input exceeds limit")
	}
	return canonical, value, nil
}

func validateAndCompileObjectSchema(raw json.RawMessage) (*jsonschema.Schema, error) {
	if len(raw) == 0 || len(raw) > MaxPlanSchemaBytes {
		return nil, errors.New("schema size is invalid")
	}
	var document map[string]any
	if json.Unmarshal(raw, &document) != nil || document["type"] != "object" || document["additionalProperties"] != false {
		return nil, errors.New("schema must be a closed object")
	}
	if err := validateSchemaNode(document, 0); err != nil {
		return nil, err
	}
	return compileObjectSchema(raw)
}

func compileObjectSchema(raw json.RawMessage) (*jsonschema.Schema, error) {
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	const uri = "https://schemas.haikeilabs.com/kei/runtime-plan-object.schema.json"
	if err := compiler.AddResource(uri, document); err != nil {
		return nil, err
	}
	return compiler.Compile(uri)
}

func validateSchemaNode(schema map[string]any, depth int) error {
	if depth > MaxPlanDepth {
		return errors.New("schema nesting exceeds limit")
	}
	for key := range schema {
		if !allowedSchemaKeywords[key] {
			return errors.New("unsupported schema keyword")
		}
	}
	typ, ok := schema["type"].(string)
	if !ok || (typ != "object" && typ != "array" && typ != "string" && typ != "integer" && typ != "number" && typ != "boolean") {
		return errors.New("unsupported schema type")
	}
	if typ == "object" {
		if schema["additionalProperties"] != false {
			return errors.New("object schema must be closed")
		}
		properties, ok := schema["properties"].(map[string]any)
		if !ok || len(properties) > 64 {
			return errors.New("object properties are invalid")
		}
		for _, value := range properties {
			child, ok := value.(map[string]any)
			if !ok {
				return errors.New("property schema is invalid")
			}
			if err := validateSchemaNode(child, depth+1); err != nil {
				return err
			}
		}
		if raw, ok := schema["required"]; ok {
			required, ok := raw.([]any)
			if !ok {
				return errors.New("required list is invalid")
			}
			seen := map[string]bool{}
			for _, value := range required {
				name, ok := value.(string)
				if !ok || properties[name] == nil || seen[name] {
					return errors.New("required list has undeclared or duplicate property")
				}
				seen[name] = true
			}
		}
	}
	if typ == "array" {
		maxItems, ok := schema["maxItems"].(float64)
		if !ok || maxItems < 0 || maxItems > 256 {
			return errors.New("array maxItems must be bounded to 0..256")
		}
		items, ok := schema["items"].(map[string]any)
		if !ok {
			return errors.New("array items schema is invalid")
		}
		if err := validateSchemaNode(items, depth+1); err != nil {
			return err
		}
	}
	if typ == "string" {
		if pattern, ok := schema["pattern"].(string); ok {
			if _, err := regexp.Compile(pattern); err != nil {
				return errors.New("string pattern is invalid")
			}
		}
	}
	return nil
}

func validatePlanReference(argsRaw, contextRaw json.RawMessage, ref V2PlanReference) (string, bool) {
	var raw json.RawMessage
	var name string
	switch ref.From {
	case "args":
		if ref.Field != "" || !strings.HasPrefix(ref.Pointer, "/") || strings.Count(ref.Pointer, "/") != 1 {
			return "", false
		}
		name = decodePointerSegment(strings.TrimPrefix(ref.Pointer, "/"))
		raw = argsRaw
	case "context":
		if ref.Pointer != "" || ref.Field == "" {
			return "", false
		}
		name, raw = ref.Field, contextRaw
	default:
		return "", false
	}
	var schema map[string]any
	if json.Unmarshal(raw, &schema) != nil {
		return "", false
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		return "", false
	}
	property, ok := properties[name].(map[string]any)
	if !ok {
		return "", false
	}
	typ, ok := property["type"].(string)
	return typ, ok && typ == ref.Type && supportedPlanReferenceType(ref.Type)
}

func validateScalarPlanReference(argsRaw, contextRaw json.RawMessage, ref V2PlanReference) (string, bool) {
	typ, ok := validatePlanReference(argsRaw, contextRaw, ref)
	return typ, ok && typ != "object" && typ != "array"
}

func supportedPlanReferenceType(typ string) bool {
	return typ == "string" || typ == "integer" || typ == "number" || typ == "boolean" || typ == "object" || typ == "array"
}

func decodePointerSegment(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '~' {
			out.WriteByte(value[i])
			continue
		}
		if i+1 >= len(value) {
			return ""
		}
		i++
		switch value[i] {
		case '0':
			out.WriteByte('~')
		case '1':
			out.WriteByte('/')
		default:
			return ""
		}
	}
	return out.String()
}

func validatePlanTemplate(value any, argsRaw, contextRaw json.RawMessage, depth int, nodes *int) error {
	*nodes = *nodes + 1
	if depth > MaxPlanDepth || *nodes > MaxPlanTemplateNodes {
		return errors.New("template bound exceeded")
	}
	switch item := value.(type) {
	case map[string]any:
		if raw, ok := item["ref"]; ok {
			if len(item) != 1 {
				return errors.New("template ref wrapper has unknown fields")
			}
			encoded, _ := json.Marshal(raw)
			var ref V2PlanReference
			if strictJSON(encoded, &ref) != nil {
				return errors.New("invalid template ref")
			}
			if _, ok := validatePlanReference(argsRaw, contextRaw, ref); !ok {
				return errors.New("undeclared or wrongly typed template ref")
			}
			return nil
		}
		if _, oldRef := item["$ref"]; oldRef {
			return errors.New("template refs must use the v4 ref wrapper")
		}
		for _, child := range item {
			if err := validatePlanTemplate(child, argsRaw, contextRaw, depth+1, nodes); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range item {
			if err := validatePlanTemplate(child, argsRaw, contextRaw, depth+1, nodes); err != nil {
				return err
			}
		}
	case string, json.Number, bool, nil:
	default:
		return errors.New("unsupported template value")
	}
	return nil
}

func validProviderResourceTemplate(value string, hasResourceID, hasParentID bool) bool {
	if value == "" || len(value) > 4096 || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "?#\\%\x00\r\n") || strings.Contains(value, "{{") || strings.Contains(value, "}}") {
		return false
	}
	for i := 0; i < len(value); {
		if value[i] == '{' {
			end := strings.IndexByte(value[i:], '}')
			if end < 0 {
				return false
			}
			end += i
			key := value[i+1 : end]
			if key == "resource.id" && hasResourceID || key == "parent.id" && hasParentID {
				i = end + 1
				continue
			}
			return false
		}
		if value[i] == '}' {
			return false
		}
		i++
	}
	normalized := strings.ReplaceAll(strings.ReplaceAll(value, "{resource.id}", "X"), "{parent.id}", "X")
	if strings.ContainsAny(normalized, "{}") {
		return false
	}
	for _, segment := range strings.Split(normalized, "/") {
		if segment == "" || segment == "." || segment == ".." || !planResourceTemplateSegment.MatchString(segment) {
			return false
		}
	}
	return true
}

func capabilityRegistered(source, capability string) bool {
	for _, definition := range contract.CapabilitiesFor(contract.Provider(source)) {
		if definition.Name == capability {
			return true
		}
	}
	return false
}

func containsPlanCapability(capabilities []string, wanted string) bool {
	for _, capability := range capabilities {
		if capability == wanted {
			return true
		}
	}
	return false
}
func parentType(parent *V2PlanParent) string {
	if parent == nil {
		return ""
	}
	return parent.Type
}
func declaredPlanResource(resources []V2ResourceType, resourceType, parent string) bool {
	for _, resource := range resources {
		if resource.Type == resourceType && resource.ParentType == parent {
			return true
		}
	}
	return false
}
