package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

var safeResourceSegment = regexp.MustCompile(`^[A-Za-z0-9_.~-]{1,256}$`)
var safeRepositorySlug = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}/[A-Za-z0-9_.-]{1,128}$`)

func decodePlanObject(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value map[string]any
	if err := dec.Decode(&value); err != nil || value == nil {
		return nil, errors.New("invalid plan object")
	}
	return value, nil
}

func resolvePlanValue(ref policybundle.V2PlanReference, args, context map[string]any) (any, bool) {
	switch ref.From {
	case "args":
		if !strings.HasPrefix(ref.Pointer, "/") || strings.Count(ref.Pointer, "/") != 1 {
			return nil, false
		}
		name := decodePlanPointerSegment(strings.TrimPrefix(ref.Pointer, "/"))
		value, ok := args[name]
		return value, ok
	case "context":
		value, ok := context[ref.Field]
		return value, ok
	default:
		return nil, false
	}
}

func decodePlanPointerSegment(value string) string {
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

func planScalarString(value any, parent bool, parentType string) (string, bool) {
	var text string
	switch item := value.(type) {
	case string:
		text = item
	case json.Number:
		text = item.String()
	default:
		return "", false
	}
	if parentType == "repository" {
		if !safeRepositorySlug.MatchString(text) {
			return "", false
		}
		parts := strings.Split(text, "/")
		return text, parts[0] != "." && parts[0] != ".." && parts[1] != "." && parts[1] != ".."
	}
	return text, safeResourceSegment.MatchString(text) && text != "." && text != ".."
}

func renderProviderResource(template, resourceID, parentID string) (string, bool) {
	if strings.Contains(template, "{resource.id}") {
		if resourceID == "" {
			return "", false
		}
		template = strings.ReplaceAll(template, "{resource.id}", resourceID)
	}
	if strings.Contains(template, "{parent.id}") {
		if parentID == "" {
			return "", false
		}
		template = strings.ReplaceAll(template, "{parent.id}", parentID)
	}
	if strings.ContainsAny(template, "{}?#\\%\x00\r\n") || len(template) > 4096 {
		return "", false
	}
	for _, segment := range strings.Split(template, "/") {
		if segment == "" || segment == "." || segment == ".." || !safeResourceSegment.MatchString(segment) {
			return "", false
		}
	}
	return template, true
}

func materializePlanTemplate(value any, args, context map[string]any, depth int) (any, error) {
	if depth > policybundle.MaxPlanDepth {
		return nil, errors.New("template depth exceeded")
	}
	switch item := value.(type) {
	case map[string]any:
		if raw, ok := item["ref"]; ok {
			if len(item) != 1 {
				return nil, errors.New("template ref is not closed")
			}
			encoded, err := json.Marshal(raw)
			if err != nil {
				return nil, err
			}
			var ref policybundle.V2PlanReference
			decoder := json.NewDecoder(bytes.NewReader(encoded))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&ref); err != nil {
				return nil, err
			}
			value, ok := resolvePlanValue(ref, args, context)
			if !ok {
				return nil, errors.New("template ref is not present")
			}
			return value, nil
		}
		out := make(map[string]any, len(item))
		for key, child := range item {
			mapped, err := materializePlanTemplate(child, args, context, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = mapped
		}
		return out, nil
	case []any:
		out := make([]any, len(item))
		for i, child := range item {
			mapped, err := materializePlanTemplate(child, args, context, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = mapped
		}
		return out, nil
	default:
		return value, nil
	}
}

func jsonMarshalCanonical(value any) ([]byte, error) { return json.Marshal(value) }

func planValueWithinBounds(value any, depth int, nodes *int) bool {
	*nodes++
	if depth > policybundle.MaxPlanDepth || *nodes > policybundle.MaxPlanTemplateNodes {
		return false
	}
	switch item := value.(type) {
	case map[string]any:
		for _, child := range item {
			if !planValueWithinBounds(child, depth+1, nodes) {
				return false
			}
		}
	case []any:
		for _, child := range item {
			if !planValueWithinBounds(child, depth+1, nodes) {
				return false
			}
		}
	}
	return true
}

func registeredCapabilityAction(source, capability string) (string, bool) {
	provider := contract.Provider(source)
	for _, registered := range contract.CapabilitiesFor(provider) {
		if registered.Name == capability {
			return string(registered.Action), true
		}
	}
	return "", false
}
