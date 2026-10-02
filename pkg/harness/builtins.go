package harness

import (
	"embed"
	"encoding/json"
	"fmt"
	"time"
)

//go:embed builtins/*.json
var builtinCatalogs embed.FS

const builtinCatalogSchema = "kei.harness-builtins/v1"

type builtinCatalog struct {
	SchemaVersion  string    `json:"schema_version"`
	HarnessKind    Kind      `json:"harness_kind"`
	HarnessVersion string    `json:"harness_version"`
	VerifiedAt     time.Time `json:"verified_at"`
	Tools          []Tool    `json:"tools"`
}

func builtinsForKind(kind Kind) ([]Tool, error) {
	data, err := builtinCatalogs.ReadFile("builtins/" + string(kind) + ".json")
	if err != nil {
		return nil, fmt.Errorf("read embedded built-ins for %s: %w", kind, err)
	}
	var catalog builtinCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("decode embedded built-ins for %s: %w", kind, err)
	}
	if catalog.SchemaVersion != builtinCatalogSchema || catalog.HarnessKind != kind || catalog.HarnessVersion == "" || catalog.VerifiedAt.IsZero() || catalog.Tools == nil {
		return nil, fmt.Errorf("invalid embedded built-ins catalog for %s", kind)
	}
	return append([]Tool(nil), catalog.Tools...), nil
}
