package connectorruntime

import keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"

type ToolManifest = keiruntime.ToolManifest
type ToolDefinition = keiruntime.ToolDefinition
type KeiResourceType = keiruntime.KeiResourceType

const ToolManifestSchemaV2 = keiruntime.ToolManifestSchemaV2

func LoadToolManifest(path string) (*ToolManifest, error) {
	return keiruntime.LoadToolManifest(path)
}
