package connectorruntime

import keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"

type ToolManifest = keiruntime.ToolManifest
type ToolDefinition = keiruntime.ToolDefinition
type KeiResourceType = keiruntime.KeiResourceType
type ToolRoute = keiruntime.ToolRoute
type ConnectorBindingRoute = keiruntime.ConnectorBindingRoute
type HarnessExecutorRoute = keiruntime.HarnessExecutorRoute

const (
	ToolManifestSchemaV3        = keiruntime.ToolManifestSchemaV3
	ToolManifestProtocolHeader  = keiruntime.ToolManifestProtocolHeader
	ToolManifestSupportedHeader = keiruntime.ToolManifestSupportedHeader
)

func LoadToolManifest(path string) (*ToolManifest, error) {
	return keiruntime.LoadToolManifest(path)
}
