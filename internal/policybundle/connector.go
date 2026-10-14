package policybundle

import (
	"encoding/json"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
)

// Connector is a policy_set.connectors entry: a workspace connector the bundle
// knows, with its provider and declared capabilities. In a v2 bundle the entry
// is also the connector's non-secret descriptor (ADR-034, HAI-378 amendment):
// where its credential lives and its non-secret config, never a credential.
// v1 entries carry only id, provider and capabilities.
type Connector struct {
	ID           string                `json:"id"`
	Name         string                `json:"name,omitempty"`
	Provider     string                `json:"provider"`
	Capabilities []ConnectorCapability `json:"capabilities"`
	// CredentialSource is oauth or opaque_ref; always set on a v2 descriptor.
	CredentialSource string `json:"credential_source,omitempty"`
	AccountModel     string `json:"account_model,omitempty"`
	// CredentialRef is the runtime-local kei://connectors/<id>/<field>
	// reference of an opaque_ref connector, resolved inside the daemon.
	CredentialRef string `json:"credential_ref,omitempty"`
	// CredentialBackend is the kind of the organization's credential store.
	CredentialBackend string                  `json:"credential_backend,omitempty"`
	Config            map[string]any          `json:"config,omitempty"`
	HTTPAPI           *contract.HTTPAPI       `json:"http_api,omitempty"`
	Grafana           *contract.GrafanaConfig `json:"grafana,omitempty"`
	// TODO(HAI-484): ADR-036 §4.3 descriptor fields. Optional until the catalog
	// emits them; the runtime gates the MCP route on kind and slug (§4.5 5-6).
	Kind string         `json:"kind,omitempty"`
	Slug string         `json:"slug,omitempty"`
	MCP  *MCPDescriptor `json:"mcp,omitempty"`
}

// MCPDescriptor is the mcp block of a v2 connector descriptor (ADR-036 §4.3).
type MCPDescriptor struct {
	URL                  string            `json:"url"`
	Transport            string            `json:"transport"`
	AuthMethod           string            `json:"auth_method"`
	ApprovedManifestHash string            `json:"approved_manifest_hash,omitempty"`
	ApprovedTools        []MCPApprovedTool `json:"approved_tools,omitempty"`
}

// MCPApprovedTool is one approved tool of an mcp descriptor (ADR-036 §4.3).
// approved_tools is sorted by name.
type MCPApprovedTool struct {
	Name     string `json:"name"`
	ToolHash string `json:"tool_hash"`
}

// ConnectorCapability is one declared capability of a bundle connector.
type ConnectorCapability struct {
	Name     string `json:"name"`
	Mutating bool   `json:"mutating"`
}

// Connector returns the bundle's connector entry with id.
func (v *Verified) Connector(id string) (Connector, bool) {
	set, err := v.decodePolicySet()
	if err != nil {
		return Connector{}, false
	}
	for _, c := range set.Connectors {
		if c.ID == id {
			return c, true
		}
	}
	return Connector{}, false
}

// CarriesConnectorDescriptors reports whether the bundle is v2 and its policy
// set has a connectors section. Without one (an older catalog) the runtime
// keeps its pre-descriptor behavior; with one, every routed connector must
// have an entry.
func (v *Verified) CarriesConnectorDescriptors() bool {
	if v == nil || v.Payload.Schema != "kei.policy-bundle/v2" {
		return false
	}
	var set struct {
		Connectors *[]json.RawMessage `json:"connectors"`
	}
	return json.Unmarshal(v.Payload.PolicySet, &set) == nil && set.Connectors != nil
}
