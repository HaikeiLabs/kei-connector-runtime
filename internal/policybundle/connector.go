package policybundle

import "encoding/json"

// Connector is a policy_set.connectors entry: a workspace connector the bundle
// knows, with its provider and declared capabilities. Descriptor, when the
// catalog sent one (AcceptWithDescriptors), is the connector's non-secret
// contract metadata plus where its opaque_ref credential lives; it never
// holds a credential value. The runtime validates it with the connector
// contract before use.
type Connector struct {
	ID           string                `json:"id"`
	Provider     string                `json:"provider"`
	Capabilities []ConnectorCapability `json:"capabilities"`
	Descriptor   json.RawMessage       `json:"descriptor,omitempty"`
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
