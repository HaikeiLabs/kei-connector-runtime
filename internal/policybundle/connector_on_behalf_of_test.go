package policybundle

import (
	"encoding/json"
	"testing"
)

// HAI-669 (R1): a descriptor's on_behalf_of block (kei-connector-contracts
// contract.OnBehalfOf) decodes onto the connector, so the runtime's
// on-behalf-of exchanger is driven by descriptor data alone.
func TestConnectorDecodesOnBehalfOf(t *testing.T) {
	raw := `{"id":"c-obo","provider":"http_api","credential_source":"on_behalf_of","account_model":"per_user",
		"credential_backend":"azure-key-vault","capabilities":[],
		"on_behalf_of":{"tenant_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","client_id":"11111111-2222-3333-4444-555555555555",
		"resource":"https://api.example.com","scopes":["https://api.example.com/Data.Read"],
		"client_secret_ref":"kei://connectors/c-obo/client_secret"}}`
	var c Connector
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	o := c.OnBehalfOf
	if o == nil || o.TenantID != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" || o.ClientID != "11111111-2222-3333-4444-555555555555" ||
		o.Resource != "https://api.example.com" || len(o.Scopes) != 1 || o.ClientSecretRef != "kei://connectors/c-obo/client_secret" {
		t.Fatalf("on_behalf_of = %+v", o)
	}
	if err := o.Validate(c.ID); err != nil {
		t.Fatalf("decoded block fails the contract: %v", err)
	}
}
