package policybundle

import (
	"errors"
	"reflect"
	"testing"
)

const testToolHash = "sha256:9e84a27116887ce94c79f25184ee07da9b9dd0288847be9e0ee885fdc61ec537"

// mcpDescriptorDoc is the catalog's HAI-570 descriptor for an mcp connector.
func mcpDescriptorDoc() map[string]any {
	return map[string]any{
		"id": "conn-grafana", "name": "Grafana (prod)", "provider": "grafana_mcp",
		"credential_source": "oauth", "account_model": "per_user", "capabilities": []any{},
		"kind": "mcp", "slug": "grafana_prod",
		"mcp": map[string]any{
			"url": "https://mcp.grafana.example/mcp", "transport": "streamable_http", "auth_method": "oauth",
			"approved_manifest_hash": "sha256:a94748f3bd7e1bc1e46ff952e802378a98249adfd5fcd2677ff48bd0df848dbb",
			"approved_tools":         []any{map[string]any{"name": "get_dashboard", "tool_hash": testToolHash}},
		},
	}
}

func withMCPDescriptor(t *testing.T, mutate func(d map[string]any)) map[string]any {
	t.Helper()
	doc := connectorsExampleDoc(t)
	d := mcpDescriptorDoc()
	if mutate != nil {
		mutate(d)
	}
	set := doc["policy_set"].(map[string]any)
	set["connectors"] = append(set["connectors"].([]any), d)
	return doc
}

func TestV2BundleDecodesMCPDescriptors(t *testing.T) {
	v, err := validateConnectorsDoc(t, withMCPDescriptor(t, nil))
	if err != nil {
		t.Fatalf("a bundle with an HAI-570 mcp descriptor must validate: %v", err)
	}
	c, ok := v.MCPConnector("grafana_prod")
	if !ok {
		t.Fatal("mcp connector grafana_prod not found by slug")
	}
	want := MCPDescriptor{
		URL: "https://mcp.grafana.example/mcp", Transport: "streamable_http", AuthMethod: "oauth",
		ApprovedManifestHash: "sha256:a94748f3bd7e1bc1e46ff952e802378a98249adfd5fcd2677ff48bd0df848dbb",
		ApprovedTools:        []MCPApprovedTool{{Name: "get_dashboard", ToolHash: testToolHash}},
	}
	if c.ID != "conn-grafana" || c.MCP == nil || !reflect.DeepEqual(*c.MCP, want) {
		t.Fatalf("descriptor = %+v / %+v", c, c.MCP)
	}
	if _, ok := v.MCPConnector("crm"); ok {
		t.Fatal("a non-mcp connector must not resolve as an mcp connector")
	}
	if hosts := v.MCPHosts(); !reflect.DeepEqual(hosts, []string{"mcp.grafana.example:443"}) {
		t.Fatalf("MCPHosts = %v, want [mcp.grafana.example:443]", hosts)
	}
}

func TestV2BundleUnapprovedMCPDescriptor(t *testing.T) {
	v, err := validateConnectorsDoc(t, withMCPDescriptor(t, func(d map[string]any) {
		m := d["mcp"].(map[string]any)
		m["approved_manifest_hash"] = nil
		m["approved_tools"] = []any{}
	}))
	if err != nil {
		t.Fatalf("an unapproved mcp descriptor must validate: %v", err)
	}
	c, ok := v.MCPConnector("grafana_prod")
	if !ok || c.MCP.ApprovedManifestHash != "" || len(c.MCP.ApprovedTools) != 0 {
		t.Fatalf("descriptor = %+v, %v; want no approval", c.MCP, ok)
	}
}

func TestV2BundleMCPDescriptorMutationsAreRejected(t *testing.T) {
	cases := map[string]func(d map[string]any){
		"mcp kind without mcp block":      func(d map[string]any) { delete(d, "mcp") },
		"mcp kind without slug":           func(d map[string]any) { delete(d, "slug") },
		"mcp block on another kind":       func(d map[string]any) { d["kind"] = "native" },
		"http url":                        func(d map[string]any) { d["mcp"].(map[string]any)["url"] = "http://mcp.grafana.example/mcp" },
		"stdio transport":                 func(d map[string]any) { d["mcp"].(map[string]any)["transport"] = "stdio" },
		"approved tools without approval": func(d map[string]any) { d["mcp"].(map[string]any)["approved_manifest_hash"] = nil },
		"malformed tool hash": func(d map[string]any) {
			d["mcp"].(map[string]any)["approved_tools"].([]any)[0].(map[string]any)["tool_hash"] = "md5:x"
		},
		"unknown mcp field":             func(d map[string]any) { d["mcp"].(map[string]any)["command"] = "npx server" },
		"slug outside the slug pattern": func(d map[string]any) { d["slug"] = "Grafana-Prod" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := validateConnectorsDoc(t, withMCPDescriptor(t, mutate)); err == nil {
				t.Fatal("mutated mcp descriptor validated")
			} else if errors.Is(err, ErrBundleExpired) {
				t.Fatalf("rejected for the wrong reason: %v", err)
			}
		})
	}
}

func TestVerifiedAgentBoundToConnector(t *testing.T) {
	doc := withMCPDescriptor(t, nil)
	doc["agent_connector_bindings"] = []any{map[string]any{"agent_id": "agent-a", "connector_id": "conn-grafana", "capabilities": []any{}}}
	v, err := validateConnectorsDoc(t, doc)
	if err != nil {
		t.Fatal(err)
	}
	if !v.AgentBoundToConnector("agent-a", "conn-grafana") {
		t.Fatal("agent-a is bound to conn-grafana")
	}
	if v.AgentBoundToConnector("agent-b", "conn-grafana") || v.AgentBoundToConnector("agent-a", "conn-crm") {
		t.Fatal("an unbound agent or connector resolved as bound")
	}
}
