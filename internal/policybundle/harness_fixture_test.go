package policybundle

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixtureSuite struct {
	Description string        `json:"description"`
	Semantics   string        `json:"semantics"`
	Cases       []fixtureCase `json:"cases"`
}

type fixtureCase struct {
	ID          string          `json:"id"`
	Desc        string          `json:"desc"`
	Call        fixtureCall     `json:"call"`
	Policies    []fixturePolicy `json:"policies"`
	WantOutcome string          `json:"want_outcome"`
	WantPolicy  string          `json:"want_policy,omitempty"`
	WantReason  string          `json:"want_reason,omitempty"`
}

type fixtureCall struct {
	Kind      string   `json:"kind,omitempty"`
	HarnessID string   `json:"harness_id,omitempty"`
	AgentID   string   `json:"agent_id,omitempty"`
	Tool      string   `json:"tool,omitempty"`
	Argv      []string `json:"argv,omitempty"`
	Skill     string   `json:"skill,omitempty"`
	Path      string   `json:"path,omitempty"`
	Home      string   `json:"home,omitempty"`
	MCPServer string   `json:"mcp_server,omitempty"`
	MCPTool   string   `json:"mcp_tool,omitempty"`
}

type fixturePolicy struct {
	ID      string `json:"id"`
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	Action  string `json:"action"`
	Enabled bool   `json:"enabled"`
	Scope   string `json:"scope_agent_id,omitempty"`
}

const (
	fixtureInstallation = "inst-fixture-0001"
	fixtureOrg          = "org-fixture-0001"
	fixtureWorkspace    = "ws-fixture-0001"
)

func testNow() time.Time { return time.Date(2026, 1, 1, 0, 5, 0, 0, time.UTC) }

func fixtureContractsDir(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/HaikeiLabs/kei-connector-contracts")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("finding contracts module: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func TestEvaluateHarnessWithContractsFixtures(t *testing.T) {
	contractsDir := fixtureContractsDir(t)
	raw, err := os.ReadFile(filepath.Join(contractsDir, "harnessmatch", "testdata", "cases.v1.json"))
	if err != nil {
		t.Fatalf("loading fixture file: %v", err)
	}
	var suite fixtureSuite
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatalf("parsing fixture file: %v", err)
	}
	if len(suite.Cases) == 0 {
		t.Fatal("no test cases in fixture file")
	}

	// Verify the same Validate works with the canonical example bundle.
	exampleBundle, err := os.ReadFile("../../docs/contracts/examples/policy-bundle-v1.payload.example.json")
	if err != nil {
		t.Fatalf("reading example bundle: %v", err)
	}
	if _, err := Validate(exampleBundle, fixtureInstallation, fixtureOrg, fixtureWorkspace, 0, fixtureNow()); err != nil {
		t.Fatalf("example bundle Validate: %v", err)
	}
	t.Log("example bundle validates OK")

	for _, tc := range suite.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			bundle := buildFixtureBundle(t, tc.Policies)
			v, err := Validate(bundle, fixtureInstallation, fixtureOrg, fixtureWorkspace, 0, testNow())
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			call := HarnessCall{
				Kind:      tc.Call.Kind,
				HarnessID: tc.Call.HarnessID,
				AgentID:   tc.Call.AgentID,
				Tool:      tc.Call.Tool,
				Argv:      tc.Call.Argv,
				Skill:     tc.Call.Skill,
				Path:      tc.Call.Path,
				Home:      tc.Call.Home,
				MCPServer: tc.Call.MCPServer,
				MCPTool:   tc.Call.MCPTool,
			}
			outcome, policyID, reason := v.EvaluateHarness(call)
			if outcome != tc.WantOutcome {
				t.Errorf("outcome: got %q, want %q", outcome, tc.WantOutcome)
			}
			if tc.WantPolicy != "" && policyID != tc.WantPolicy {
				t.Errorf("policy: got %q, want %q", policyID, tc.WantPolicy)
			}
			if tc.WantReason != "" && reason != tc.WantReason {
				t.Errorf("reason: got %q, want %q", reason, tc.WantReason)
			}
		})
	}
}

// buildFixtureBundle constructs a minimal valid policy bundle JSON payload
// from the given fixture policies. Disabled policies are excluded (the bundle
// only carries enabled policies; harnessmatch.Evaluate skips disabled ones).
func buildFixtureBundle(t *testing.T, policies []fixturePolicy) []byte {
	t.Helper()
	var ps []map[string]any
	for i, fp := range policies {
		if !fp.Enabled {
			continue
		}
		var agent any
		if fp.Scope != "" {
			agent = fp.Scope
		}
		ps = append(ps, map[string]any{
			"id":                fp.ID,
			"name":              "p" + fp.ID[len(fp.ID)-1:],
			"src_pattern":       fp.Src,
			"dst_pattern":       fp.Dst,
			"action":            fp.Action,
			"priority":          1000 - i,
			"enabled":           true,
			"approval_required": false,
			"scope": map[string]any{
				"org_id":       fixtureOrg,
				"workspace_id": fixtureWorkspace,
				"agent_id":     agent,
			},
		})
	}
	bundle := map[string]any{
		"schema":          "kei.policy-bundle/v1",
		"bundle_id":       "fixture-bundle",
		"bundle_version":  1,
		"policy_revision": 1,
		"issuer":          Issuer,
		"audience": map[string]any{
			"installation_id": fixtureInstallation,
			"org_id":          fixtureOrg,
			"workspace_id":    fixtureWorkspace,
		},
		"issued_at": "2026-01-01T00:00:00Z",
		"not_after": "2026-01-01T12:00:00Z",
		"refresh": map[string]any{
			"poll_interval_seconds": 300,
			"stale_after_seconds":   900,
		},
		"subject_resolution": map[string]any{
			"mode":              "online",
			"max_cache_seconds": 30,
		},
		"policy_set": map[string]any{
			"match_semantics": "kei.match/v1",
			"evaluation": map[string]any{
				"order":   "array_order_first_match",
				"default": "deny",
			},
			"groups":   []any{},
			"tools":    []any{},
			"agents":   []any{},
			"policies": ps,
		},
		"agent_connector_bindings": []any{},
	}
	out, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal fixture bundle: %v", err)
	}
	return out
}
