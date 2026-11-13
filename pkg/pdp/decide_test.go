package pdp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

func TestDecideUnregisteredToolForTheOwnerSessionUsesTheTrustedAgent(t *testing.T) {
	now := time.Now().UTC()
	e, owner := newV2OwnerUnregisteredToolEvaluator(t, now, []any{
		v2GrantPermitPolicy("group:members", "custom.read"),
		v2GrantPermitPolicy("group:members", "mcp:linear.create_issue_a1b2c3d4"),
	})
	res, err := e.Decide(context.Background(), DecideRequest{
		Session: owner, Target: Target{Tool: "custom.read"}, TrustedAgent: testAgent, OwnerSession: true,
	})
	if err != nil || !res.Allow || !res.AuditTrustedAgent {
		t.Fatalf("result=%+v err=%v", res, err)
	}

	mcp, err := e.Decide(context.Background(), DecideRequest{
		Session: owner, Target: Target{Tool: "mcp:linear.create_issue_a1b2c3d4"}, TrustedAgent: testAgent, OwnerSession: true,
	})
	if err != nil || !mcp.Allow || !mcp.AuditTrustedAgent {
		t.Fatalf("unregistered Pi MCP tool with an exact policy = %+v err=%v", mcp, err)
	}
}

func TestDecideDeniesWithoutATrustedAgentOrForAnotherAgent(t *testing.T) {
	now := time.Now().UTC()
	e, owner := newV2OwnerUnregisteredToolEvaluator(t, now, []any{v2GrantPermitPolicy("group:members", "custom.read")})
	for _, tc := range []struct {
		name string
		req  DecideRequest
		want ReasonCode
	}{
		{"no trusted agent", DecideRequest{Session: owner, Target: Target{Tool: "custom.read"}, OwnerSession: true}, ReasonAgentNotAssigned},
		{"another agent", DecideRequest{Session: owner, Target: Target{Tool: "custom.read"}, AgentID: "attacker", TrustedAgent: testAgent, OwnerSession: true}, ReasonAgentMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := e.Decide(context.Background(), tc.req)
			if err != nil || res.Allow || res.ReasonCode != tc.want || !res.AuditTrustedAgent {
				t.Fatalf("result=%+v err=%v; want deny %s", res, err, tc.want)
			}
		})
	}
}

func TestDecideShellTargetFlagsAnUnmatchedCommand(t *testing.T) {
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	sessions := NewSessions()
	sessionID, err := sessions.Create(Subject{UserID: "u-alice", Source: "discord", ExternalID: "discord-alice", Status: StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	policies := []map[string]any{shellPolicy("allow", "user:u-alice", "shell:git status", "permit", 10, nil)}
	e, _, _ := newTestEvaluator(t, now, shellV2Bundle(t, now, []map[string]any{linkedIdentity("engineering")}, policies), sessions)

	res, err := e.Decide(context.Background(), DecideRequest{Session: sessionID, Target: Target{Shell: "git status"}, TrustedAgent: testAgent})
	if err != nil || !res.Allow || res.Unmatched {
		t.Fatalf("permitted result=%+v err=%v", res, err)
	}
	res, err = e.Decide(context.Background(), DecideRequest{Session: sessionID, Target: Target{Shell: "ls"}, TrustedAgent: testAgent})
	if err != nil || res.Allow || !res.Unmatched || res.ReasonCode != ReasonNoMatchingPolicy {
		t.Fatalf("unmatched result=%+v err=%v", res, err)
	}
	res, err = e.Decide(context.Background(), DecideRequest{Session: sessionID, Target: Target{Shell: "ls"}})
	if err != nil || res.Allow || res.ReasonCode != ReasonAgentNotAssigned {
		t.Fatalf("no trusted agent result=%+v err=%v", res, err)
	}
}

func registryShellBundle(t *testing.T, now time.Time, kinds []any, policies []map[string]any) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(shellV2Bundle(t, now, []map[string]any{linkedIdentity("engineering")}, policies), &doc); err != nil {
		t.Fatal(err)
	}
	if kinds != nil {
		doc["harness_kinds"] = kinds
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func registryKinds() []any {
	return []any{
		map[string]any{"kind": "pi", "tool_prefix": "pi.", "shell_tool": "pi.bash", "gateable": true, "decides_via": "pdp"},
		map[string]any{"kind": "viapdp", "tool_prefix": "viapdp.", "shell_tool": "viapdp.shell", "gateable": true, "decides_via": "pdp"},
		map[string]any{"kind": "claude_code", "tool_prefix": "claude_code.", "shell_tool": "claude_code.bash", "gateable": true, "decides_via": "native"},
	}
}

func TestShellKindForToolReadsTheBundleRegistry(t *testing.T) {
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	for name, tc := range map[string]struct {
		bundle []byte
		tool   string
		kind   string
		ok     bool
	}{
		"no registry, the generic shell tool": {registryShellBundle(t, now, nil, nil), "shell", "pi", true},
		"no registry, legacy pi.bash":         {registryShellBundle(t, now, nil, nil), "pi.bash", "", false},
		"no registry, another tool":           {registryShellBundle(t, now, nil, nil), "viapdp.shell", "", false},
		"registry kind that decides via pdp":  {registryShellBundle(t, now, registryKinds(), nil), "viapdp.shell", "viapdp", true},
		"registry lists pi":                   {registryShellBundle(t, now, registryKinds(), nil), "pi.bash", "pi", true},
		"registry keeps the generic shell":    {registryShellBundle(t, now, registryKinds(), nil), "shell", "pi", true},
		"native kind is not a pdp shell":      {registryShellBundle(t, now, registryKinds(), nil), "claude_code.bash", "", false},
		"cold start, the generic shell tool":  {nil, "shell", "pi", true},
		"cold start, legacy pi.bash":          {nil, "pi.bash", "", false},
		"cold start, another tool":            {nil, "viapdp.shell", "", false},
	} {
		t.Run(name, func(t *testing.T) {
			e, _, _ := newTestEvaluator(t, now, tc.bundle, NewSessions())
			kind, ok := e.ShellKindForTool(tc.tool)
			if kind != tc.kind || ok != tc.ok {
				t.Fatalf("ShellKindForTool(%q) = %q, %v; want %q, %v", tc.tool, kind, ok, tc.kind, tc.ok)
			}
		})
	}
}

func TestDecideShellTargetIsAttributedToItsKind(t *testing.T) {
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	sessions := NewSessions()
	sessionID, err := sessions.Create(Subject{UserID: "u-alice", Source: "discord", ExternalID: "discord-alice", Status: StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	policies := []map[string]any{shellPolicy("viapdp-allow", "harness:viapdp", "shell:git status", "permit", 10, nil)}
	e, _, _ := newTestEvaluator(t, now, registryShellBundle(t, now, registryKinds(), policies), sessions)
	res, err := e.Decide(context.Background(), DecideRequest{Session: sessionID, Target: Target{Shell: "git status", ShellKind: "viapdp"}, TrustedAgent: testAgent})
	if err != nil || !res.Allow || res.PolicyID != "viapdp-allow" {
		t.Fatalf("own kind: result=%+v err=%v", res, err)
	}
	res, err = e.Decide(context.Background(), DecideRequest{Session: sessionID, Target: Target{Shell: "git status"}, TrustedAgent: testAgent})
	if err != nil || res.Allow || !res.Unmatched {
		t.Fatalf("default kind is pi, a harness:viapdp policy must not match it: result=%+v err=%v", res, err)
	}
}
