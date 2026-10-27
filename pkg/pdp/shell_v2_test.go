package pdp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

func shellPolicy(id, src, dst, action string, priority int, agentScope any) map[string]any {
	return map[string]any{
		"policy_id": id, "name": id, "src_pattern": src, "dst_pattern": dst,
		"action": action, "priority": priority,
		"scope": map[string]any{"org_id": testOrg, "workspace_id": testWorkspace, "agent_id": agentScope},
	}
}

func shellV2Bundle(t *testing.T, now time.Time, identities []map[string]any, policies []map[string]any) []byte {
	t.Helper()
	var bundle map[string]any
	if err := json.Unmarshal(v2SnapshotBundle(t, now, 42, identities), &bundle); err != nil {
		t.Fatal(err)
	}
	set := bundle["policy_set"].(map[string]any)
	set["harness_policies"] = policies
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func linkedIdentity(groups ...string) map[string]any {
	return map[string]any{
		"source": "discord", "external_id": "discord-alice", "user_id": "u-alice",
		"status": "linked", "groups": groups,
	}
}

func TestAuthorizeShellUsesSessionMembershipAndOrderedV2Policies(t *testing.T) {
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	identity := linkedIdentity("engineering")
	tests := []struct {
		name     string
		policies []map[string]any
		allow    bool
		policyID string
	}{
		{
			name:     "user source permit",
			policies: []map[string]any{shellPolicy("user-allow", "user:u-alice", "shell:git status", "permit", 10, nil)},
			allow:    true, policyID: "user-allow",
		},
		{
			name:     "user source deny",
			policies: []map[string]any{shellPolicy("user-deny", "user:u-alice", "shell:git status", "deny", 10, nil)},
			allow:    false, policyID: "user-deny",
		},
		{
			name:     "group source permit",
			policies: []map[string]any{shellPolicy("group-allow", "group:engineering", "shell:git status", "permit", 10, nil)},
			allow:    true, policyID: "group-allow",
		},
		{
			name:     "group source deny",
			policies: []map[string]any{shellPolicy("group-deny", "group:engineering", "shell:git status", "deny", 10, nil)},
			allow:    false, policyID: "group-deny",
		},
		{
			name: "deny wins equal priority across matching user and group sources",
			policies: []map[string]any{
				shellPolicy("user-permit", "user:u-alice", "shell:git status", "permit", 20, nil),
				shellPolicy("group-deny", "group:engineering", "shell:git status", "deny", 20, nil),
			},
			allow: false, policyID: "group-deny",
		},
		{
			name: "higher priority permit precedes lower priority deny",
			policies: []map[string]any{
				shellPolicy("group-deny", "group:engineering", "shell:git status", "deny", 10, nil),
				shellPolicy("user-permit", "user:u-alice", "shell:git status", "permit", 20, nil),
			},
			allow: true, policyID: "user-permit",
		},
		{
			name:     "Pi harness source permit",
			policies: []map[string]any{shellPolicy("harness-allow", "harness:pi", "shell:git status", "permit", 10, nil)},
			allow:    true, policyID: "harness-allow",
		},
		{
			name:     "agent source permit uses trusted default agent",
			policies: []map[string]any{shellPolicy("agent-allow", "agent:"+testAgent, "shell:git status", "permit", 10, nil)},
			allow:    true, policyID: "agent-allow",
		},
		{
			name:     "assigned agent scope uses trusted default agent",
			policies: []map[string]any{shellPolicy("scoped", "agent:"+testAgent, "shell:git status", "permit", 10, testAgent)},
			allow:    true, policyID: "scoped",
		},
		{
			name:     "caller-selected different agent does not match trusted assignment",
			policies: []map[string]any{shellPolicy("scoped", "agent:attacker-agent", "shell:git status", "permit", 10, "attacker-agent")},
			allow:    false,
		},
		{
			name:     "tool grant is not a shell grant",
			policies: []map[string]any{shellPolicy("broad-tool", "*", "tool:pi.bash", "permit", 1000, nil)},
			allow:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sessions := NewSessions()
			sessionID, err := sessions.Create(Subject{UserID: "u-alice", Source: "discord", ExternalID: "discord-alice", Status: StatusLinked})
			if err != nil {
				t.Fatal(err)
			}
			bundle := shellV2Bundle(t, now, []map[string]any{identity}, tc.policies)
			e, _, _ := newTestEvaluator(t, now, bundle, sessions)
			d, err := e.AuthorizeShell(context.Background(), sessionID, "git status --short", testAgent)
			if err != nil {
				t.Fatal(err)
			}
			if d.Allow != tc.allow || d.PolicyID != tc.policyID {
				t.Fatalf("decision=%+v; want allow=%v policy=%q", d, tc.allow, tc.policyID)
			}
		})
	}
}

func TestAuthorizeShellFailsClosedWithoutSessionMembershipOrAssignedAgent(t *testing.T) {
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	policies := []map[string]any{shellPolicy("group-allow", "group:engineering", "shell:git status", "permit", 10, nil)}

	t.Run("missing session", func(t *testing.T) {
		e, _, _ := newTestEvaluator(t, now, shellV2Bundle(t, now, []map[string]any{linkedIdentity("engineering")}, policies), NewSessions())
		d, err := e.AuthorizeShell(context.Background(), DefaultSession, "git status", testAgent)
		if err != nil || d.Allow || d.ReasonCode != ReasonSessionNotFound {
			t.Fatalf("decision=%+v err=%v", d, err)
		}
	})

	t.Run("missing membership snapshot", func(t *testing.T) {
		sessions := NewSessions()
		sessionID, err := sessions.Create(Subject{UserID: "u-alice", Source: "discord", ExternalID: "discord-alice", Status: StatusLinked})
		if err != nil {
			t.Fatal(err)
		}
		e, _, _ := newTestEvaluator(t, now, shellV2Bundle(t, now, []map[string]any{}, policies), sessions)
		d, err := e.AuthorizeShell(context.Background(), sessionID, "git status", testAgent)
		if err != nil || d.Allow || (d.ReasonCode != "subject_unlinked" && d.ReasonCode != "subject_pending") {
			t.Fatalf("decision=%+v err=%v", d, err)
		}
	})

	t.Run("missing assigned agent", func(t *testing.T) {
		sessions := NewSessions()
		sessionID, err := sessions.Create(Subject{UserID: "u-alice", Source: "discord", ExternalID: "discord-alice", Status: StatusLinked})
		if err != nil {
			t.Fatal(err)
		}
		e, _, _ := newTestEvaluator(t, now, shellV2Bundle(t, now, []map[string]any{linkedIdentity("engineering")}, policies), sessions)
		d, err := e.AuthorizeShell(context.Background(), sessionID, "git status", "")
		if err != nil || d.Allow || d.ReasonCode != "agent_not_assigned" {
			t.Fatalf("decision=%+v err=%v", d, err)
		}
	})
}

func TestAuthorizeShellChecksEveryStage(t *testing.T) {
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	permit := func(id, dst string) map[string]any {
		return shellPolicy(id, "user:u-alice", "shell:"+dst, "permit", 10, nil)
	}
	deny := func(id, dst string) map[string]any {
		return shellPolicy(id, "user:u-alice", "shell:"+dst, "deny", 10, nil)
	}
	tests := []struct {
		name       string
		command    string
		policies   []map[string]any
		allow      bool
		reasonCode string
		policyID   string
	}{
		{"allow+allow=allow", "cd x && ls", []map[string]any{permit("p-cd", "cd"), permit("p-ls", "ls")}, true, "policy_permit", "p-cd"},
		{"single stage still allowed", "ls", []map[string]any{permit("p-ls", "ls")}, true, "policy_permit", "p-ls"},
		{"allow+deny=deny", "cd x && rm -rf y", []map[string]any{permit("p-cd", "cd"), deny("d-rm", "rm -rf")}, false, "policy_deny", "d-rm"},
		{"deny first, allow second", "rm -rf y && cd x", []map[string]any{permit("p-cd", "cd"), deny("d-rm", "rm -rf")}, false, "policy_deny", "d-rm"},
		{"allow+unmatched=unmatched", "cd x && whoami", []map[string]any{permit("p-cd", "cd")}, false, "no_matching_policy", ""},
		{"unmatched+allow=unmatched", "whoami && cd x", []map[string]any{permit("p-cd", "cd")}, false, "no_matching_policy", ""},
		{"unmatched+deny=deny", "whoami ; rm -rf y", []map[string]any{deny("d-rm", "rm -rf")}, false, "policy_deny", "d-rm"},
		{"deny after unmatched and allow", "cd x && whoami | rm -rf y", []map[string]any{permit("p-cd", "cd"), deny("d-rm", "rm -rf")}, false, "policy_deny", "d-rm"},
		{"unmatched+unmatched=unmatched", "a || b", nil, false, "no_matching_policy", ""},
		{"deny+deny reports first denying stage", "rm -rf y ; whoami", []map[string]any{deny("d-rm", "rm -rf"), deny("d-who", "whoami")}, false, "policy_deny", "d-rm"},
		{"pipe with redirect allowed when both permitted", "go build ./... 2>&1 | head -30", []map[string]any{permit("p-go", "go"), permit("p-head", "head")}, true, "policy_permit", "p-go"},
		{"pipe with redirect unmatched when head unpermitted", "go build ./... 2>&1 | head -30", []map[string]any{permit("p-go", "go")}, false, "no_matching_policy", ""},
		{"quoted operator is one stage", `echo "a && rm -rf y"`, []map[string]any{permit("p-echo", "echo"), deny("d-rm", "rm -rf")}, true, "policy_permit", "p-echo"},
		{"redirect stripped before matching", "rm -rf y 2>/dev/null", []map[string]any{deny("d-rm", "rm -rf")}, false, "policy_deny", "d-rm"},
		{"command substitution unsupported", "$(id)", []map[string]any{permit("p-id", "id")}, false, "unsupported_shell_syntax", ""},
		{"backticks unsupported", "ls `id`", []map[string]any{permit("p-ls", "ls")}, false, "unsupported_shell_syntax", ""},
		{"redirect to file unsupported", "ls > file", []map[string]any{permit("p-ls", "ls")}, false, "unsupported_shell_syntax", ""},
		{"one unsupported piece rejects the line", "ls && echo $HOME", []map[string]any{permit("p-ls", "ls"), permit("p-echo", "echo")}, false, "unsupported_shell_syntax", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sessions := NewSessions()
			sessionID, err := sessions.Create(Subject{UserID: "u-alice", Source: "discord", ExternalID: "discord-alice", Status: StatusLinked})
			if err != nil {
				t.Fatal(err)
			}
			bundle := shellV2Bundle(t, now, []map[string]any{linkedIdentity("engineering")}, tc.policies)
			e, _, _ := newTestEvaluator(t, now, bundle, sessions)
			d, err := e.AuthorizeShell(context.Background(), sessionID, tc.command, testAgent)
			if err != nil {
				t.Fatal(err)
			}
			if d.Allow != tc.allow || d.ReasonCode != tc.reasonCode || d.PolicyID != tc.policyID {
				t.Fatalf("decision=%+v; want allow=%v reason=%q policy=%q", d, tc.allow, tc.reasonCode, tc.policyID)
			}
		})
	}
}

func TestAuthorizeShellUnsupportedSyntaxReasonSaysWhatIsSupported(t *testing.T) {
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	sessions := NewSessions()
	sessionID, err := sessions.Create(Subject{UserID: "u-alice", Source: "discord", ExternalID: "discord-alice", Status: StatusLinked})
	if err != nil {
		t.Fatal(err)
	}
	e, _, _ := newTestEvaluator(t, now, shellV2Bundle(t, now, []map[string]any{linkedIdentity("engineering")}, nil), sessions)
	d, err := e.AuthorizeShell(context.Background(), sessionID, "ls > file", testAgent)
	if err != nil {
		t.Fatal(err)
	}
	want := "use one command, or commands joined with && || ; |; redirects other than 2>&1 and /dev/null, subshells, substitutions and globs are not supported"
	if d.Allow || d.ReasonCode != "unsupported_shell_syntax" || d.Reason != want {
		t.Fatalf("decision=%+v; want reason %q", d, want)
	}
}
