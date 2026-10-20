package pdp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

func piShellPolicy(id, src, dst, action string, priority int, agentScope any) map[string]any {
	return map[string]any{
		"policy_id": id, "name": id, "src_pattern": src, "dst_pattern": dst,
		"action": action, "priority": priority,
		"scope": map[string]any{"org_id": testOrg, "workspace_id": testWorkspace, "agent_id": agentScope},
	}
}

func piShellV2Bundle(t *testing.T, now time.Time, identities []map[string]any, policies []map[string]any) []byte {
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

func linkedPiIdentity(groups ...string) map[string]any {
	return map[string]any{
		"source": "discord", "external_id": "discord-alice", "user_id": "u-alice",
		"status": "linked", "groups": groups,
	}
}

func TestAuthorizePiShellUsesSessionMembershipAndOrderedV2Policies(t *testing.T) {
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	identity := linkedPiIdentity("engineering")
	tests := []struct {
		name     string
		policies []map[string]any
		allow    bool
		policyID string
	}{
		{
			name:     "user source permit",
			policies: []map[string]any{piShellPolicy("user-allow", "user:u-alice", "shell:git status", "permit", 10, nil)},
			allow:    true, policyID: "user-allow",
		},
		{
			name:     "user source deny",
			policies: []map[string]any{piShellPolicy("user-deny", "user:u-alice", "shell:git status", "deny", 10, nil)},
			allow:    false, policyID: "user-deny",
		},
		{
			name:     "group source permit",
			policies: []map[string]any{piShellPolicy("group-allow", "group:engineering", "shell:git status", "permit", 10, nil)},
			allow:    true, policyID: "group-allow",
		},
		{
			name:     "group source deny",
			policies: []map[string]any{piShellPolicy("group-deny", "group:engineering", "shell:git status", "deny", 10, nil)},
			allow:    false, policyID: "group-deny",
		},
		{
			name: "deny wins equal priority across matching user and group sources",
			policies: []map[string]any{
				piShellPolicy("user-permit", "user:u-alice", "shell:git status", "permit", 20, nil),
				piShellPolicy("group-deny", "group:engineering", "shell:git status", "deny", 20, nil),
			},
			allow: false, policyID: "group-deny",
		},
		{
			name: "higher priority permit precedes lower priority deny",
			policies: []map[string]any{
				piShellPolicy("group-deny", "group:engineering", "shell:git status", "deny", 10, nil),
				piShellPolicy("user-permit", "user:u-alice", "shell:git status", "permit", 20, nil),
			},
			allow: true, policyID: "user-permit",
		},
		{
			name:     "Pi harness source permit",
			policies: []map[string]any{piShellPolicy("harness-allow", "harness:pi", "shell:git status", "permit", 10, nil)},
			allow:    true, policyID: "harness-allow",
		},
		{
			name:     "agent source permit uses trusted default agent",
			policies: []map[string]any{piShellPolicy("agent-allow", "agent:"+testAgent, "shell:git status", "permit", 10, nil)},
			allow:    true, policyID: "agent-allow",
		},
		{
			name:     "assigned agent scope uses trusted default agent",
			policies: []map[string]any{piShellPolicy("scoped", "agent:"+testAgent, "shell:git status", "permit", 10, testAgent)},
			allow:    true, policyID: "scoped",
		},
		{
			name:     "caller-selected different agent does not match trusted assignment",
			policies: []map[string]any{piShellPolicy("scoped", "agent:attacker-agent", "shell:git status", "permit", 10, "attacker-agent")},
			allow:    false,
		},
		{
			name:     "tool grant is not a shell grant",
			policies: []map[string]any{piShellPolicy("broad-tool", "*", "tool:pi.bash", "permit", 1000, nil)},
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
			bundle := piShellV2Bundle(t, now, []map[string]any{identity}, tc.policies)
			e, _, _ := newTestEvaluator(t, now, bundle, sessions)
			d, err := e.AuthorizePiShell(context.Background(), sessionID, "git status --short", testAgent)
			if err != nil {
				t.Fatal(err)
			}
			if d.Allow != tc.allow || d.PolicyID != tc.policyID {
				t.Fatalf("decision=%+v; want allow=%v policy=%q", d, tc.allow, tc.policyID)
			}
		})
	}
}

func TestAuthorizePiShellFailsClosedWithoutSessionMembershipOrAssignedAgent(t *testing.T) {
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	policies := []map[string]any{piShellPolicy("group-allow", "group:engineering", "shell:git status", "permit", 10, nil)}

	t.Run("missing session", func(t *testing.T) {
		e, _, _ := newTestEvaluator(t, now, piShellV2Bundle(t, now, []map[string]any{linkedPiIdentity("engineering")}, policies), NewSessions())
		d, err := e.AuthorizePiShell(context.Background(), DefaultSession, "git status", testAgent)
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
		e, _, _ := newTestEvaluator(t, now, piShellV2Bundle(t, now, []map[string]any{}, policies), sessions)
		d, err := e.AuthorizePiShell(context.Background(), sessionID, "git status", testAgent)
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
		e, _, _ := newTestEvaluator(t, now, piShellV2Bundle(t, now, []map[string]any{linkedPiIdentity("engineering")}, policies), sessions)
		d, err := e.AuthorizePiShell(context.Background(), sessionID, "git status", "")
		if err != nil || d.Allow || d.ReasonCode != "agent_not_assigned" {
			t.Fatalf("decision=%+v err=%v", d, err)
		}
	})
}
