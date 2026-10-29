package pdp

import (
	"context"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

func TestDecideUnregisteredToolForTheOwnerSessionUsesTheTrustedAgent(t *testing.T) {
	now := time.Now().UTC()
	e, owner := newV2OwnerUnregisteredToolEvaluator(t, now, []any{v2GrantPermitPolicy("group:members", "custom.read")})
	res, err := e.Decide(context.Background(), DecideRequest{
		Session: owner, Target: Target{Tool: "custom.read"}, TrustedAgent: testAgent, OwnerSession: true,
	})
	if err != nil || !res.Allow || !res.AuditTrustedAgent {
		t.Fatalf("result=%+v err=%v", res, err)
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
