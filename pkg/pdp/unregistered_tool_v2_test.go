package pdp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

func newV2OwnerUnregisteredToolEvaluator(t *testing.T, now time.Time, policies []any) (*Evaluator, string) {
	t.Helper()
	bundle := v2GrantBundle(t, now, 1, policies, nil)
	var doc map[string]any
	if err := json.Unmarshal(bundle, &doc); err != nil {
		t.Fatal(err)
	}
	doc["subject"] = map[string]any{"user_id": "u-alice", "email": "alice@example.test", "groups": []string{"members"}}
	doc["identities"] = []any{}
	bundle, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	policybundle.SetV2SchemaValidator(func([]byte) error { return nil })
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(nil) })
	sessions := NewSessions()
	sessionID, err := sessions.CreatePinned(Subject{UserID: "u-alice", Email: "alice@example.test", Source: "installation_owner", ExternalID: "u-alice", Status: StatusLinked, Groups: []string{"members"}})
	if err != nil {
		t.Fatal(err)
	}
	e, _, _ := newTestEvaluator(t, now, bundle, sessions)
	return e, sessionID
}

func TestAuthorizeV2UnregisteredToolUsesOwnerPoliciesByName(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name       string
		tool       string
		policies   []any
		wantAllow  bool
		wantReason ReasonCode
	}{
		{
			name:      "group policy permits unregistered tool",
			tool:      "custom.read",
			policies:  []any{v2GrantPermitPolicy("group:members", "custom.read")},
			wantAllow: true,
		},
		{
			name:       "group policy denies unregistered tool",
			tool:       "custom.write",
			policies:   []any{v2GrantDenyPolicy("group:members", "custom.write")},
			wantReason: "policy_deny",
		},
		{
			name:       "unmatched unregistered tool remains a PDP deny",
			tool:       "custom.unmatched",
			wantReason: "no_matching_policy",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, sessionID := newV2OwnerUnregisteredToolEvaluator(t, now, tc.policies)
			decision, err := e.AuthorizeV2UnregisteredTool(context.Background(), Request{Session: sessionID, Tool: tc.tool, AgentID: testAgent})
			if err != nil {
				t.Fatal(err)
			}
			if decision.Allow != tc.wantAllow || decision.ReasonCode != tc.wantReason {
				t.Fatalf("decision=%+v, want allow=%v reason=%q", decision, tc.wantAllow, tc.wantReason)
			}
		})
	}
}

func TestAuthorizeV2UnregisteredToolDoesNotDeferForSDKCaller(t *testing.T) {
	now := time.Now().UTC()
	e, sessionID := newV2OwnerUnregisteredToolEvaluator(t, now, nil)
	decision, err := e.Evaluate(context.Background(), Request{Session: sessionID, Tool: "custom.unmatched"})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allow || decision.ReasonCode != "preflight_required" {
		t.Fatalf("SDK/PDP decision=%+v, want a non-permit decision", decision)
	}
}
