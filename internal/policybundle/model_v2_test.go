package policybundle

import (
	"encoding/json"
	"testing"
	"time"
)

func v2ModelBundle(t *testing.T, now time.Time, assignments []any) *Verified {
	t.Helper()
	doc := v2BundleDoc(now)
	if assignments != nil {
		doc["agent_model_profiles"] = assignments
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := v2SchemaValidator(t)(raw); err != nil {
		t.Fatalf("v2 model bundle does not match the schema: %v", err)
	}
	var payload Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	return &Verified{Payload: payload, PayloadBytes: raw, Digest: "sha256:test-v2-model"}
}

func TestEvaluateV2ModelAllowsOnlyTheAgentsActiveAssignment(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	subject := &SessionSubject{UserID: "user-alice", Source: "discord", ExternalID: "ext-alice", Status: SubjectLinked}
	assignments := []any{
		map[string]any{"agent_id": "agent-a", "profile_id": "profile-a", "status": "active"},
		map[string]any{"agent_id": "agent-b", "profile_id": "profile-a", "status": "active"},
		map[string]any{"agent_id": "agent-c", "profile_id": "profile-c", "status": "revoked"},
	}
	for _, tc := range []struct {
		name, agent, profile, outcome, reason string
		assignments                           []any
		subject                               *SessionSubject
		at                                    time.Time
	}{
		{"assigned", "agent-a", "profile-a", "allow", ReasonModelAssigned, assignments, subject, now},
		{"shared profile", "agent-b", "profile-a", "allow", ReasonModelAssigned, assignments, subject, now},
		{"other profile", "agent-a", "profile-c", "deny", ReasonModelNotAssigned, assignments, subject, now},
		{"unassigned agent", "agent-z", "profile-a", "deny", ReasonModelNotAssigned, assignments, subject, now},
		{"empty agent", "", "profile-a", "deny", ReasonModelNotAssigned, assignments, subject, now},
		{"empty profile", "agent-a", "", "deny", ReasonModelNotAssigned, assignments, subject, now},
		{"inactive assignment", "agent-c", "profile-c", "deny", ReasonModelProfileInactive, assignments, subject, now},
		{"field absent", "agent-a", "profile-a", "deny", ReasonModelNotAssigned, nil, subject, now},
		{"no subject", "agent-a", "profile-a", "deny", "subject_unlinked", assignments, nil, now},
		{"revoked subject", "agent-a", "profile-a", "deny", "subject_revoked", assignments, &SessionSubject{UserID: "user-alice", Source: "discord", ExternalID: "ext-alice", Status: SubjectRevoked}, now},
		{"stale snapshot is now fresh", "agent-a", "profile-a", "allow", ReasonModelAssigned, assignments, subject, now.Add(31 * time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := v2ModelBundle(t, now, tc.assignments).EvaluateV2Model(tc.profile, tc.agent, tc.subject, tc.at)
			if d.Outcome != tc.outcome || d.ReasonCode != tc.reason {
				t.Fatalf("decision = %+v, want %s/%s", d, tc.outcome, tc.reason)
			}
		})
	}
}

func TestV2SchemaRejectsMalformedModelAssignments(t *testing.T) {
	validate := v2SchemaValidator(t)
	for name, entry := range map[string]any{
		"unknown status": map[string]any{"agent_id": "agent-a", "profile_id": "profile-a", "status": "enabled"},
		"missing status": map[string]any{"agent_id": "agent-a", "profile_id": "profile-a"},
		"extra field":    map[string]any{"agent_id": "agent-a", "profile_id": "profile-a", "status": "active", "model": "gpt"},
	} {
		t.Run(name, func(t *testing.T) {
			doc := v2BundleDoc(time.Now())
			doc["agent_model_profiles"] = []any{entry}
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if validate(raw) == nil {
				t.Fatal("schema accepted a malformed agent_model_profiles entry")
			}
		})
	}
}
