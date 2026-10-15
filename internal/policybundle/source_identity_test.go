package policybundle

import (
	"encoding/json"
	"testing"
	"time"
)

// HAI-669 (R2): the catalog emits each user's Entra object id as a bundle
// identity {source: "entra", external_id: "<oid>"} (from web.users
// external_id "ms:<oid>", prefix stripped). The on_behalf_of exchange looks
// it up by the session subject's user id.
func TestLookupLinkedSourceIdentity(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 30, 0, 0, time.UTC)
	doc := v2BundleDoc(now)
	doc["identities"] = []any{
		map[string]any{"source": "discord", "external_id": "ext-alice", "user_id": "user-alice", "status": "linked"},
		map[string]any{"source": "entra", "external_id": "oid-alice", "user_id": "user-alice", "status": "linked"},
		map[string]any{"source": "entra", "external_id": "oid-bob", "user_id": "user-bob", "status": "revoked"},
		map[string]any{"source": "entra", "external_id": "oid-carol-1", "user_id": "user-carol", "status": "linked"},
		map[string]any{"source": "entra", "external_id": "oid-carol-2", "user_id": "user-carol", "status": "linked"},
		map[string]any{"source": "entra", "external_id": "oid-dave", "user_id": "user-dave", "status": "linked", "expire_time": now.Add(-time.Minute).Format(time.RFC3339)},
		map[string]any{"source": "discord", "external_id": "ext-erin", "user_id": "user-erin", "status": "linked"},
	}
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ValidateV2(raw, v2Installation, v2Org, v2Workspace, 0, now)
	if err != nil {
		t.Fatalf("an entra identity must validate under the v2 schema: %v", err)
	}

	if id, ok := v.LookupLinkedSourceIdentity("user-alice", "entra", now); !ok || id.ExternalID != "oid-alice" {
		t.Fatalf("alice entra = %+v, %v", id, ok)
	}
	for name, user := range map[string]string{
		"revoked":         "user-bob",
		"ambiguous":       "user-carol",
		"expired":         "user-dave",
		"no entra source": "user-erin",
		"unknown user":    "user-zed",
		"empty user":      "",
	} {
		if id, ok := v.LookupLinkedSourceIdentity(user, "entra", now); ok {
			t.Errorf("%s: resolved %+v", name, id)
		}
	}
	// A stale subject snapshot resolves nothing.
	if _, ok := v.LookupLinkedSourceIdentity("user-alice", "entra", now.Add(-time.Hour)); ok {
		t.Error("a bundle issued in the future resolved an identity")
	}
}
