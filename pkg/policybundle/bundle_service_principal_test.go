package policybundle

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// One malformed service-principal identity is dropped and logged by id (never
// its token) instead of rejecting the whole bundle, so user identities, valid
// principals and policies still load.
func TestValidateV2DropsMalformedServicePrincipalIdentity(t *testing.T) {
	// The shared schema validator only knows user identities.
	SetV2SchemaValidator(func(raw []byte) error {
		if bytes.Contains(raw, []byte(`"subject_type"`)) {
			t.Errorf("schema validator saw a principal entry: %s", raw)
		}
		return nil
	})
	t.Cleanup(func() { SetV2SchemaValidator(nil) })
	now := time.Now().UTC()
	expire := now.Add(time.Hour).Format(time.RFC3339)
	good := map[string]any{"subject_type": "service_principal", "service_principal_id": "sp-good", "agent_id": "agent-1", "groups": []string{"sre"}, "subject_token": "GOOD-SECRET-TOKEN", "expire_time": expire}
	bad := func(edit func(map[string]any)) map[string]any {
		entry := map[string]any{"subject_type": "service_principal", "service_principal_id": "sp-bad", "agent_id": "agent-1", "groups": []string{}, "subject_token": "BAD-SECRET-TOKEN", "expire_time": expire}
		edit(entry)
		return entry
	}
	tests := []struct {
		name   string
		entry  map[string]any
		logsID string
	}{
		{name: "missing groups", entry: bad(func(e map[string]any) { delete(e, "groups") }), logsID: "sp-bad"},
		{name: "null groups", entry: bad(func(e map[string]any) { e["groups"] = nil }), logsID: "sp-bad"},
		{name: "empty subject token", entry: bad(func(e map[string]any) { e["subject_token"] = "" }), logsID: "sp-bad"},
		{name: "missing expire time", entry: bad(func(e map[string]any) { delete(e, "expire_time") }), logsID: "sp-bad"},
		{name: "invalid agent id", entry: bad(func(e map[string]any) { e["agent_id"] = "" }), logsID: "sp-bad"},
		{name: "invalid principal id", entry: bad(func(e map[string]any) { e["service_principal_id"] = "bad id!" }), logsID: "invalid"},
		{name: "invalid name", entry: bad(func(e map[string]any) { e["service_principal_name"] = "Bad Name" }), logsID: "sp-bad"},
		{name: "blank group", entry: bad(func(e map[string]any) { e["groups"] = []string{" "} }), logsID: "sp-bad"},
		{name: "duplicate group", entry: bad(func(e map[string]any) { e["groups"] = []string{"a", "a"} }), logsID: "sp-bad"},
		{name: "unknown member", entry: bad(func(e map[string]any) { e["extra"] = true }), logsID: "sp-bad"},
	}
	for _, tt := range tests {
		for _, withGood := range []bool{true, false} {
			name := tt.name
			if !withGood {
				name += " only principal"
			}
			t.Run(name, func(t *testing.T) {
				var logs bytes.Buffer
				prev := slog.Default()
				slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
				t.Cleanup(func() { slog.SetDefault(prev) })

				doc := v2BundleDoc(now)
				identities := doc["identities"].([]any)
				identities = append(identities, tt.entry)
				if withGood {
					identities = append(identities, good)
				}
				doc["identities"] = identities
				raw, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				v, err := Validate(raw, v2Installation, v2Org, v2Workspace, 1, now)
				if err != nil {
					t.Fatalf("Validate: %v; want the bundle accepted without the bad principal", err)
				}
				wantPrincipals := 0
				if withGood {
					wantPrincipals = 1
				}
				if len(v.Payload.ServicePrincipalIdentities) != wantPrincipals {
					t.Fatalf("principals = %+v; want %d", v.Payload.ServicePrincipalIdentities, wantPrincipals)
				}
				if withGood && v.Payload.ServicePrincipalIdentities[0].ServicePrincipalID != "sp-good" {
					t.Fatalf("principal = %+v; want sp-good", v.Payload.ServicePrincipalIdentities[0])
				}
				if _, ok := v.LookupIdentity("discord", "ext-alice", now); !ok {
					t.Fatal("user identity ext-alice was not loaded")
				}
				out := logs.String()
				if !strings.Contains(out, "service_principal_id="+tt.logsID) {
					t.Fatalf("log = %q; want the dropped principal's id %q", out, tt.logsID)
				}
				if strings.Contains(out, "SECRET-TOKEN") {
					t.Fatalf("log leaked a subject token: %q", out)
				}
			})
		}
	}
}
