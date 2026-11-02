package run

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/invoke"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// accessRecords returns the decision-class credential access records the
// daemon appended (lines with credential_kind and no event_class).
func (rig *runDescriptorRig) accessRecords() []map[string]json.RawMessage {
	rig.t.Helper()
	var out []map[string]json.RawMessage
	for _, line := range rig.audit {
		var rec map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			rig.t.Fatalf("audit line %q: %v", line, err)
		}
		if _, ok := rec["event_class"]; ok {
			continue
		}
		if _, ok := rec["credential_kind"]; ok {
			out = append(out, rec)
		}
	}
	return out
}

func str(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("%s is not a string: %v", raw, err)
	}
	return s
}

func TestDaemonRunRecordsSecretStoreCredentialAccess(t *testing.T) {
	rig := newRunDescriptorRig(t)
	out := rig.run()
	if out.done.Decision != "allow" {
		t.Fatalf("done = %+v", out.done)
	}
	recs := rig.accessRecords()
	if len(recs) != 1 {
		t.Fatalf("access records = %d, want 1 (audit %v)", len(recs), rig.audit)
	}
	rec := recs[0]
	want := map[string]string{
		"credential_kind":  "secret_store",
		"tool_name":        "connector:" + runDescriptorConnector + "/credential",
		"decision":         "allow",
		"invoking_subject": "user:user-378",
		"framework":        "kei-proxy-run",
	}
	for k, v := range want {
		if got := str(t, rec[k]); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	var resources []string
	_ = json.Unmarshal(rec["resources_touched"], &resources)
	if len(resources) != 1 || resources[0] != runDescriptorRef {
		t.Errorf("resources_touched = %v, want [%s]", resources, runDescriptorRef)
	}
	if str(t, rec["span_id"]) == "" || len(rec["invoked_at"]) == 0 {
		t.Errorf("record lacks span_id/invoked_at: %v", rec)
	}
	for _, k := range []string{"credential_released", "session_id"} {
		if _, ok := rec[k]; ok {
			t.Errorf("access record carries %s; release status stays in the session", k)
		}
	}
	rig.assertNoLeak(out)
}

func TestDaemonRunRecordsAccessWhenTheChildFails(t *testing.T) {
	rig := newRunDescriptorRig(t)
	out := rig.runWith([]string{"/bin/sh", "-c", "exit 3"}, []string{"PATH=/usr/bin:/bin", "API_KEY=" + runDescriptorRef})
	if out.done.ExitCode != 3 {
		t.Fatalf("done = %+v", out.done)
	}
	if recs := rig.accessRecords(); len(recs) != 1 {
		t.Fatalf("access records = %d, want 1: the credential reached the child", len(recs))
	}
}

func TestDaemonRunRecordsOAuthCredentialAccess(t *testing.T) {
	rig := newRunDescriptorRig(t)
	rig.grant.Provider = "github"
	rig.grant.Connector = &policybundle.Connector{ID: runDescriptorConnector, Provider: "github", CredentialSource: "oauth", AccountModel: "per_user"}
	rig.daemon.UseCredential = func(_ context.Context, _, _, _ string, fn func(string) error) error {
		return fn(runDescriptorSentinel)
	}
	rig.daemon.Authorize = func(context.Context, invoke.DaemonCall) (invoke.Grant, error) { return rig.grant, nil }
	out := rig.runWith([]string{"/bin/sh", "-c", "true"}, []string{"PATH=/usr/bin:/bin", "GH_TOKEN=kei://connectors/" + runDescriptorConnector + "/token"})
	if out.done.Decision != "allow" {
		t.Fatalf("done = %+v", out.done)
	}
	recs := rig.accessRecords()
	if len(recs) != 1 || str(t, recs[0]["credential_kind"]) != "oauth" {
		t.Fatalf("access records = %v, want one oauth record", recs)
	}
	rig.assertNoLeak(out)
}

func TestDaemonRunRecordsNoAccessWithoutHandingOutACredential(t *testing.T) {
	for name, mutate := range map[string]func(*runDescriptorRig){
		"policy deny":            func(r *runDescriptorRig) { r.grant.Allow, r.grant.ReasonCode = false, "policy_deny" },
		"secret never delivered": func(r *runDescriptorRig) { r.store.values = map[string]string{} },
	} {
		t.Run(name, func(t *testing.T) {
			rig := newRunDescriptorRig(t)
			mutate(rig)
			if out := rig.run(); out.done.Decision != "deny" {
				t.Fatalf("done = %+v, want deny", out.done)
			}
			if recs := rig.accessRecords(); len(recs) != 0 {
				t.Fatalf("access records on a deny: %v", recs)
			}
		})
	}
	t.Run("command not started", func(t *testing.T) {
		rig := newRunDescriptorRig(t)
		rig.runWith([]string{"/kei-no-such-command-credkind"}, []string{"PATH=/usr/bin:/bin", "API_KEY=" + runDescriptorRef})
		if recs := rig.accessRecords(); len(recs) != 0 {
			t.Fatalf("access records for a command that never started: %v", recs)
		}
	})
}
