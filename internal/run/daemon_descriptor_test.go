package run

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/invoke"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// HAI-378 (ADR-034 amendment 2026-10-11): POST /v1/commands:run resolves a
// kei://connectors reference to an opaque_ref connector from the bundle's
// descriptor, the connector reference index and the tenant secret store,
// inside the daemon. The value reaches only the child's environment.

const (
	runDescriptorConnector = "00000000-0000-4000-8000-000000000378"
	runDescriptorSentinel  = "kei-sentinel-run-api-key-91c4d7"
	runDescriptorBackend   = "aws-secrets-manager"
	runDescriptorSecretRef = "aws-secrets-manager://us-west-2/kei/acme/connectors/" + runDescriptorConnector + "/api_key"
	runDescriptorRef       = "kei://connectors/" + runDescriptorConnector + "/api_key"
)

type runSecretStore struct {
	values map[string]string
	calls  int
}

func (s *runSecretStore) Get(_ context.Context, backend, ref string) (*string, error) {
	s.calls++
	v, ok := s.values[backend+"|"+ref]
	if !ok {
		return nil, errors.New("secret not found")
	}
	return &v, nil
}

type runDescriptorRig struct {
	t      *testing.T
	daemon *Daemon
	grant  invoke.Grant
	index  string
	store  *runSecretStore
	audit  []string
	marker string
}

func newRunDescriptorRig(t *testing.T) *runDescriptorRig {
	t.Helper()
	rig := &runDescriptorRig{t: t, store: &runSecretStore{values: map[string]string{runDescriptorBackend + "|" + runDescriptorSecretRef: runDescriptorSentinel}}}
	rig.index = credentials.ConnectorIndexPath(filepath.Join(t.TempDir(), "state"))
	if err := credentials.WriteConnectorReference(rig.index, credentials.ConnectorReference{ConnectorID: runDescriptorConnector, Field: "api_key", SecretBackend: runDescriptorBackend, SecretRef: runDescriptorSecretRef, Generation: 1}); err != nil {
		t.Fatal(err)
	}
	rig.marker = filepath.Join(t.TempDir(), "child-ran")
	rig.grant = invoke.Grant{
		Allow: true, HasSession: true, Subject: "user-378", Provider: "http_api", ConnectorID: runDescriptorConnector, Descriptors: true,
		Connector: &policybundle.Connector{
			ID: runDescriptorConnector, Name: "crm", Provider: "http_api", CredentialSource: "opaque_ref", AccountModel: "shared",
			CredentialRef: runDescriptorRef, CredentialBackend: runDescriptorBackend,
		},
	}
	rig.daemon = &Daemon{
		Authorize: func(_ context.Context, call invoke.DaemonCall) (invoke.Grant, error) {
			if call.Capability != runCapability || call.Resource != runDescriptorRef {
				t.Errorf("authorized %s on %s", call.Capability, call.Resource)
			}
			return rig.grant, nil
		},
		UseCredential: func(context.Context, string, string, string, func(string) error) error {
			return errors.New("an opaque_ref descriptor must not use the session credential store")
		},
		AppendAudit: func(record []byte) error {
			rig.audit = append(rig.audit, string(record))
			return nil
		},
		Secrets: invoke.SecretResolver{IndexPath: rig.index, Store: rig.store},
	}
	return rig
}

type runOutcome struct {
	stdout, stderr string
	done           runDone
	raw            string
}

// run runs a child that reports the length of $API_KEY, then prints the
// value on stdout and stderr (which the daemon must redact), and touches the
// marker file.
func (rig *runDescriptorRig) run() runOutcome {
	rig.t.Helper()
	script := fmt.Sprintf(`touch %q; printf 'len=%%s\n' "${#API_KEY}"; printf 'raw=%%s\n' "$API_KEY"; printf 'err-raw=%%s\n' "$API_KEY" >&2`, rig.marker)
	return rig.runWith([]string{"/bin/sh", "-c", script}, []string{"PATH=/usr/bin:/bin", "API_KEY=" + runDescriptorRef})
}

// runWith runs argv with env through the daemon route and collects the frames.
func (rig *runDescriptorRig) runWith(argv, env []string) runOutcome {
	rig.t.Helper()
	body, _ := json.Marshal(daemonRunRequest{Schema: daemonRunSchema, Argv: argv, Env: env})
	req := httptest.NewRequest(http.MethodPost, DaemonRunPath, bytes.NewReader(body))
	session.SetHeader(req, "ks_run_378")
	rec := httptest.NewRecorder()
	rig.daemon.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		rig.t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	out := runOutcome{raw: rec.Body.String()}
	scanner := bufio.NewScanner(strings.NewReader(out.raw))
	for scanner.Scan() {
		var frame runFrame
		if err := json.Unmarshal(scanner.Bytes(), &frame); err != nil {
			rig.t.Fatalf("frame %q: %v", scanner.Text(), err)
		}
		switch {
		case frame.Done != nil:
			out.done = *frame.Done
		case frame.Stream == "stdout":
			out.stdout += string(frame.Data)
		case frame.Stream == "stderr":
			out.stderr += string(frame.Data)
		}
	}
	return out
}

func (rig *runDescriptorRig) assertNoLeak(out runOutcome) {
	rig.t.Helper()
	for name, text := range map[string]string{"socket stream": out.raw + out.stdout + out.stderr, "audit": strings.Join(rig.audit, "\n")} {
		if strings.Contains(text, runDescriptorSentinel) || strings.Contains(text, runDescriptorSecretRef) {
			rig.t.Fatalf("%s leaked the credential or its location:\n%s", name, text)
		}
	}
}

func TestDaemonRunResolvesDescriptorSecretIntoChildOnly(t *testing.T) {
	rig := newRunDescriptorRig(t)
	out := rig.run()
	if out.done.Decision != "allow" || out.done.ExitCode != 0 {
		t.Fatalf("done = %+v\n%s", out.done, out.raw)
	}
	if !strings.Contains(out.stdout, fmt.Sprintf("len=%d", len(runDescriptorSentinel))) {
		t.Fatalf("child did not receive the resolved credential: %q", out.stdout)
	}
	// Redaction replaces only the exact resolved value, so this also shows
	// the child's value was the sentinel.
	if !strings.Contains(out.stdout, "raw=[REDACTED]") || !strings.Contains(out.stderr, "err-raw=[REDACTED]") {
		t.Fatalf("child output not redacted: stdout=%q stderr=%q", out.stdout, out.stderr)
	}
	rig.assertNoLeak(out)
	if rig.store.calls != 1 || len(rig.audit) != 1 || !strings.Contains(rig.audit[0], runDescriptorConnector) {
		t.Fatalf("store reads %d, audit %v", rig.store.calls, rig.audit)
	}
}

func TestDaemonRunDescriptorDenyMatrix(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(rig *runDescriptorRig)
		want   string
	}{
		"bundle without descriptors runs no opaque_ref connector": {func(r *runDescriptorRig) { r.grant.Descriptors, r.grant.Connector = false, nil }, "credential_source_not_supported"},
		"connector routed but no descriptor":                      {func(r *runDescriptorRig) { r.grant.Connector = nil }, "descriptor_invalid"},
		"descriptor names another connector":                      {func(r *runDescriptorRig) { r.grant.Connector.ID = "00000000-0000-4000-8000-000000000999" }, "descriptor_invalid"},
		"reference names another field": {func(r *runDescriptorRig) {
			r.grant.Connector.CredentialRef = "kei://connectors/" + runDescriptorConnector + "/api_token"
		}, "unresolved_reference"},
		"domain_delegation":       {func(r *runDescriptorRig) { r.grant.Connector.AccountModel = "domain_delegation" }, "account_model_not_supported"},
		"shared oauth":            {func(r *runDescriptorRig) { r.grant.Connector.CredentialSource = "oauth" }, "credential_source_not_supported"},
		"secret never delivered":  {func(r *runDescriptorRig) { _ = os.Remove(r.index) }, "credential_unavailable"},
		"index backend differs":   {func(r *runDescriptorRig) { r.grant.Connector.CredentialBackend = "azure-key-vault" }, "credential_backend_mismatch"},
		"secret store read fails": {func(r *runDescriptorRig) { r.store.values = map[string]string{} }, "credential_unavailable"},
		"policy deny":             {func(r *runDescriptorRig) { r.grant.Allow, r.grant.ReasonCode = false, "policy_deny" }, "policy_deny"},
	} {
		t.Run(name, func(t *testing.T) {
			rig := newRunDescriptorRig(t)
			tc.mutate(rig)
			out := rig.run()
			if out.done.Decision != "deny" || out.done.ReasonCode != tc.want {
				t.Fatalf("done = %+v, want deny %s", out.done, tc.want)
			}
			if _, err := os.Stat(rig.marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("the child ran on a deny")
			}
			rig.assertNoLeak(out)
		})
	}
}

// With descriptors, a per_user oauth reference keeps the session path.
func TestDaemonRunDescriptorPerUserOAuthUsesTheSessionCredential(t *testing.T) {
	rig := newRunDescriptorRig(t)
	rig.grant.Provider = "github"
	rig.grant.Connector = &policybundle.Connector{ID: runDescriptorConnector, Provider: "github", CredentialSource: "oauth", AccountModel: "per_user"}
	var used string
	rig.daemon.UseCredential = func(_ context.Context, _, subject, provider string, fn func(string) error) error {
		used = subject + "/" + provider
		return fn(runDescriptorSentinel)
	}
	body, _ := json.Marshal(daemonRunRequest{Schema: daemonRunSchema, Argv: []string{"/bin/sh", "-c", "true"}, Env: []string{"GH_TOKEN=kei://connectors/" + runDescriptorConnector + "/token"}})
	rig.daemon.Authorize = func(context.Context, invoke.DaemonCall) (invoke.Grant, error) { return rig.grant, nil }
	rec := httptest.NewRecorder()
	rig.daemon.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, DaemonRunPath, bytes.NewReader(body)))
	if !strings.Contains(rec.Body.String(), `"decision":"allow"`) || used != "user-378/github" || rig.store.calls != 0 {
		t.Fatalf("body %s, credential %q, store reads %d", rec.Body.String(), used, rig.store.calls)
	}
}

// The child's environment is exactly the caller's environment with the
// credential references resolved: nothing from the daemon's own process
// environment reaches it. (Ported from the end-to-end root test, which can no
// longer be permitted by a real v2 bundle.)
func TestDaemonRunChildEnvironmentIsCallerEnvPlusRefs(t *testing.T) {
	t.Setenv("KEI_DAEMON_ONLY_CANARY", "daemon-secret")
	rig := newRunDescriptorRig(t)
	out := rig.runWith([]string{"/usr/bin/env"}, []string{"PATH=/usr/bin:/bin", "EXTRA=1", "API_KEY=" + runDescriptorRef})
	if out.done.Decision != "allow" || out.done.ExitCode != 0 {
		t.Fatalf("done = %+v\n%s", out.done, out.raw)
	}
	var keys []string
	for _, line := range strings.Split(strings.TrimSpace(out.stdout), "\n") {
		keys = append(keys, strings.SplitN(line, "=", 2)[0])
	}
	sort.Strings(keys)
	if got := strings.Join(keys, ","); got != "API_KEY,EXTRA,PATH" {
		t.Fatalf("child environment keys = %s, want API_KEY,EXTRA,PATH\n%s", got, out.stdout)
	}
	if strings.Contains(out.stdout, "daemon-secret") {
		t.Fatalf("the daemon's own environment reached the child:\n%s", out.stdout)
	}
	rig.assertNoLeak(out)
}

// A command that cannot be started is a typed deny, never a silent success.
func TestDaemonRunCommandNotStartedIsATypedDeny(t *testing.T) {
	rig := newRunDescriptorRig(t)
	out := rig.runWith([]string{"/kei-no-such-command-hai-622"}, []string{"PATH=/usr/bin:/bin", "API_KEY=" + runDescriptorRef})
	if out.done.Decision != "deny" || out.done.ReasonCode != "command_not_started" || out.done.ExitCode != 127 {
		t.Fatalf("done = %+v, want deny command_not_started with exit 127", out.done)
	}
	rig.assertNoLeak(out)
}
