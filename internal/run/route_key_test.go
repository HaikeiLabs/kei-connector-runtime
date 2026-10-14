package run

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
)

// ADR-036 §4.4: `kei-proxy run -- <harness>` delivers the session's MCP route
// key to the child as KEI_MCP_ROUTE_KEY. The daemon mints it for the run's
// named session, agent and harness kind; it reaches only the child's
// environment and is revoked when the child exits.

const mintedRouteKey = "kmr_minted-route-key-for-the-test-session-0001"

type fakeRouteKeys struct {
	mu      sync.Mutex
	minted  []string // session|agent|harness
	revoked []string
	err     error
}

func (f *fakeRouteKeys) Mint(sessionID, agentID, harnessKind string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.minted = append(f.minted, sessionID+"|"+agentID+"|"+harnessKind)
	if f.err != nil {
		return "", f.err
	}
	return mintedRouteKey, nil
}

func (f *fakeRouteKeys) Revoke(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, key)
}

// runWithRouteKeys posts one run to d in session sessionID and returns the
// outcome. The child reports whether it received the minted or the caller's
// key, prints the key (which must be redacted), and touches marker.
func runWithRouteKeys(t *testing.T, d *Daemon, sessionID, harnessKind string, env []string, marker string) (runOutcome, int) {
	t.Helper()
	script := `touch "$MARKER"; case "$KEI_MCP_ROUTE_KEY" in ` + mintedRouteKey + `) echo key=minted;; kmr_spoofed) echo key=spoofed;; *) echo key=other;; esac; printf 'raw=%s\n' "$KEI_MCP_ROUTE_KEY"; printf 'err-raw=%s\n' "$KEI_MCP_ROUTE_KEY" >&2`
	body, _ := json.Marshal(daemonRunRequest{
		Schema: daemonRunSchema, Argv: []string{"/bin/sh", "-c", script},
		Env:     append([]string{"PATH=/usr/bin:/bin", "MARKER=" + marker}, env...),
		AgentID: "agent-488", HarnessKind: harnessKind,
	})
	req := httptest.NewRequest(http.MethodPost, DaemonRunPath, bytes.NewReader(body))
	session.SetHeader(req, sessionID)
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, req)
	out := runOutcome{raw: rec.Body.String()}
	scanner := bufio.NewScanner(strings.NewReader(out.raw))
	for scanner.Scan() {
		var frame runFrame
		if json.Unmarshal(scanner.Bytes(), &frame) != nil {
			continue
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
	return out, rec.Code
}

func routeKeyDaemon(keys RouteKeys, audit *[]string) *Daemon {
	return &Daemon{
		RouteKeys: keys,
		AppendAudit: func(record []byte) error {
			*audit = append(*audit, string(record))
			return nil
		},
	}
}

func TestDaemonRunInjectsTheSessionRouteKeyIntoTheChildOnly(t *testing.T) {
	keys := &fakeRouteKeys{}
	var audit []string
	marker := filepath.Join(t.TempDir(), "ran")
	// The caller's own KEI_MCP_ROUTE_KEY is never trusted or passed on.
	out, status := runWithRouteKeys(t, routeKeyDaemon(keys, &audit), "ks_run_488", "claude_code", []string{"KEI_MCP_ROUTE_KEY=kmr_spoofed"}, marker)

	if status != http.StatusOK || out.done.Decision != "allow" {
		t.Fatalf("status %d done %+v\n%s", status, out.done, out.raw)
	}
	if len(keys.minted) != 1 || keys.minted[0] != "ks_run_488|agent-488|claude_code" {
		t.Fatalf("minted %v, want one key for ks_run_488|agent-488|claude_code", keys.minted)
	}
	if !strings.Contains(out.stdout, "key=minted\n") {
		t.Fatalf("child did not receive the minted key:\n%s", out.stdout)
	}
	if !strings.Contains(out.stdout, "raw=[REDACTED]") || !strings.Contains(out.stderr, "err-raw=[REDACTED]") {
		t.Fatalf("route key not redacted from the child's output:\nstdout %s\nstderr %s", out.stdout, out.stderr)
	}
	for name, text := range map[string]string{"socket stream": out.raw, "audit": strings.Join(audit, "\n")} {
		if strings.Contains(text, mintedRouteKey) {
			t.Fatalf("%s carries the route key:\n%s", name, text)
		}
	}
	if len(keys.revoked) != 1 || keys.revoked[0] != mintedRouteKey {
		t.Fatalf("revoked %v, want the minted key revoked when the child exits", keys.revoked)
	}
}

func TestDaemonRunRouteKeyDenialStopsTheRun(t *testing.T) {
	keys := &fakeRouteKeys{err: &RouteKeyDenied{Code: "subject_unlinked", Reason: "the session subject is not linked"}}
	var audit []string
	marker := filepath.Join(t.TempDir(), "ran")
	out, _ := runWithRouteKeys(t, routeKeyDaemon(keys, &audit), "ks_run_488", "claude_code", nil, marker)

	if out.done.Decision != "deny" || out.done.ReasonCode != "subject_unlinked" {
		t.Fatalf("done %+v, want deny subject_unlinked", out.done)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the child ran although no route key could be minted")
	}
}

func TestDaemonRunMintsNoRouteKeyForTheDefaultSession(t *testing.T) {
	// A route key belongs to one named session (§4.4); the deprecated default
	// session gets none, and run keeps requiring a credential reference.
	keys := &fakeRouteKeys{}
	var audit []string
	out, _ := runWithRouteKeys(t, routeKeyDaemon(keys, &audit), "", "claude_code", nil, filepath.Join(t.TempDir(), "ran"))

	if len(keys.minted) != 0 {
		t.Fatalf("minted %v for the default session", keys.minted)
	}
	if out.done.ReasonCode != "credential_reference_missing" {
		t.Fatalf("done %+v, want credential_reference_missing", out.done)
	}
}

func TestDaemonRunRejectsAnInvalidHarnessKind(t *testing.T) {
	keys := &fakeRouteKeys{}
	var audit []string
	_, status := runWithRouteKeys(t, routeKeyDaemon(keys, &audit), "ks_run_488", "Claude Code!", nil, filepath.Join(t.TempDir(), "ran"))

	if status != http.StatusBadRequest || len(keys.minted) != 0 {
		t.Fatalf("status %d minted %v, want 400 and no key", status, keys.minted)
	}
}
