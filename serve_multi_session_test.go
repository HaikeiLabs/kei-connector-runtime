package connectorruntime

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// startNamedSession creates a kei.session/v2 session over the socket and
// returns its id.
func (rig *socketRig) startNamedSession(t *testing.T) string {
	t.Helper()
	r := socketDo(t, rig.client, http.MethodPut, "/v1/session", `{"schema":"kei.session/v2","source":"discord","external_id":"`+linkedExternalID+`"}`)
	if r.code != http.StatusCreated {
		t.Fatalf("PUT /v1/session v2 = %s", r.dump)
	}
	var out struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal([]byte(r.dump[strings.Index(r.dump, "{"):]), &out); err != nil || !strings.HasPrefix(out.SessionID, "ks_") {
		t.Fatalf("PUT v2 response %s: %v", r.dump, err)
	}
	return out.SessionID
}

// TestDaemonNamedSessionCLIPassthrough drives the daemon's credentialed
// route in a named session through the real CLI: run with $KEI_SESSION_ID.
// Its audit record carries the session id; an unknown or ended id fails
// closed before the child runs.
func TestDaemonNamedSessionCLIPassthrough(t *testing.T) {
	rig := newSocketRig(t)
	id := rig.startNamedSession(t)
	t.Setenv("KEI_SESSION_ID", "")

	// No default session exists: a call without the id has no session.
	if code, _, errOut := runProxyRunCLI(t, rig.socket,
		map[string]string{"GH_TOKEN": githubTokenRef, "KEI_RUN_HELPER_EXIT": "0"},
		"--", helperBinary(t)); code != 1 || !strings.Contains(errOut, "no active kei-proxy session") {
		t.Fatalf("run without a session id: exit %d stderr %s", code, errOut)
	}

	code, out, errOut := runProxyRunCLI(t, rig.socket,
		map[string]string{"GH_TOKEN": githubTokenRef, "KEI_RUN_HELPER_EXIT": "0", "KEI_SESSION_ID": id},
		"--", helperBinary(t))
	if code != 0 || !strings.Contains(out, "token-sha256="+credentialCanaryDigest) {
		t.Fatalf("run in the named session: exit %d\nstdout %s\nstderr %s", code, out, errOut)
	}

	if code, _, errOut := runProxyRunCLI(t, rig.socket,
		map[string]string{"GH_TOKEN": githubTokenRef, "KEI_RUN_HELPER_EXIT": "0", "KEI_SESSION_ID": "ks_forged"},
		"--", helperBinary(t)); code != 1 || !strings.Contains(errOut, "session_not_found") {
		t.Fatalf("run with an unknown session: exit %d stderr %s", code, errOut)
	}

	spool := readSpool(t, rig.cfg.AuditPath)
	found := false
	for _, line := range strings.Split(spool, "\n") {
		if strings.Contains(line, `"schema":"kei.proxy-run-event/v1"`) && strings.Contains(line, `"session_id":"`+id+`"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("no run audit record with the session id:\n%s", spool)
	}

	// After DELETE the id is dead on every credentialed route.
	if r := socketDoSession(t, rig.client, http.MethodDelete, "/v1/session", id, ""); r.code != http.StatusNoContent {
		t.Fatalf("DELETE = %s", r.dump)
	}
	if code, _, errOut := runProxyRunCLI(t, rig.socket,
		map[string]string{"GH_TOKEN": githubTokenRef, "KEI_RUN_HELPER_EXIT": "0", "KEI_SESSION_ID": id}, "--", helperBinary(t)); code != 1 || !strings.Contains(errOut, "session_not_found") {
		t.Fatalf("run in an ended session: exit %d stderr %s", code, errOut)
	}
	if i11, _ := rig.counts(); len(i11) != 1 {
		t.Fatalf("I11 calls = %v, want only the session start", i11)
	}
}

// socketDoSession is socketDo naming a session.
func socketDoSession(t *testing.T, c *http.Client, method, path, id, body string) socketResponse {
	t.Helper()
	req, err := http.NewRequest(method, "http://unix"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+credTestToken)
	req.Header.Set("X-Kei-Session", id)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return socketResponse{route: method + " " + path, code: resp.StatusCode, dump: resp.Status + "\n" + string(b)}
}
