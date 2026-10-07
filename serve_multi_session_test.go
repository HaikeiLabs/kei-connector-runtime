package connectorruntime

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// startNamedSession creates a kei.session/v2 session over the socket and
// returns its id.
func (rig *invokeRig) startNamedSession(t *testing.T) string {
	t.Helper()
	r := socketDo(t, rig.client, http.MethodPut, "/v1/session", `{"schema":"kei.session/v2","source":"discord","external_id":"`+invokeExternalID+`"}`)
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
// routes in a named session through the real CLIs: connector invoke --session
// and run with $KEI_SESSION_ID. Their audit records carry the session id; an
// unknown or ended id fails closed before any provider call.
func TestDaemonNamedSessionCLIPassthrough(t *testing.T) {
	rig := newInvokeRig(t)
	id := rig.startNamedSession(t)
	t.Setenv("KEI_SESSION_ID", "")

	// No default session exists: a call without the id has no session.
	if code, stdout, _ := runConnectorCLI(t, rig.socket, cliRepositoryRead...); code != 1 || !strings.Contains(stdout, `"reason_code":"no_session"`) {
		t.Fatalf("invoke without a session id: exit %d %s", code, stdout)
	}
	code, stdout, stderr := runConnectorCLI(t, rig.socket, append([]string{"--session", id}, cliRepositoryRead...)...)
	if code != 0 || !strings.Contains(stdout, `"decision":"allow"`) {
		t.Fatalf("invoke --session: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	if code, stdout, _ := runConnectorCLI(t, rig.socket, append([]string{"--session", "ks_forged"}, cliRepositoryRead...)...); code != 1 || !strings.Contains(stdout, `"reason_code":"session_not_found"`) {
		t.Fatalf("invoke with an unknown session: exit %d %s", code, stdout)
	}

	code, out, errOut := runProxyRunCLI(t, rig.socket,
		map[string]string{"GH_TOKEN": githubTokenRef, "KEI_RUN_HELPER_EXIT": "0", "KEI_SESSION_ID": id},
		"--", helperBinary(t))
	if code != 0 || !strings.Contains(out, "token-sha256="+credentialCanaryDigest) {
		t.Fatalf("run in the named session: exit %d\nstdout %s\nstderr %s", code, out, errOut)
	}

	spool := readSpool(t, rig.cfg.AuditPath)
	for _, schema := range []string{`"tool_name":"connector:github:repository.read"`, `"schema":"kei.proxy-run-event/v1"`} {
		found := false
		for _, line := range strings.Split(spool, "\n") {
			if strings.Contains(line, schema) && strings.Contains(line, `"session_id":"`+id+`"`) {
				found = true
			}
		}
		if !found {
			t.Errorf("no audit record %s with the session id:\n%s", schema, spool)
		}
	}

	// After DELETE the id is dead on every credentialed route.
	if r := socketDoSession(t, rig.client, http.MethodDelete, "/v1/session", id, ""); r.code != http.StatusNoContent {
		t.Fatalf("DELETE = %s", r.dump)
	}
	if code, stdout, _ := runConnectorCLI(t, rig.socket, append([]string{"--session", id}, cliRepositoryRead...)...); code != 1 || !strings.Contains(stdout, `"reason_code":"session_not_found"`) {
		t.Fatalf("invoke in an ended session: exit %d %s", code, stdout)
	}
	if code, _, errOut := runProxyRunCLI(t, rig.socket,
		map[string]string{"GH_TOKEN": githubTokenRef, "KEI_SESSION_ID": id}, "--", helperBinary(t)); code == 0 || !strings.Contains(errOut, "session_not_found") {
		t.Fatalf("run in an ended session: exit %d stderr %s", code, errOut)
	}
	if _, github := rig.counts(); len(github) != 1 {
		t.Fatalf("GitHub calls = %d, want only the one allowed invoke", len(github))
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
	return socketResponse{route: method + " " + path, code: resp.StatusCode, dump: resp.Status}
}
