package connectorruntime

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/credrelease"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// HAI-346 L3b: POST /v1/connectors:invoke on the serve daemon, and
// `kei-proxy connector invoke` as its thin client. Each test runs the daemon's
// real wiring (newServeLocalPDP, newServeHandlers) on a real Unix socket, with
// a fake identity service (I11) and a fake GitHub API behind the provider
// transport seam. The linked session's GitHub token is credentialCanary and
// its subject token is subjectCanary; neither may leave the daemon.

const (
	invokeExternalID = "ext-linked-0001"
	invokeConnector  = "conn-github-0001"
)

// invokeRig is a running daemon with a linked bundle session available.
type invokeRig struct {
	t      *testing.T
	cfg    Config
	local  *keiruntime.LocalPDP
	mcp    *mcpRoute
	client *http.Client
	socket string

	mu sync.Mutex
	// githubTokens are what successive I11 calls release for github; the
	// last repeats.
	githubTokens []string
	i11Calls     []string // "all" or the re-fetched provider
	// githubStatus is the GitHub API status for each call; the last repeats.
	githubStatus []int
	githubAuth   []string
	githubPaths  []string
}

func newInvokeRig(t *testing.T) *invokeRig { return newInvokeRigConfig(t, nil) }

// newInvokeRigConfig is newInvokeRig with mutate applied to the serve config.
func newInvokeRigConfig(t *testing.T, mutate func(*Config)) *invokeRig {
	t.Helper()
	rig := &invokeRig{t: t, githubTokens: []string{credentialCanary}, githubStatus: []int{http.StatusOK}}
	i11 := httptest.NewServer(http.HandlerFunc(rig.serveI11))
	t.Cleanup(i11.Close)
	rig.cfg = identityServeConfig(t, i11.URL)
	if mutate != nil {
		mutate(&rig.cfg)
	}

	store, err := policybundle.OpenStore(rig.cfg.RuntimeStateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(connectorTestBundle(t), "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	rig.local, rig.mcp, err = newServeLocalPDP(rig.cfg, serveSeams{providerTransport: roundTripFunc(rig.serveGitHub)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rig.local.Close)
	ws := "ws-fixture-0001"
	rig.local.SetIdentity(&keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: &ws, AgentID: "agent-fixture-0001"})
	_, h := newServeHandlers(rig.cfg, rig.local)
	rig.client, rig.socket = serveSocketForTest(t, h)
	return rig
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (rig *invokeRig) serveI11(w http.ResponseWriter, r *http.Request) {
	// HAI-577: one connector's token for one resource.
	if connector, ok := strings.CutPrefix(r.URL.Path, "/api/v1/connectorCredentials/"); ok && strings.HasSuffix(connector, ":resolve") && r.Header.Get("X-Kei-Subject-Token") == subjectCanary {
		connector = strings.TrimSuffix(connector, ":resolve")
		var body struct {
			Resource string `json:"resource"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if connector != mcpConnectorID {
			_ = json.NewEncoder(w).Encode(map[string]any{"connector_id": connector, "failure": map[string]any{"reason": "NOT_CONNECTED"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connector_id": connector, "issuer": "https://auth.mcp.example", "resource": body.Resource, "account_model": "per_user",
			"credential": map[string]any{"access_token": mcpTokenCanary, "token_type": "Bearer"},
		})
		return
	}
	if r.URL.Path != credrelease.ResolvePath || r.Header.Get("X-Kei-Subject-Token") != subjectCanary {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var body struct {
		Providers []string `json:"providers"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	rig.mu.Lock()
	n := len(rig.i11Calls)
	call := "all"
	if len(body.Providers) > 0 {
		call = strings.Join(body.Providers, ",")
	}
	rig.i11Calls = append(rig.i11Calls, call)
	token := rig.githubTokens[min(n, len(rig.githubTokens)-1)]
	rig.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{
		"credentials": []map[string]string{{"provider": "github", "access_token": token, "token_type": "Bearer"}},
		"failures":    []map[string]string{{"provider": "linear", "reason": "NOT_CONNECTED"}},
	})
}

func (rig *invokeRig) serveGitHub(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	if r.URL.Host != "api.github.com" {
		rec.WriteHeader(http.StatusBadGateway)
		return rec.Result(), nil
	}
	auth := r.Header.Get("Authorization")
	rig.mu.Lock()
	n := len(rig.githubAuth)
	rig.githubAuth = append(rig.githubAuth, auth)
	rig.githubPaths = append(rig.githubPaths, r.URL.Path)
	status := rig.githubStatus[min(n, len(rig.githubStatus)-1)]
	rig.mu.Unlock()
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(status)
	if status != http.StatusOK {
		// A hostile provider echoes the credential in its error body.
		_, _ = io.WriteString(rec, `{"message":"Bad credentials: `+auth+`"}`)
		return rec.Result(), nil
	}
	if strings.Contains(r.URL.Path, "/issues/") {
		_, _ = io.WriteString(rec, `{"number":7,"title":"test issue","state":"open","labels":[],"repository":{"name":"kei","owner":{"login":"acme"}}}`)
	} else {
		_, _ = io.WriteString(rec, `{"name":"kei","owner":{"login":"acme"},"description":"d","default_branch":"main","private":true}`)
	}
	return rec.Result(), nil
}

func (rig *invokeRig) counts() (i11 []string, github []string) {
	rig.mu.Lock()
	defer rig.mu.Unlock()
	return append([]string(nil), rig.i11Calls...), append([]string(nil), rig.githubAuth...)
}

func (rig *invokeRig) providerPaths() []string {
	rig.mu.Lock()
	defer rig.mu.Unlock()
	return append([]string(nil), rig.githubPaths...)
}

func (rig *invokeRig) startSession(t *testing.T) {
	t.Helper()
	r := socketDo(t, rig.client, http.MethodPut, "/v1/session", `{"schema":"kei.session/v1","source":"discord","external_id":"`+invokeExternalID+`"}`)
	if r.code != http.StatusNoContent {
		t.Fatalf("PUT /v1/session = %s", r.dump)
	}
}

type invokeResult struct {
	Schema     string          `json:"schema"`
	Decision   string          `json:"decision"`
	ReasonCode string          `json:"reason_code"`
	Hint       string          `json:"hint"`
	Provider   string          `json:"provider"`
	Result     json.RawMessage `json:"result"`
	Connect    json.RawMessage `json:"connect"`
	Enrollment json.RawMessage `json:"enrollment"`
	Audit      *struct {
		InputDigest  string `json:"input_digest"`
		ResultDigest string `json:"result_digest"`
	} `json:"audit"`
}

func (rig *invokeRig) invoke(t *testing.T, connector, capability, resource string) (invokeResult, socketResponse) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"schema": "kei.connector-invoke-request/v1", "connector_id": connector, "capability": capability,
		"action": "read", "resource": resource, "input": map[string]any{}, "trace_id": "trace-l3b-0001",
	})
	resp := socketDo(t, rig.client, http.MethodPost, "/v1/connectors:invoke", string(body))
	if resp.code != http.StatusOK {
		t.Fatalf("POST /v1/connectors:invoke = %s", resp.dump)
	}
	var out invokeResult
	if err := json.Unmarshal([]byte(resp.dump[strings.Index(resp.dump, "{"):]), &out); err != nil {
		t.Fatalf("response %s: %v", resp.dump, err)
	}
	if out.Schema != "kei.connector-invoke-response/v1" {
		t.Fatalf("response schema %q", out.Schema)
	}
	return out, resp
}

// connectorTestBundle is the example bundle in bundle mode with one linked
// discord identity (in group members, subject token subjectCanary) and four
// connectors: github (read permitted, pull_request.read not), linear
// (permitted, but the subject never connected it) and notion (permitted, but
// it needs an opaque_ref credential the daemon does not hold).
func connectorTestBundle(t *testing.T) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(unsignedExampleBundle(t, time.Now().UTC()), &doc); err != nil {
		t.Fatal(err)
	}
	doc["subject_resolution"] = map[string]any{"mode": "bundle", "max_cache_seconds": 0}
	doc["identities"] = []any{map[string]any{
		"source": "discord", "external_id": invokeExternalID, "user_id": "u-canary", "status": "linked",
		"groups": []string{"members"}, "subject_token": subjectCanary,
	}}
	ps := doc["policy_set"].(map[string]any)
	template := ps["policies"].([]any)[3].(map[string]any) // pol-read-all
	policy := func(id, dst string) map[string]any {
		p := map[string]any{}
		for k, v := range template {
			p[k] = v
		}
		p["id"], p["name"], p["dst_pattern"] = id, id, dst
		return p
	}
	tool := func(name, service, action, connector, capability string) map[string]any {
		return map[string]any{"name": name, "service": service, "action": action, "connector_id": connector, "capability": capability}
	}
	ps["groups"] = []any{map[string]any{"id": "grp-members-0001", "name": "members", "description": "members", "child_group_ids": []string{}}}
	ps["tools"] = []any{
		tool("github.repository_read", "github", "github:read", invokeConnector, "repository.read"),
		tool("github.pull_request_read", "github", "github:admin", invokeConnector, "pull_request.read"),
		tool("linear.team_read", "linear", "linear:read", "conn-linear-0001", "team.read"),
		tool("notion.page_read", "notion", "notion:read", "conn-notion-0001", "page.read"),
		// L3c: kei-proxy run credential references.
		tool("github.credential", "github", "github:credential", invokeConnector, "credential"),
		tool("linear.credential", "linear", "linear:credential", "conn-linear-0001", "credential"),
		tool("notion.credential", "notion", "notion:credential", "conn-notion-0001", "credential"),
	}
	ps["policies"] = []any{
		policy("pol-github-read", "capability:repository.read"), policy("pol-linear-read", "capability:team.read"), policy("pol-notion-read", "capability:page.read"),
		policy("pol-github-token", "resource:kei://connectors/"+invokeConnector+"/token"),
		policy("pol-linear-token", "resource:kei://connectors/conn-linear-0001/token"),
		policy("pol-notion-token", "resource:kei://connectors/conn-notion-0001/token"),
	}
	capability := func(names ...string) []any {
		var out []any
		for _, n := range names {
			out = append(out, map[string]any{"name": n, "mutating": false})
		}
		return out
	}
	ps["connectors"] = []any{
		map[string]any{"id": invokeConnector, "provider": "github", "capabilities": capability("repository.read", "pull_request.read", "credential")},
		map[string]any{"id": "conn-linear-0001", "provider": "linear", "capabilities": capability("team.read", "credential")},
		map[string]any{"id": "conn-notion-0001", "provider": "notion", "capabilities": capability("page.read", "credential")},
	}
	doc["agent_connector_bindings"] = []any{
		map[string]any{"agent_id": "agent-fixture-0001", "connector_id": invokeConnector, "capabilities": []string{"repository.read", "pull_request.read", "credential"}},
		map[string]any{"agent_id": "agent-fixture-0001", "connector_id": "conn-linear-0001", "capabilities": []string{"team.read", "credential"}},
		map[string]any{"agent_id": "agent-fixture-0001", "connector_id": "conn-notion-0001", "capabilities": []string{"page.read", "credential"}},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDaemonConnectorInvokeRunsWithSessionCredential(t *testing.T) {
	rig := newInvokeRig(t)
	rig.startSession(t)
	for range 5 {
		out, resp := rig.invoke(t, invokeConnector, "repository.read", "repos/acme/kei")
		if out.Decision != "allow" || out.Provider != "github" || !strings.Contains(string(out.Result), `"default_branch":"main"`) {
			t.Fatalf("invoke = %s", resp.dump)
		}
		if out.Audit == nil || out.Audit.InputDigest == "" || out.Audit.ResultDigest == "" {
			t.Fatalf("audit digests missing: %s", resp.dump)
		}
	}
	i11, github := rig.counts()
	if len(i11) != 1 || i11[0] != "all" {
		t.Fatalf("I11 calls = %v, want one at session start", i11)
	}
	if len(github) != 5 {
		t.Fatalf("GitHub calls = %d, want 5", len(github))
	}
	for _, auth := range github {
		if !strings.Contains(auth, credentialCanary) {
			t.Fatalf("provider did not get the session credential: %q", auth)
		}
	}
	spool := readSpool(t, rig.cfg.AuditPath)
	if !strings.Contains(spool, `"invoking_subject":"u-canary"`) || !strings.Contains(spool, `"decision":"allow"`) {
		t.Fatalf("audit spool lacks the execution record: %s", spool)
	}
}

func TestDaemonConnectorInvokeDenyPaths(t *testing.T) {
	rig := newInvokeRig(t)

	// No session: fail closed before the PDP, I11 or the provider.
	out, _ := rig.invoke(t, invokeConnector, "repository.read", "repos/acme/kei")
	if out.Decision != "deny" || out.ReasonCode != "no_session" {
		t.Fatalf("no session: %+v", out)
	}

	rig.startSession(t)
	for _, tc := range []struct {
		name, connector, capability, resource, code string
		connect                                     bool
	}{
		{"policy deny", invokeConnector, "pull_request.read", "repos/acme/kei/pulls/1", "policy_deny", false},
		{"unregistered capability", invokeConnector, "workflow.read", "repos/acme/kei", "tool_not_registered", false},
		{"provider not connected", "conn-linear-0001", "team.read", "teams/eng", "connector_not_connected", true},
		{"opaque_ref provider", "conn-notion-0001", "page.read", "pages/p1", "credential_source_not_supported", false},
		{"bad resource", invokeConnector, "repository.read", "repos/acme/../kei", "input_invalid", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, resp := rig.invoke(t, tc.connector, tc.capability, tc.resource)
			if out.Decision != "deny" || len(out.Result) != 0 {
				t.Fatalf("got %s", resp.dump)
			}
			if tc.code == "policy_deny" {
				if out.ReasonCode == "" || strings.HasPrefix(out.ReasonCode, "connector_") {
					t.Fatalf("reason = %q, want a PDP denial", out.ReasonCode)
				}
			} else if out.ReasonCode != tc.code {
				t.Fatalf("reason = %q, want %q (%s)", out.ReasonCode, tc.code, resp.dump)
			}
			if (len(out.Connect) > 0) != tc.connect {
				t.Fatalf("connect hint = %s, want %v", out.Connect, tc.connect)
			}
		})
	}
	i11, github := rig.counts()
	if len(i11) != 1 {
		t.Fatalf("I11 calls = %v, want only the session start", i11)
	}
	// Every deny happens before a provider request.
	if len(github) != 0 {
		t.Fatalf("GitHub calls = %d, want 0 on deny paths", len(github))
	}

	// After DELETE the held credential is gone: no_session, no fetch.
	socketDo(t, rig.client, http.MethodDelete, "/v1/session", "")
	if out, _ := rig.invoke(t, invokeConnector, "repository.read", "repos/acme/kei"); out.ReasonCode != "no_session" {
		t.Fatalf("after DELETE: %+v", out)
	}
	if i11, github := rig.counts(); len(i11) != 1 || len(github) != 0 {
		t.Fatalf("after DELETE: I11 %v, GitHub %d", i11, len(github))
	}
}

// TestDaemonConnectorInvokeDenyCarriesHint asserts a connector invoke deny
// carries a hint for a reason_code in the denyhint table and omits it (omitempty)
// for a code outside the table.
func TestDaemonConnectorInvokeDenyCarriesHint(t *testing.T) {
	rig := newInvokeRig(t)
	rig.startSession(t)

	// tool_not_registered is in the table: the deny must carry a non-empty hint.
	out, resp := rig.invoke(t, invokeConnector, "workflow.read", "repos/acme/kei")
	if out.Decision != "deny" || out.ReasonCode != "tool_not_registered" {
		t.Fatalf("want tool_not_registered deny, got %+v (%s)", out, resp.dump)
	}
	if out.Hint == "" {
		t.Fatalf("tool_not_registered deny missing hint: %s", resp.dump)
	}

	// no_session is outside the table: the deny must omit the hint.
	socketDo(t, rig.client, http.MethodDelete, "/v1/session", "")
	out2, resp2 := rig.invoke(t, invokeConnector, "repository.read", "repos/acme/kei")
	if out2.ReasonCode != "no_session" {
		t.Fatalf("want no_session, got %+v (%s)", out2, resp2.dump)
	}
	if out2.Hint != "" {
		t.Fatalf("no_session deny must omit hint: %s", resp2.dump)
	}
}

func TestDaemonConnectorInvokeProvider401RefetchRetry(t *testing.T) {
	t.Run("retry succeeds", func(t *testing.T) {
		rig := newInvokeRig(t)
		rig.githubTokens = []string{"stale-session-token", credentialCanary}
		rig.githubStatus = []int{http.StatusUnauthorized, http.StatusOK}
		rig.startSession(t)
		out, resp := rig.invoke(t, invokeConnector, "repository.read", "repos/acme/kei")
		if out.Decision != "allow" {
			t.Fatalf("got %s", resp.dump)
		}
		i11, github := rig.counts()
		if strings.Join(i11, "|") != "all|github" || len(github) != 2 || !strings.Contains(github[1], credentialCanary) {
			t.Fatalf("I11 %v, GitHub auth %d", i11, len(github))
		}
	})
	t.Run("second 401 denies with connect", func(t *testing.T) {
		rig := newInvokeRig(t)
		rig.githubStatus = []int{http.StatusUnauthorized}
		rig.startSession(t)
		out, resp := rig.invoke(t, invokeConnector, "repository.read", "repos/acme/kei")
		if out.Decision != "deny" || out.ReasonCode != "connector_reconnect_required" || len(out.Connect) == 0 {
			t.Fatalf("got %s", resp.dump)
		}
		i11, github := rig.counts()
		if strings.Join(i11, "|") != "all|github" || len(github) != 2 {
			t.Fatalf("I11 %v, GitHub calls %d; want one re-fetch and one retry", i11, len(github))
		}
		// The rejected credential is dropped; the next call is not
		// re-fetched again.
		rig.invoke(t, invokeConnector, "repository.read", "repos/acme/kei")
		if i11, github := rig.counts(); len(i11) != 2 || len(github) != 2 {
			t.Fatalf("after deny: I11 %v, GitHub %d", i11, len(github))
		}
	})
}

func TestDaemonConnectorInvokeRequiresRuntimeTokenAndIdentityMode(t *testing.T) {
	rig := newInvokeRig(t)
	req, _ := http.NewRequest(http.MethodPost, "http://unix/v1/connectors:invoke", strings.NewReader(`{}`))
	resp, err := rig.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated invoke = %d, want 401", resp.StatusCode)
	}

	// legacy: the route is not served.
	cfg := rig.cfg
	cfg.CredentialRelease = CredentialReleaseLegacy
	local, _, err := newServeLocalPDP(cfg, serveSeams{})
	if err != nil {
		t.Fatal(err)
	}
	_, h := newServeHandlers(cfg, local)
	c, _ := serveSocketForTest(t, h)
	if r := socketDo(t, c, http.MethodPost, "/v1/connectors:invoke", `{}`); r.code != http.StatusNotFound {
		t.Fatalf("legacy invoke = %d, want 404", r.code)
	}
}

// runConnectorCLI runs `kei-proxy connector invoke` through the root
// command's wiring with KEI_CREDENTIAL_RELEASE=identity.
func runConnectorCLI(t *testing.T, socketPath string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Setenv("KEI_RUNTIME_TOKEN", credTestToken)
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", "https://kei.example")
	t.Setenv("KEI_CREDENTIAL_RELEASE", "identity")
	t.Setenv("KEI_RUNTIME_SOCKET_PATH", socketPath)
	t.Setenv("KEI_PROXY_AUDIT_PATH", "")
	stdout, stderr = captureFDs(t, func() {
		code = runConnector(append([]string{"invoke"}, args...))
	})
	return code, stdout, stderr
}

var cliRepositoryRead = []string{"--connector", invokeConnector, "--capability", "repository.read", "--action", "read", "--resource", "repos/acme/kei"}

func TestConnectorInvokeCLIThinClient(t *testing.T) {
	rig := newInvokeRig(t)

	t.Run("no session", func(t *testing.T) {
		code, stdout, stderr := runConnectorCLI(t, rig.socket, cliRepositoryRead...)
		if code != 1 || !strings.Contains(stdout, `"reason_code":"no_session"`) || !strings.Contains(stderr, "no active kei-proxy session") {
			t.Fatalf("exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
	})

	rig.startSession(t)
	t.Run("allow", func(t *testing.T) {
		code, stdout, stderr := runConnectorCLI(t, rig.socket, cliRepositoryRead...)
		if code != 0 || !strings.Contains(stdout, `"decision":"allow"`) || !strings.Contains(stdout, `"default_branch":"main"`) {
			t.Fatalf("exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
		if strings.Contains(stdout, `"schema"`) {
			t.Fatalf("CLI output changed shape: %s", stdout)
		}
	})
	t.Run("deny", func(t *testing.T) {
		code, stdout, _ := runConnectorCLI(t, rig.socket, "--connector", "conn-linear-0001", "--capability", "team.read", "--action", "read", "--resource", "teams/eng")
		if code != 1 || !strings.Contains(stdout, `"reason_code":"connector_not_connected"`) {
			t.Fatalf("exit %d stdout %s", code, stdout)
		}
	})
	t.Run("subject flags rejected", func(t *testing.T) {
		code, stdout, stderr := runConnectorCLI(t, rig.socket, append([]string{"--user-id", "u-someone-else"}, cliRepositoryRead...)...)
		if code != 1 || !strings.Contains(stdout, `"decision":"deny"`) || !strings.Contains(stderr, "not accepted") {
			t.Fatalf("exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
	})
	t.Run("no daemon", func(t *testing.T) {
		missing := filepath.Join(shortSocketTempDir(t), "absent.sock")
		code, stdout, stderr := runConnectorCLI(t, missing, cliRepositoryRead...)
		if code != 1 || !strings.Contains(stdout, `"reason_code":"daemon_unavailable"`) || !strings.Contains(stderr, "not reachable") {
			t.Fatalf("exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
	})
	t.Run("bad mode fails closed", func(t *testing.T) {
		t.Setenv("KEI_RUNTIME_TOKEN", credTestToken)
		t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", "https://kei.example")
		t.Setenv("KEI_CREDENTIAL_RELEASE", "option-c")
		var code int
		_, stderr := captureFDs(t, func() { code = runConnector(append([]string{"invoke"}, cliRepositoryRead...)) })
		if code != 1 || !strings.Contains(stderr, "KEI_CREDENTIAL_RELEASE") {
			t.Fatalf("exit %d stderr %s", code, stderr)
		}
	})
	if _, github := rig.counts(); len(github) != 1 {
		t.Fatalf("GitHub calls = %d, want 1 (the allow)", len(github))
	}
}

// TestConnectorInvokeNeverLeaksCredential drives allow, deny, the 401
// re-fetch path (with a provider that echoes the credential in its error
// body) and the CLI through the daemon, and checks neither canary reaches
// stdout, stderr, the log, the audit spool, or any socket response.
func TestConnectorInvokeNeverLeaksCredential(t *testing.T) {
	var logs bytes.Buffer
	prevLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prevLog) })

	rig := newInvokeRig(t)
	rig.githubTokens = []string{credentialCanary, credentialCanary + "-refetched"}
	rig.githubStatus = []int{http.StatusOK, http.StatusUnauthorized}
	var responses []socketResponse
	stdout, stderr := captureFDs(t, func() {
		rig.startSession(t)
		for _, call := range [][3]string{
			{invokeConnector, "repository.read", "repos/acme/kei"},           // allow
			{invokeConnector, "repository.read", "repos/acme/kei"},           // 401, re-fetch, 401: deny
			{invokeConnector, "pull_request.read", "repos/acme/kei/pulls/1"}, // policy deny
			{"conn-linear-0001", "team.read", "teams/eng"},                   // not connected
		} {
			_, resp := rig.invoke(t, call[0], call[1], call[2])
			responses = append(responses, resp)
		}
		responses = append(responses, socketDo(t, rig.client, http.MethodGet, "/v1/session", ""))
	})
	_, cliOut, cliErr := runConnectorCLI(t, rig.socket, cliRepositoryRead...)

	if _, github := rig.counts(); len(github) < 3 {
		t.Fatalf("GitHub calls = %d; the 401 path did not run", len(github))
	}
	sinks := map[string]string{
		"stdout": stdout + cliOut, "stderr": stderr + cliErr, "log": logs.String(),
		"audit spool": readSpool(t, rig.cfg.AuditPath),
	}
	for _, r := range responses {
		sinks["socket "+r.route] += r.dump
	}
	for name, content := range sinks {
		for _, canary := range []string{credentialCanary, subjectCanary} {
			if strings.Contains(content, canary) {
				t.Errorf("%s leaked %s:\n%s", name, canary, content)
			}
		}
	}
}

func TestProductionServeInterpretsCachedPlanWithoutPlannerRegistration(t *testing.T) {
	rig := newInvokeRig(t)
	now := time.Now().UTC()
	check := map[string]any{"policy_id": "permit-repository", "name": "repo read", "effect": "permit", "priority": 10, "scope": map[string]any{"org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "agent_id": "agent-fixture-0001"}, "selector": map[string]any{"source_principal": "user:u-canary", "source": "github", "connector_id": invokeConnector, "tool": "github.repository_read", "capability": "repository.read"}}
	plan := map[string]any{"args_schema": map[string]any{"type": "object", "properties": map[string]any{"note": map[string]any{"type": "string", "maxLength": 64}}, "required": []any{"note"}, "additionalProperties": false}, "context_schema": map[string]any{"type": "object", "properties": map[string]any{"repository": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"}}, "required": []any{"repository"}, "additionalProperties": false}, "operations": []any{map[string]any{"id": "get-repository", "capability": "repository.read", "resource": map[string]any{"type": "repository", "id": map[string]any{"from": "context", "field": "repository", "type": "string"}}, "provider_resource_template": "repos/{resource.id}", "provider_input": map[string]any{}}}}
	bundle, err := json.Marshal(map[string]any{"schema": "kei.policy-bundle/v2", "bundle_id": "bundle-serve-v2", "bundle_version": 43, "policy_revision": 7, "issuer": "kei-policy-catalog", "audience": map[string]any{"installation_id": "inst-fixture-0001", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001"}, "issued_at": now.Format(time.RFC3339Nano), "not_after": now.Add(time.Hour).Format(time.RFC3339Nano), "refresh": map[string]any{"poll_interval_seconds": 60, "stale_after_seconds": 300}, "subject_resolution": map[string]any{"mode": "bundle", "max_cache_seconds": 60}, "policy_set": map[string]any{"schema": "kei.policy-set/v2", "org_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "match_semantics": "kei.match/v2", "evaluation": map[string]any{"precedence": []string{"priority_desc", "deny_before_permit", "policy_id_asc"}, "checks": "per_capability_first_match_and", "default": "deny"}, "tools": []any{map[string]any{"name": "github.repository_read", "source": "github", "operation_class": "read", "route": map[string]any{"connector_binding": map[string]any{"connector_id": invokeConnector}}, "required_capabilities": []string{"repository.read"}, "resource_types": []any{map[string]any{"type": "repository"}}, "plan": plan}}, "checks": []any{check}, "tool_policies": []any{}, "harness_match_semantics": "kei.harness-match/v1", "harness_policies": []any{}}, "agent_connector_bindings": []any{map[string]any{"agent_id": "agent-fixture-0001", "connector_id": invokeConnector, "capabilities": []string{"repository.read"}}}, "identities": []any{map[string]any{"source": "discord", "external_id": invokeExternalID, "user_id": "u-canary", "status": "linked", "groups": []string{"members"}, "subject_token": subjectCanary}}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := policybundle.OpenStore(rig.cfg.RuntimeStateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(bundle, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", now); err != nil {
		t.Fatal(err)
	}
	// newInvokeRig uses production newServeLocalPDP/newServeHandlers wiring;
	// no per-tool planner is registered anywhere in serve.
	sessionID := rig.startNamedSession(t)
	args := `{"note":"model-visible"}`
	contextMap := `{"repository":"acme/kei"}`
	preflight := socketDoSession(t, rig.client, http.MethodPost, "/v1/preflight", sessionID, `{"schema":"kei.preflight-request/v1","session_id":"`+sessionID+`","tool":"github.repository_read","agent_id":"agent-fixture-0001","arguments":`+args+`,"context":`+contextMap+`}`)
	if preflight.code != http.StatusOK {
		t.Fatalf("catalog-plan preflight status=%d body=%s", preflight.code, preflight.dump)
	}
	var grant struct {
		Handle string `json:"handle"`
	}
	bodyStart := strings.Index(preflight.dump, "{")
	if bodyStart < 0 {
		t.Fatalf("preflight response=%s", preflight.dump)
	}
	if err := json.Unmarshal([]byte(preflight.dump[bodyStart:]), &grant); err != nil || grant.Handle == "" {
		t.Fatalf("preflight response=%s err=%v", preflight.dump, err)
	}
	invokeBody, _ := json.Marshal(map[string]any{"schema": "kei.connector-invoke-request/v1", "tool_name": "github.repository_read", "preflight_handle": grant.Handle, "session_id": sessionID, "agent_id": "agent-fixture-0001", "input": json.RawMessage(args), "context": json.RawMessage(contextMap), "trace_id": "trace-generic-plan"})
	response := socketDoSession(t, rig.client, http.MethodPost, "/v1/connectors:invoke", sessionID, string(invokeBody))
	if response.code != http.StatusOK || !strings.Contains(response.dump, `"decision":"allow"`) {
		t.Fatalf("generic bundle plan invoke=%d %s", response.code, response.dump)
	}
	_, providerCalls := rig.counts()
	if len(providerCalls) != 1 {
		t.Fatalf("provider calls=%d want 1", len(providerCalls))
	}
}
