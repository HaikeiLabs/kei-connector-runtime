package connectorruntime

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/credrelease"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// socketRig is a running daemon with a linked bundle session available. It
// serves the credentialed socket routes (commands:run, sessions) with the
// daemon's real wiring (newServeLocalPDP, newServeHandlers) on a real Unix
// socket, a fake identity service (I11) and a fake GitHub API behind the
// provider transport seam. The linked session's GitHub token is
// credentialCanary and its subject token is subjectCanary; neither may leave
// the daemon.

const (
	linkedExternalID  = "ext-linked-0001"
	githubConnectorID = "conn-github-0001"
	mcpConnectorID    = "conn-mcp-1"
	mcpTokenCanary    = "kei-canary-mcp-connector-token-577"
)

// socketRig is a running daemon with a linked bundle session available.
type socketRig struct {
	t      *testing.T
	cfg    Config
	local  *keiruntime.LocalPDP
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

func newSocketRig(t *testing.T) *socketRig { return newSocketRigConfig(t, nil) }

// newSocketRigConfig is newSocketRig with mutate applied to the serve config.
func newSocketRigConfig(t *testing.T, mutate func(*Config)) *socketRig {
	return newSocketRigWithBundle(t, connectorTestBundle(t), mutate)
}

// newSocketRigWithBundle is newSocketRigConfig activating an explicit bundle,
// so two rigs can run the byte-identical bundle.
func newSocketRigWithBundle(t *testing.T, bundle []byte, mutate func(*Config)) *socketRig {
	t.Helper()
	rig := &socketRig{t: t, githubTokens: []string{credentialCanary}, githubStatus: []int{http.StatusOK}}
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
	if _, err := store.Activate(bundle, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	rig.local, err = newServeLocalPDP(rig.cfg, serveSeams{providerTransport: roundTripFunc(rig.serveGitHub)})
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

func (rig *socketRig) serveI11(w http.ResponseWriter, r *http.Request) {
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

func (rig *socketRig) serveGitHub(r *http.Request) (*http.Response, error) {
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

func (rig *socketRig) counts() (i11 []string, github []string) {
	rig.mu.Lock()
	defer rig.mu.Unlock()
	return append([]string(nil), rig.i11Calls...), append([]string(nil), rig.githubAuth...)
}

func (rig *socketRig) providerPaths() []string {
	rig.mu.Lock()
	defer rig.mu.Unlock()
	return append([]string(nil), rig.githubPaths...)
}

func (rig *socketRig) startSession(t *testing.T) {
	t.Helper()
	r := socketDo(t, rig.client, http.MethodPut, "/v1/session", `{"schema":"kei.session/v1","source":"discord","external_id":"`+linkedExternalID+`"}`)
	if r.code != http.StatusNoContent {
		t.Fatalf("PUT /v1/session = %s", r.dump)
	}
}

func connectorTestBundle(t *testing.T) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(unsignedExampleBundle(t, time.Now().UTC()), &doc); err != nil {
		t.Fatal(err)
	}
	doc["subject_resolution"] = map[string]any{"mode": "bundle", "max_cache_seconds": 0}
	doc["identities"] = []any{map[string]any{
		"source": "discord", "external_id": linkedExternalID, "user_id": "u-canary", "status": "linked",
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
		tool("github.repository_read", "github", "github:read", githubConnectorID, "repository.read"),
		tool("github.pull_request_read", "github", "github:admin", githubConnectorID, "pull_request.read"),
		tool("linear.team_read", "linear", "linear:read", "conn-linear-0001", "team.read"),
		tool("notion.page_read", "notion", "notion:read", "conn-notion-0001", "page.read"),
		// L3c: kei-proxy run credential references.
		tool("github.credential", "github", "github:credential", githubConnectorID, "credential"),
		tool("linear.credential", "linear", "linear:credential", "conn-linear-0001", "credential"),
		tool("notion.credential", "notion", "notion:credential", "conn-notion-0001", "credential"),
	}
	ps["policies"] = []any{
		policy("pol-github-read", "capability:repository.read"), policy("pol-linear-read", "capability:team.read"), policy("pol-notion-read", "capability:page.read"),
		policy("pol-github-token", "resource:kei://connectors/"+githubConnectorID+"/token"),
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
		map[string]any{"id": githubConnectorID, "provider": "github", "capabilities": capability("repository.read", "pull_request.read", "credential")},
		map[string]any{"id": "conn-linear-0001", "provider": "linear", "capabilities": capability("team.read", "credential")},
		map[string]any{"id": "conn-notion-0001", "provider": "notion", "capabilities": capability("page.read", "credential")},
	}
	doc["agent_connector_bindings"] = []any{
		map[string]any{"agent_id": "agent-fixture-0001", "connector_id": githubConnectorID, "capabilities": []string{"repository.read", "pull_request.read", "credential"}},
		map[string]any{"agent_id": "agent-fixture-0001", "connector_id": "conn-linear-0001", "capabilities": []string{"team.read", "credential"}},
		map[string]any{"agent_id": "agent-fixture-0001", "connector_id": "conn-notion-0001", "capabilities": []string{"page.read", "credential"}},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
