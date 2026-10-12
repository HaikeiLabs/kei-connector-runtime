package invoke

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

// HAI-431 through the serve daemon (POST /v1/connectors:invoke): the daemon
// decides with its PDP, runs skills_repo with the session subject's own
// GitHub OAuth token, and returns only the result. The fake GitHub API is a
// real TLS httptest server.

const daemonSkillsTok = "fake-session-github-oauth-token-0042"

type skillsDaemonRig struct {
	t      *testing.T
	daemon *Daemon
	grant  Grant
	github *fakeSkillsGitHub
	audit  []string
	logs   bytes.Buffer
}

func newSkillsDaemonRig(t *testing.T) *skillsDaemonRig {
	t.Helper()
	rig := &skillsDaemonRig{t: t}
	prevLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&rig.logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prevLog) })

	rig.github = newFakeSkillsGitHub(t, daemonSkillsTok, demoSkills())
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "api.github.com" {
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		rig.github.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsConfig.ServerName = "example.com"
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	t.Cleanup(transport.CloseIdleConnections)

	descriptor := &policybundle.Connector{
		ID: execConnector, Name: "skills", Provider: "skills_repo",
		Capabilities:     []policybundle.ConnectorCapability{{Name: "skills.list"}, {Name: "skills.fetch"}},
		CredentialSource: "oauth", AccountModel: "per_user",
		Config: map[string]any{"repo_url": "https://github.com/acme/skills"},
	}
	rig.grant = Grant{Allow: true, HasSession: true, Subject: execUser, Provider: "skills_repo", ConnectorID: execConnector,
		Capabilities: []string{"skills.list", "skills.fetch"}, TenantID: execTenant, WorkspaceID: execWorkspace, Connector: descriptor, Descriptors: true}
	rig.daemon = &Daemon{
		Env: Env{
			ProviderTransport: transport,
			Audit: func(record []byte) error {
				rig.audit = append(rig.audit, string(record))
				return nil
			},
		},
		Authorize: func(context.Context, DaemonCall) (Grant, error) { return rig.grant, nil },
		UseCredential: func(_ context.Context, _, subject, provider string, fn func(string) error) error {
			if subject != execUser || provider != "skills_repo" {
				t.Errorf("session credential for %q/%q", subject, provider)
			}
			return fn(daemonSkillsTok)
		},
	}
	return rig
}

func (rig *skillsDaemonRig) invoke(capability, resource string) daemonResponse {
	rig.t.Helper()
	body, _ := json.Marshal(daemonRequest{Schema: daemonRequestSchema, ConnectorID: execConnector, Capability: capability, Action: "read", Resource: resource, TraceID: "trace-hai-431", AgentID: execAgent})
	rec := httptest.NewRecorder()
	rig.daemon.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, DaemonInvokePath, bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		rig.t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	for name, text := range map[string]string{"socket response": rec.Body.String(), "audit": strings.Join(rig.audit, "\n"), "log": rig.logs.String()} {
		if strings.Contains(text, daemonSkillsTok) {
			rig.t.Fatalf("%s leaked the session GitHub token", name)
		}
	}
	var out daemonResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		rig.t.Fatal(err)
	}
	return out
}

func TestDaemonSkillsRepoListAndFetch(t *testing.T) {
	rig := newSkillsDaemonRig(t)
	list := rig.invoke("skills.list", "skills")
	if list.Decision != "allow" || !strings.Contains(string(list.Result), `"name":"demo"`) || !strings.Contains(string(list.Result), `"name":"lint"`) {
		t.Fatalf("list = %s %s %s", list.Decision, list.ReasonCode, list.Result)
	}
	fetch := rig.invoke("skills.fetch", "skills/demo")
	if fetch.Decision != "allow" {
		t.Fatalf("fetch = %s %s", fetch.ReasonCode, fetch.Reason)
	}
	var result any
	if err := json.Unmarshal(fetch.Result, &result); err != nil {
		t.Fatal(err)
	}
	archive := decodeSkillArchive(t, result, rig.github.commit)
	if files := untarSkill(t, archive); string(files["demo/SKILL.md"]) != string(skillMD("demo")) {
		t.Fatalf("archive files = %v", keys(files))
	}
	if strings.Contains(rig.logs.String(), string(fetch.Result[:64])) {
		t.Fatal("the fetch result reached the log")
	}
}

func TestDaemonSkillsRepoDenyMakesNoGitHubCall(t *testing.T) {
	cases := []struct {
		name, capability, resource, reasonCode string
		grant                                  func(*Grant)
	}{
		{"authorize deny", "skills.fetch", "skills/demo", "policy_deny", func(g *Grant) {
			g.Allow, g.ReasonCode, g.Reason = false, "policy_deny", "no matching policy"
		}},
		{"traversal", "skills.fetch", "skills/../secrets", "input_invalid", func(*Grant) {}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newSkillsDaemonRig(t)
			tc.grant(&rig.grant)
			rig.daemon.UseCredential = func(_ context.Context, _, _, _ string, fn func(string) error) error {
				if tc.name == "authorize deny" {
					t.Error("a denied call must not use the session credential")
				}
				return fn(daemonSkillsTok)
			}
			out := rig.invoke(tc.capability, tc.resource)
			if out.Decision != "deny" || out.ReasonCode != tc.reasonCode || len(out.Result) != 0 {
				t.Fatalf("outcome = %s %s %s", out.Decision, out.ReasonCode, out.Result)
			}
			if n := rig.github.callCount(); n != 0 {
				t.Fatalf("github called %d times on a deny", n)
			}
		})
	}
}
