package invoke

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	execGrafanaTok  = "glsa_fakeGrafanaServiceAccountToken_0001"
	execGrafanaHost = "grafana.internal.example"
	grafanaCaps     = `[{"name":"folder.list","action":"read"},{"name":"folder.read","action":"read"},{"name":"dashboard.search","action":"read"},{"name":"dashboard.read","action":"read"},{"name":"datasource.list","action":"read"},{"name":"datasource.read","action":"read"},{"name":"alert_rule.list","action":"read"},{"name":"annotation.list","action":"read"},{"name":"datasource.query","action":"read"}]`
)

func grafanaAllow(capability, resource, baseURL string) string {
	return allowJSON(envelopeJSON(capability, "read", resource, execUser),
		descriptorJSON("grafana", "opaque_ref", "", "", grafanaCaps, `,"grafana":{"base_url":"`+baseURL+`"}`), "")
}

func runGrafana(h *execHarness, capability, resource string, extra ...string) (map[string]any, int) {
	h.t.Helper()
	out, code := h.run(append([]string{"--capability", capability, "--action", "read", "--resource", resource, "--user", execUser}, extra...)...)
	for name, text := range map[string]string{"stdout": h.lastStdout, "stderr": h.lastStderr, "audit": strings.Join(h.lastAuditLines, "\n")} {
		if strings.Contains(text, execGrafanaTok) {
			h.t.Fatalf("%s leaked the grafana token", name)
		}
	}
	return out, code
}

// Grafana resolves its service-account token from the tenant secret store
// (path 1) and calls the connector's base_url; the query stays local.
func TestConnectorInvokeGrafanaDatasourceQueryUsesTheServiceAccountToken(t *testing.T) {
	h := newExecHarness(t)
	h.store.values[execBackend+"|"+execSecretRef] = execGrafanaTok
	h.catalogBody = grafanaAllow("datasource.query", "datasources/prom-main/query", "https://"+execGrafanaHost)
	h.transport.routes[execGrafanaHost] = func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+execGrafanaTok {
			t.Errorf("grafana authorization = %q", got)
		}
		switch r.URL.Path {
		case "/api/datasources/uid/prom-main":
			_, _ = io.WriteString(w, `{"uid":"prom-main","name":"Prometheus","type":"prometheus","url":"http://prom.secret:9090"}`)
		case "/api/ds/query":
			_, _ = io.WriteString(w, `{"results":{"A":{"frames":[{"schema":{"fields":[{"name":"Time","type":"time"},{"name":"Value","type":"number"}]},"data":{"values":[[1000],[42]]}}]}}}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}
	out, code := runGrafana(h, "datasource.query", "datasources/prom-main/query", "--input", `{"expr":"node_load1","max_rows":10}`)
	if code != 0 {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
	frames := out["result"].(map[string]any)["frames"].([]any)
	if len(frames) != 1 || strings.Contains(h.lastStdout, "prom.secret") {
		t.Fatalf("result = %v", out["result"])
	}
	catalogSent, _ := json.Marshal(h.catalogReqs)
	if strings.Contains(string(catalogSent), "node_load1") || strings.Contains(strings.Join(h.lastAuditLines, "\n"), "node_load1") {
		t.Fatalf("the query left the runtime: catalog %s audit %v", catalogSent, h.lastAuditLines)
	}
	if rec := h.auditRecord(); rec["credential_source"] != "opaque_ref" || rec["decision"] != "allow" {
		t.Fatalf("audit = %v", rec)
	}
}

func TestConnectorInvokeGrafanaFailsClosedWithoutCallingGrafana(t *testing.T) {
	now := time.Now().UTC()
	base := "https://" + execGrafanaHost
	cases := []struct {
		name       string
		setup      func(h *execHarness)
		extra      []string
		reasonCode string
	}{
		{"missing credential", func(h *execHarness) { h.catalogBody = grafanaAllow("datasource.list", "datasources", base) }, nil, "credential_unavailable"},
		{"policy deny", func(h *execHarness) {
			h.store.values[execBackend+"|"+execSecretRef] = execGrafanaTok
			h.catalogBody = `{"decision":"deny","reason_code":"policy_deny","reason":"no matching policy"}`
		}, nil, "policy_deny"},
		{"oauth descriptor", func(h *execHarness) {
			h.catalogBody = allowJSON(envelopeJSON("datasource.list", "read", "datasources", execUser),
				descriptorJSON("grafana", "oauth", "", execUser, grafanaCaps, `,"grafana":{"base_url":"`+base+`"}`), oauthJSON(now.Add(time.Minute)))
		}, nil, "descriptor_invalid"},
		{"plain http base_url", func(h *execHarness) {
			h.store.values[execBackend+"|"+execSecretRef] = execGrafanaTok
			h.catalogBody = grafanaAllow("datasource.list", "datasources", "http://"+execGrafanaHost)
		}, nil, "descriptor_invalid"},
		{"metadata base_url", func(h *execHarness) {
			h.store.values[execBackend+"|"+execSecretRef] = execGrafanaTok
			h.catalogBody = grafanaAllow("datasource.list", "datasources", "https://169.254.169.254")
		}, nil, "descriptor_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newExecHarness(t)
			h.now = now
			tc.setup(h)
			h.transport.routes[execGrafanaHost] = func(http.ResponseWriter, *http.Request) {}
			out, code := runGrafana(h, "datasource.list", "datasources", tc.extra...)
			h.assertDeny(out, code, tc.reasonCode)
			if n := h.transport.callCount(); n != 0 {
				t.Fatalf("grafana called %d times on a deny", n)
			}
			if rec := h.auditRecord(); rec["decision"] != "deny" || rec["policy_reason"] != tc.reasonCode {
				t.Fatalf("audit = %v", rec)
			}
		})
	}
}

// An over-long range is refused locally before the catalog is asked.
func TestConnectorInvokeGrafanaQueryRangeIsBounded(t *testing.T) {
	h := newExecHarness(t)
	h.store.values[execBackend+"|"+execSecretRef] = execGrafanaTok
	h.catalogBody = grafanaAllow("datasource.query", "datasources/prom-main/query", "https://"+execGrafanaHost)
	h.transport.routes[execGrafanaHost] = func(http.ResponseWriter, *http.Request) {}
	week := int64(7 * 24 * 60 * 60 * 1000)
	out, code := runGrafana(h, "datasource.query", "datasources/prom-main/query", "--input", fmt.Sprintf(`{"expr":"up","from":1000,"to":%d}`, 1000+week+1))
	h.assertDeny(out, code, "input_invalid")
	if n := h.transport.callCount(); n != 0 {
		t.Fatalf("grafana calls = %d", n)
	}
}

func TestConnectorInvokeGrafanaProviderStatuses(t *testing.T) {
	for status, reason := range map[int]string{
		http.StatusUnauthorized:    "provider_denied",
		http.StatusForbidden:       "provider_denied",
		http.StatusNotFound:        "provider_not_found",
		http.StatusTooManyRequests: "provider_rate_limited",
	} {
		t.Run(reason+fmt.Sprint(status), func(t *testing.T) {
			h := newExecHarness(t)
			h.store.values[execBackend+"|"+execSecretRef] = execGrafanaTok
			h.catalogBody = grafanaAllow("folder.read", "folders/f1", "https://"+execGrafanaHost)
			h.transport.routes[execGrafanaHost] = func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"message":"invalid API key `+execGrafanaTok+`"}`)
			}
			out, code := runGrafana(h, "folder.read", "folders/f1")
			h.assertDeny(out, code, reason)
			if n := h.transport.callCount(); n != 1 {
				t.Fatalf("grafana calls = %d, want 1", n)
			}
		})
	}
}
