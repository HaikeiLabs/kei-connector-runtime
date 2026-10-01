package invoke

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	execDiscordTok     = "fake-discord-bot-token-0001.AAAA.BBBB"
	execDiscordChannel = "323456789012345678"
	discordCaps        = `[{"name":"guild.list","action":"read"},{"name":"guild.read","action":"read"},{"name":"channel.list","action":"read"},{"name":"channel.read","action":"read"},{"name":"thread.list","action":"read"},{"name":"message.list","action":"read"},{"name":"message.read","action":"read"},{"name":"role.list","action":"read"}]`
)

var discordMessages = "channels/" + execDiscordChannel + "/messages"

func discordAllow() string {
	return allowJSON(envelopeJSON("message.list", "read", discordMessages, execUser), descriptorJSON("discord", "opaque_ref", "", "", discordCaps, ""), "")
}

func runDiscord(h *execHarness, extra ...string) (map[string]any, int) {
	h.t.Helper()
	out, code := h.run(append([]string{"--capability", "message.list", "--action", "read", "--resource", discordMessages, "--user", execUser}, extra...)...)
	for name, text := range map[string]string{"stdout": h.lastStdout, "stderr": h.lastStderr, "audit": strings.Join(h.lastAuditLines, "\n")} {
		if strings.Contains(text, execDiscordTok) {
			h.t.Fatalf("%s leaked the discord bot token", name)
		}
	}
	return out, code
}

// Discord resolves its bot token from the tenant secret store (path 1) and
// returns redacted messages.
func TestConnectorInvokeDiscordMessageListUsesTheBotToken(t *testing.T) {
	h := newExecHarness(t)
	h.store.values[execBackend+"|"+execSecretRef] = execDiscordTok
	h.catalogBody = discordAllow()
	h.transport.routes["discord.com"] = func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bot "+execDiscordTok {
			t.Errorf("discord authorization = %q", got)
		}
		if r.URL.Path != "/api/v10/"+discordMessages || r.URL.Query().Get("limit") != "10" {
			t.Errorf("discord request = %s", r.URL)
		}
		_, _ = io.WriteString(w, `[{"id":"523456789012345678","channel_id":"`+execDiscordChannel+`","content":"ship it","timestamp":"2026-09-01T10:00:00+00:00","author":{"id":"623456789012345678","username":"alice","email":"alice@example.com"},"attachments":[{"url":"https://cdn.discordapp.com/x.png"}]}]`)
	}
	out, code := runDiscord(h, "--input", `{"limit":10}`)
	if code != 0 {
		t.Fatalf("outcome = %d %v (stderr %q)", code, out, h.lastStderr)
	}
	msgs := out["result"].(map[string]any)["messages"].([]any)
	if len(msgs) != 1 || msgs[0].(map[string]any)["content"] != "ship it" ||
		strings.Contains(h.lastStdout, "alice@example.com") || strings.Contains(h.lastStdout, "cdn.discordapp.com") {
		t.Fatalf("result = %v", out["result"])
	}
	if rec := h.auditRecord(); rec["credential_source"] != "opaque_ref" || rec["decision"] != "allow" {
		t.Fatalf("audit = %v", rec)
	}
}

func TestConnectorInvokeDiscordFailsClosedWithoutCallingDiscord(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name       string
		setup      func(h *execHarness)
		extra      []string
		reasonCode string
	}{
		{"missing credential", func(h *execHarness) { h.catalogBody = discordAllow() }, nil, "credential_unavailable"},
		{"empty credential", func(h *execHarness) {
			h.store.values[execBackend+"|"+execSecretRef] = ""
			h.catalogBody = discordAllow()
		}, nil, "credential_unavailable"},
		{"policy deny", func(h *execHarness) {
			h.store.values[execBackend+"|"+execSecretRef] = execDiscordTok
			h.catalogBody = `{"decision":"deny","reason_code":"policy_deny","reason":"no matching policy"}`
		}, nil, "policy_deny"},
		{"oauth descriptor", func(h *execHarness) {
			h.catalogBody = allowJSON(envelopeJSON("message.list", "read", discordMessages, execUser), descriptorJSON("discord", "oauth", "", execUser, discordCaps, ""), oauthJSON(now.Add(time.Minute)))
		}, nil, "descriptor_invalid"},
		{"input over the limit", func(h *execHarness) {
			h.store.values[execBackend+"|"+execSecretRef] = execDiscordTok
			h.catalogBody = discordAllow()
		}, []string{"--input", `{"limit":500}`}, "input_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newExecHarness(t)
			h.now = now
			tc.setup(h)
			h.transport.routes["discord.com"] = func(http.ResponseWriter, *http.Request) {}
			out, code := runDiscord(h, tc.extra...)
			h.assertDeny(out, code, tc.reasonCode)
			if n := h.transport.callCount(); n != 0 {
				t.Fatalf("discord called %d times on a deny", n)
			}
			if rec := h.auditRecord(); rec["decision"] != "deny" || rec["policy_reason"] != tc.reasonCode {
				t.Fatalf("audit = %v", rec)
			}
		})
	}
}

// Provider statuses map to reason codes, and a provider error body that
// echoes the token never reaches stdout, stderr, or audit.
func TestConnectorInvokeDiscordProviderStatuses(t *testing.T) {
	for status, reason := range map[int]string{
		http.StatusUnauthorized:    "provider_denied",
		http.StatusForbidden:       "provider_denied",
		http.StatusNotFound:        "provider_not_found",
		http.StatusTooManyRequests: "provider_rate_limited",
	} {
		t.Run(reason+fmt.Sprint(status), func(t *testing.T) {
			h := newExecHarness(t)
			h.store.values[execBackend+"|"+execSecretRef] = execDiscordTok
			h.catalogBody = discordAllow()
			h.transport.routes["discord.com"] = func(w http.ResponseWriter, _ *http.Request) {
				// A Retry-After beyond the connector's wait limit: no retry.
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"message":"bad token `+execDiscordTok+`"}`)
			}
			out, code := runDiscord(h)
			h.assertDeny(out, code, reason)
			if n := h.transport.callCount(); n != 1 {
				t.Fatalf("discord calls = %d, want 1", n)
			}
		})
	}
}
