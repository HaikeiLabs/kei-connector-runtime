package discord

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/connectortest"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

const (
	token     = "fake-discord-bot-token-0001.AAAA.BBBB"
	guildID   = "223456789012345678"
	channelID = "323456789012345678"
	threadID  = "423456789012345678"
	messageID = "523456789012345678"
	// Values that must never leave the runtime.
	authorEmail   = "alice@example.com"
	attachmentURL = "https://cdn.discordapp.com/attachments/secret.png"
)

func routes(t *testing.T, handle func(w http.ResponseWriter, r *http.Request)) *connectortest.Routes {
	r := connectortest.NewRoutes()
	r.Handle("discord.com", func(w http.ResponseWriter, req *http.Request) {
		if got := req.Header.Get("Authorization"); got != "Bot "+token {
			t.Errorf("authorization = %q", got)
		}
		if req.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", req.Method)
		}
		if !strings.HasPrefix(req.Header.Get("User-Agent"), "DiscordBot (") {
			t.Errorf("User-Agent = %q", req.Header.Get("User-Agent"))
		}
		handle(w, req)
	})
	return r
}

func call(r *connectortest.Routes, capability, resource string, in any) connector.Call {
	return connectortest.Call(r, contract.ProviderDiscord, capability, contract.ActionRead, resource, in, token)
}

func execute(t *testing.T, r *connectortest.Routes, capability, resource string, in any) any {
	t.Helper()
	got, err := Connector{}.Execute(context.Background(), call(r, capability, resource, in))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	assertNoLeak(t, got)
	return got
}

func assertNoLeak(t *testing.T, got any) {
	t.Helper()
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{token, authorEmail, attachmentURL} {
		if strings.Contains(string(raw), leaked) {
			t.Fatalf("result leaked %q: %s", leaked, raw)
		}
	}
}

func messageJSON(id string) string {
	return `{"id":"` + id + `","channel_id":"` + channelID + `","type":0,"content":"ship it",` +
		`"timestamp":"2026-09-01T10:00:00.000000+00:00","edited_timestamp":null,` +
		`"author":{"id":"623456789012345678","username":"alice","bot":false,"email":"` + authorEmail + `"},` +
		`"attachments":[{"id":"1","url":"` + attachmentURL + `"}],"embeds":[{"description":"x"}],` +
		`"mentions":[{"id":"7","email":"` + authorEmail + `"}],"reactions":[{"count":3},{"count":2}]}`
}

func TestGuildListPassesTheCursorAndReturnsNextAfter(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/v10/users/@me/guilds" {
			t.Errorf("path = %s", req.URL.Path)
		}
		if q := req.URL.Query(); q.Get("limit") != "2" || q.Get("after") != "100000000000000000" {
			t.Errorf("query = %v", q)
		}
		_, _ = io.WriteString(w, `[{"id":"`+guildID+`","name":"Haikei","owner":true,"permissions":"8"},{"id":"223456789012345679","name":"Other","owner":false}]`)
	})
	got := execute(t, r, "guild.list", "guilds", input.DiscordGuildList{Limit: 2, After: "100000000000000000"})
	res := got.(GuildList)
	if len(res.Guilds) != 2 || res.Guilds[0].ID != guildID || res.Guilds[0].Name != "Haikei" || !res.Guilds[0].Owner {
		t.Fatalf("guilds = %+v", res.Guilds)
	}
	if res.NextAfter != "223456789012345679" {
		t.Fatalf("next_after = %q", res.NextAfter)
	}
}

func TestGuildListShortPageHasNoCursorAndDefaultsTheLimit(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request) {
		if got := req.URL.Query().Get("limit"); got != "25" {
			t.Errorf("limit = %q, want default 25", got)
		}
		if req.URL.Query().Has("after") {
			t.Errorf("empty cursor was sent")
		}
		_, _ = io.WriteString(w, `[{"id":"`+guildID+`","name":"Haikei"}]`)
	})
	res := execute(t, r, "guild.list", "guilds", input.DiscordGuildList{}).(GuildList)
	if res.NextAfter != "" || len(res.Guilds) != 1 {
		t.Fatalf("result = %+v", res)
	}
}

func TestGuildRead(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/v10/guilds/"+guildID || req.URL.Query().Get("with_counts") != "true" {
			t.Errorf("request = %s", req.URL)
		}
		_, _ = io.WriteString(w, `{"id":"`+guildID+`","name":"Haikei","owner_id":"623456789012345678","description":"d","approximate_member_count":42,"roles":[{"id":"1"}],"emojis":[]}`)
	})
	g := execute(t, r, "guild.read", "guilds/"+guildID, input.Empty{}).(Guild)
	if g.ID != guildID || g.Name != "Haikei" || g.OwnerID != "623456789012345678" || g.MemberCount != 42 {
		t.Fatalf("guild = %+v", g)
	}
}

func TestChannelList(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/v10/guilds/"+guildID+"/channels" {
			t.Errorf("path = %s", req.URL.Path)
		}
		_, _ = io.WriteString(w, `[{"id":"`+channelID+`","guild_id":"`+guildID+`","name":"general","type":0,"position":1,"parent_id":null,"permission_overwrites":[{"id":"9"}]}]`)
	})
	got := execute(t, r, "channel.list", "guilds/"+guildID+"/channels", input.Empty{}).([]Channel)
	if len(got) != 1 || got[0].ID != channelID || got[0].Name != "general" || got[0].GuildID != guildID || got[0].Position != 1 {
		t.Fatalf("channels = %+v", got)
	}
}

func TestChannelRead(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/v10/channels/"+channelID {
			t.Errorf("path = %s", req.URL.Path)
		}
		_, _ = io.WriteString(w, `{"id":"`+channelID+`","guild_id":"`+guildID+`","name":"general","type":0,"topic":"launch","last_message_id":"`+messageID+`"}`)
	})
	c := execute(t, r, "channel.read", "channels/"+channelID, input.Empty{}).(Channel)
	if c.ID != channelID || c.Topic != "launch" || c.LastMessageID != messageID {
		t.Fatalf("channel = %+v", c)
	}
}

// Discord lists active threads per guild, so thread.list reads the channel
// for its guild and keeps only that channel's threads.
func TestThreadListKeepsOnlyTheChannelsActiveThreads(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/v10/channels/" + channelID:
			_, _ = io.WriteString(w, `{"id":"`+channelID+`","guild_id":"`+guildID+`","name":"general","type":0}`)
		case "/api/v10/guilds/" + guildID + "/threads/active":
			_, _ = io.WriteString(w, `{"threads":[`+
				`{"id":"`+threadID+`","guild_id":"`+guildID+`","parent_id":"`+channelID+`","name":"rfc","type":11,"message_count":4,"thread_metadata":{"archived":false}},`+
				`{"id":"423456789012345679","guild_id":"`+guildID+`","parent_id":"999999999999999999","name":"elsewhere","type":11}],`+
				`"members":[{"user_id":"7"}]}`)
		default:
			t.Errorf("unexpected path %s", req.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	got := execute(t, r, "thread.list", "channels/"+channelID+"/threads", input.Empty{}).([]Thread)
	if len(got) != 1 || got[0].ID != threadID || got[0].ParentID != channelID || got[0].Name != "rfc" || got[0].MessageCount != 4 {
		t.Fatalf("threads = %+v", got)
	}
}

func TestMessageListRedactsAndReturnsNextBefore(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/v10/channels/"+channelID+"/messages" {
			t.Errorf("path = %s", req.URL.Path)
		}
		if q := req.URL.Query(); q.Get("limit") != "2" || q.Get("before") != "923456789012345678" || q.Has("after") {
			t.Errorf("query = %v", q)
		}
		_, _ = io.WriteString(w, `[`+messageJSON(messageID)+`,`+messageJSON("523456789012345677")+`]`)
	})
	res := execute(t, r, "message.list", "channels/"+channelID+"/messages", input.DiscordMessageList{Limit: 2, Before: "923456789012345678"}).(MessageList)
	if len(res.Messages) != 2 || res.NextBefore != "523456789012345677" {
		t.Fatalf("result = %+v", res)
	}
	m := res.Messages[0]
	if m.ID != messageID || m.Content != "ship it" || m.Author.ID != "623456789012345678" || m.Author.Username != "alice" ||
		m.AttachmentCount != 1 || m.ReactionCount != 5 || m.Timestamp.IsZero() {
		t.Fatalf("message = %+v", m)
	}
}

func TestMessageListDefaultsAndCapsTheLimit(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request) {
		if got := req.URL.Query().Get("limit"); got != "25" {
			t.Errorf("limit = %q", got)
		}
		// A provider that ignores limit still cannot widen the result.
		items := make([]string, 30)
		for i := range items {
			items[i] = messageJSON(messageID)
		}
		_, _ = io.WriteString(w, `[`+strings.Join(items, ",")+`]`)
	})
	res := execute(t, r, "message.list", "channels/"+channelID+"/messages", input.DiscordMessageList{}).(MessageList)
	if len(res.Messages) != 25 {
		t.Fatalf("messages = %d, want 25", len(res.Messages))
	}
}

func TestMessageRead(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/v10/channels/"+channelID+"/messages/"+messageID {
			t.Errorf("path = %s", req.URL.Path)
		}
		_, _ = io.WriteString(w, messageJSON(messageID))
	})
	m := execute(t, r, "message.read", "channels/"+channelID+"/messages/"+messageID, input.Empty{}).(Message)
	if m.ID != messageID || m.ChannelID != channelID || m.Content != "ship it" {
		t.Fatalf("message = %+v", m)
	}
}

func TestRoleList(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/v10/guilds/"+guildID+"/roles" {
			t.Errorf("path = %s", req.URL.Path)
		}
		_, _ = io.WriteString(w, `[{"id":"`+guildID+`","name":"@everyone","position":0,"permissions":"1071698660929","managed":false,"color":0}]`)
	})
	got := execute(t, r, "role.list", "guilds/"+guildID+"/roles", input.Empty{}).([]Role)
	if len(got) != 1 || got[0].Name != "@everyone" || got[0].Permissions != "1071698660929" {
		t.Fatalf("roles = %+v", got)
	}
}

// Every bad resource, input, or credential fails closed before any request.
func TestFailsClosedWithoutAProviderRequest(t *testing.T) {
	cases := []struct {
		name       string
		capability string
		resource   string
		in         any
		mutate     func(*connector.Call)
		want       error
	}{
		{"missing credential", "guild.read", "guilds/" + guildID, input.Empty{}, func(c *connector.Call) { c.Credential = "" }, connector.ErrConfig},
		{"oauth descriptor", "guild.read", "guilds/" + guildID, input.Empty{}, func(c *connector.Call) { c.Meta.CredentialSource = contract.CredentialSourceOAuth }, connector.ErrConfig},
		{"non-snowflake guild", "guild.read", "guilds/haikei", input.Empty{}, nil, connector.ErrInput},
		{"traversal", "channel.read", "channels/../users/@me", input.Empty{}, nil, connector.ErrInput},
		{"extra segment", "guild.read", "guilds/" + guildID + "/bans", input.Empty{}, nil, connector.ErrInput},
		{"wrong resource for capability", "channel.list", "channels/" + channelID, input.Empty{}, nil, connector.ErrInput},
		{"wrong input type", "message.list", "channels/" + channelID + "/messages", input.Empty{}, nil, connector.ErrInput},
		{"unknown capability", "message.write", "channels/" + channelID + "/messages", input.Empty{}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := routes(t, func(http.ResponseWriter, *http.Request) {})
			c := call(r, tc.capability, tc.resource, tc.in)
			if tc.mutate != nil {
				tc.mutate(&c)
			}
			_, err := Connector{}.Execute(context.Background(), c)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), token) {
				t.Fatalf("error leaked the token: %v", err)
			}
			if r.Count() != 0 {
				t.Fatalf("provider requests = %d, want 0", r.Count())
			}
		})
	}
}

// Provider errors never carry the provider body or the token.
func TestProviderStatusesFailWithoutLeaking(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		r := routes(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"message":"401: Unauthorized `+token+`","code":0}`)
		})
		_, err := Connector{}.Execute(context.Background(), call(r, "guild.read", "guilds/"+guildID, input.Empty{}))
		if err == nil {
			t.Fatalf("status %d: expected an error", status)
		}
		if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "Unauthorized") {
			t.Fatalf("status %d: error leaked provider text: %v", status, err)
		}
		if r.Count() != 1 {
			t.Fatalf("status %d: requests = %d, want 1 (no retry)", status, r.Count())
		}
	}
}

func withWait(t *testing.T) *[]time.Duration {
	t.Helper()
	var waited []time.Duration
	orig := wait
	wait = func(_ context.Context, d time.Duration) error {
		waited = append(waited, d)
		return nil
	}
	t.Cleanup(func() { wait = orig })
	return &waited
}

func TestRateLimitHonorsAShortRetryAfter(t *testing.T) {
	waited := withWait(t)
	n := 0
	r := routes(t, func(w http.ResponseWriter, _ *http.Request) {
		n++
		if n == 1 {
			w.Header().Set("Retry-After", "0.5")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = io.WriteString(w, `{"id":"`+guildID+`","name":"Haikei"}`)
	})
	g := execute(t, r, "guild.read", "guilds/"+guildID, input.Empty{}).(Guild)
	if g.ID != guildID || r.Count() != 2 {
		t.Fatalf("guild = %+v, requests = %d", g, r.Count())
	}
	if len(*waited) != 1 || (*waited)[0] != 500*time.Millisecond {
		t.Fatalf("waited = %v", *waited)
	}
}

func TestRateLimitGivesUpOnALongRetryAfter(t *testing.T) {
	waited := withWait(t)
	r := routes(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_, err := Connector{}.Execute(context.Background(), call(r, "guild.read", "guilds/"+guildID, input.Empty{}))
	if err == nil || r.Count() != 1 || len(*waited) != 0 {
		t.Fatalf("err = %v, requests = %d, waited = %v", err, r.Count(), *waited)
	}
}

func TestRateLimitRetriesAreBounded(t *testing.T) {
	waited := withWait(t)
	r := routes(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_, err := Connector{}.Execute(context.Background(), call(r, "guild.read", "guilds/"+guildID, input.Empty{}))
	if err == nil || r.Count() != maxAttempts || len(*waited) != maxAttempts-1 {
		t.Fatalf("err = %v, requests = %d, waited = %v", err, r.Count(), *waited)
	}
}

func TestRateLimitWithoutRetryAfterDoesNotRetry(t *testing.T) {
	waited := withWait(t)
	r := routes(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_, err := Connector{}.Execute(context.Background(), call(r, "guild.read", "guilds/"+guildID, input.Empty{}))
	if err == nil || r.Count() != 1 || len(*waited) != 0 {
		t.Fatalf("err = %v, requests = %d, waited = %v", err, r.Count(), *waited)
	}
}

func TestWaitStopsAtTheDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := wait(ctx, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait err = %v", err)
	}
}

// A redirect is never followed: it could carry the token to another host.
func TestRedirectsAreNotFollowed(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://discord.com/api/v10/guilds/"+guildID+"/elsewhere")
		w.WriteHeader(http.StatusFound)
	})
	_, err := Connector{}.Execute(context.Background(), call(r, "guild.read", "guilds/"+guildID, input.Empty{}))
	if err == nil || r.Count() != 1 {
		t.Fatalf("err = %v, requests = %d, want an error after 1 request", err, r.Count())
	}
}
