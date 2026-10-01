// Package discord is the discord connector: guild, channel, thread, message,
// and role reads against the Discord HTTP API v10, using a bot token
// (credential path 1, opaque_ref only). The contract module defines the
// capabilities and the Guard; the HTTP client lives here.
//
// Redaction: results are re-encoded from the typed structs below. Messages
// keep their content, author id and username, and timestamps; attachments
// and reactions are reduced to counts, and embeds, mentions, and every other
// user field (email, avatar, and so on) are dropped when the response is
// decoded. Guild members are not readable.
//
// Rate limits: a 429 whose Retry-After is at most maxRetryAfter is retried,
// up to maxAttempts requests in all, inside the provider deadline. This is
// the one read that is retried (docs/connector-execution-contract.md,
// section 7). A longer or missing Retry-After fails at once as
// provider_rate_limited.
package discord

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-contracts/providers"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

const (
	apiBase      = "https://discord.com/api/v10"
	userAgent    = "DiscordBot (https://haikeilabs.com, 1)"
	defaultLimit = 25
	// maxAttempts bounds the requests one read makes when rate limited.
	maxAttempts = 3
	// maxRetryAfter is the longest Retry-After the connector waits out.
	maxRetryAfter = 2 * time.Second
)

// snowflake is a Discord id: 17 to 20 decimal digits.
var snowflake = regexp.MustCompile(`^[0-9]{17,20}$`)

// resources maps each capability to its resource pattern; "{id}" is a
// snowflake.
var resources = map[string]string{
	"guild.list":   "guilds",
	"guild.read":   "guilds/{id}",
	"channel.list": "guilds/{id}/channels",
	"role.list":    "guilds/{id}/roles",
	"channel.read": "channels/{id}",
	"thread.list":  "channels/{id}/threads",
	"message.list": "channels/{id}/messages",
	"message.read": "channels/{id}/messages/{id}",
}

// GuildSummary is one guild the bot belongs to.
type GuildSummary struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Owner bool   `json:"owner"`
}

// GuildList is a page of guilds. NextAfter is set when the page is full.
type GuildList struct {
	Guilds    []GuildSummary `json:"guilds"`
	NextAfter string         `json:"next_after,omitempty"`
}

// Guild is one guild's metadata.
type Guild struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	OwnerID     string `json:"owner_id"`
	MemberCount int    `json:"member_count"`
}

// Channel is one channel's metadata. Permission overwrites are dropped.
type Channel struct {
	ID            string `json:"id"`
	GuildID       string `json:"guild_id,omitempty"`
	Name          string `json:"name"`
	Type          int    `json:"type"`
	Position      int    `json:"position"`
	ParentID      string `json:"parent_id,omitempty"`
	Topic         string `json:"topic,omitempty"`
	LastMessageID string `json:"last_message_id,omitempty"`
}

// Thread is one active thread.
type Thread struct {
	ID           string `json:"id"`
	GuildID      string `json:"guild_id"`
	ParentID     string `json:"parent_id"`
	Name         string `json:"name"`
	Type         int    `json:"type"`
	MessageCount int    `json:"message_count"`
	Archived     bool   `json:"archived"`
}

// Author is the part of a message author the connector keeps.
type Author struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Bot      bool   `json:"bot"`
}

// Message is one message, without attachments, embeds, or mentions.
type Message struct {
	ID              string     `json:"id"`
	ChannelID       string     `json:"channel_id"`
	Type            int        `json:"type"`
	Content         string     `json:"content"`
	Author          Author     `json:"author"`
	Timestamp       time.Time  `json:"timestamp"`
	EditedAt        *time.Time `json:"edited_at,omitempty"`
	AttachmentCount int        `json:"attachment_count"`
	ReactionCount   int        `json:"reaction_count"`
}

// MessageList is a page of messages. When the page is full, NextBefore (or
// NextAfter, when paging forward) is the cursor for the next page.
type MessageList struct {
	Messages   []Message `json:"messages"`
	NextBefore string    `json:"next_before,omitempty"`
	NextAfter  string    `json:"next_after,omitempty"`
}

// Role is one guild role.
type Role struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Position    int    `json:"position"`
	Permissions string `json:"permissions"`
	Managed     bool   `json:"managed"`
}

// Connector executes discord reads.
type Connector struct{}

// Execute runs one discord read. The resource and input are checked before
// the contract Guard, and both before any request.
func (Connector) Execute(ctx context.Context, call connector.Call) (any, error) {
	if call.Meta.EffectiveCredentialSource() != contract.CredentialSourceOpaqueRef || call.Credential == "" {
		return nil, connector.ErrConfig
	}
	capability := call.Invocation.Capability
	pattern, ok := resources[capability]
	if !ok {
		return nil, connector.ErrInput
	}
	ids, ok := match(pattern, call.Invocation.Resource)
	if !ok || !inputFits(capability, call.Input) {
		return nil, connector.ErrInput
	}
	if err := providers.Guard(call.Meta, call.Invocation); err != nil {
		return nil, err
	}
	// Redirects are refused: one could carry the token to another host.
	client := *call.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	b := &backend{client: &client, token: call.Credential}
	switch capability {
	case "guild.list":
		return b.guilds(ctx, call.Input.(input.DiscordGuildList))
	case "guild.read":
		return b.guild(ctx, ids[0])
	case "channel.list":
		return b.channels(ctx, ids[0])
	case "role.list":
		return b.roles(ctx, ids[0])
	case "channel.read":
		return b.channel(ctx, ids[0])
	case "thread.list":
		return b.threads(ctx, ids[0])
	case "message.list":
		return b.messages(ctx, ids[0], call.Input.(input.DiscordMessageList))
	default: // message.read
		return b.message(ctx, ids[0], ids[1])
	}
}

// match returns the snowflakes in resource if it fits pattern exactly.
func match(pattern, resource string) ([]string, bool) {
	want, got := strings.Split(pattern, "/"), strings.Split(resource, "/")
	if len(want) != len(got) {
		return nil, false
	}
	var ids []string
	for i, w := range want {
		switch {
		case w == "{id}" && snowflake.MatchString(got[i]):
			ids = append(ids, got[i])
		case w != got[i]:
			return nil, false
		}
	}
	return ids, true
}

func inputFits(capability string, in any) bool {
	switch capability {
	case "guild.list":
		_, ok := in.(input.DiscordGuildList)
		return ok
	case "message.list":
		_, ok := in.(input.DiscordMessageList)
		return ok
	}
	_, ok := in.(input.Empty)
	return ok
}

func limit(n int) int {
	if n <= 0 {
		return defaultLimit
	}
	return n
}

// backend is the Discord HTTP API, built per call with that call's token.
type backend struct {
	client *http.Client
	token  string
}

func (b *backend) guilds(ctx context.Context, in input.DiscordGuildList) (GuildList, error) {
	n := limit(in.Limit)
	q := url.Values{"limit": {strconv.Itoa(n)}}
	if in.After != "" {
		q.Set("after", in.After)
	}
	var raw []GuildSummary
	if err := b.get(ctx, "/users/@me/guilds", q, &raw); err != nil {
		return GuildList{}, err
	}
	out := GuildList{Guilds: capped(raw, n)}
	if len(raw) >= n {
		out.NextAfter = out.Guilds[len(out.Guilds)-1].ID
	}
	return out, nil
}

func (b *backend) guild(ctx context.Context, id string) (Guild, error) {
	var raw struct {
		Guild
		ApproximateMemberCount int `json:"approximate_member_count"`
	}
	if err := b.get(ctx, "/guilds/"+id, url.Values{"with_counts": {"true"}}, &raw); err != nil {
		return Guild{}, err
	}
	g := raw.Guild
	g.MemberCount = raw.ApproximateMemberCount
	return g, nil
}

func (b *backend) channels(ctx context.Context, guildID string) ([]Channel, error) {
	out := []Channel{}
	if err := b.get(ctx, "/guilds/"+guildID+"/channels", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (b *backend) roles(ctx context.Context, guildID string) ([]Role, error) {
	out := []Role{}
	if err := b.get(ctx, "/guilds/"+guildID+"/roles", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (b *backend) channel(ctx context.Context, id string) (Channel, error) {
	var c Channel
	if err := b.get(ctx, "/channels/"+id, nil, &c); err != nil {
		return Channel{}, err
	}
	return c, nil
}

// threads lists the channel's active threads. Discord lists them per guild,
// so the channel is read first for its guild.
func (b *backend) threads(ctx context.Context, channelID string) ([]Thread, error) {
	c, err := b.channel(ctx, channelID)
	if err != nil {
		return nil, err
	}
	if !snowflake.MatchString(c.GuildID) {
		return nil, errors.New("provider response was invalid")
	}
	var resp struct {
		Threads []struct {
			Thread
			Metadata struct {
				Archived bool `json:"archived"`
			} `json:"thread_metadata"`
		} `json:"threads"`
	}
	if err := b.get(ctx, "/guilds/"+c.GuildID+"/threads/active", nil, &resp); err != nil {
		return nil, err
	}
	out := []Thread{}
	for _, t := range resp.Threads {
		if t.ParentID == channelID {
			t.Thread.Archived = t.Metadata.Archived
			out = append(out, t.Thread)
		}
	}
	return out, nil
}

func (b *backend) messages(ctx context.Context, channelID string, in input.DiscordMessageList) (MessageList, error) {
	n := limit(in.Limit)
	q := url.Values{"limit": {strconv.Itoa(n)}}
	switch {
	case in.Before != "":
		q.Set("before", in.Before)
	case in.After != "":
		q.Set("after", in.After)
	}
	var raw []message
	if err := b.get(ctx, "/channels/"+channelID+"/messages", q, &raw); err != nil {
		return MessageList{}, err
	}
	out := MessageList{Messages: []Message{}}
	for _, m := range capped(raw, n) {
		out.Messages = append(out.Messages, m.redacted())
	}
	if len(raw) >= n {
		// Order within a page is Discord's; the cursor is the oldest id going
		// back and the newest going forward.
		oldest, newest := out.Messages[0].ID, out.Messages[0].ID
		for _, m := range out.Messages[1:] {
			if idLess(m.ID, oldest) {
				oldest = m.ID
			}
			if idLess(newest, m.ID) {
				newest = m.ID
			}
		}
		if in.After != "" {
			out.NextAfter = newest
		} else {
			out.NextBefore = oldest
		}
	}
	return out, nil
}

func (b *backend) message(ctx context.Context, channelID, id string) (Message, error) {
	var m message
	if err := b.get(ctx, "/channels/"+channelID+"/messages/"+id, nil, &m); err != nil {
		return Message{}, err
	}
	return m.redacted(), nil
}

// wait sleeps for d or until ctx ends; tests replace it.
var wait = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// get sends one GET, retrying a short rate limit. Provider bodies are read
// only on success, so provider error text cannot reach an error or a log.
func (b *backend) get(ctx context.Context, path string, q url.Values, out any) error {
	target := apiBase + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
		if err != nil {
			return errors.New("provider request could not be created")
		}
		req.Header.Set("Authorization", "Bot "+b.token)
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "application/json")
		resp, err := b.client.Do(req)
		if err != nil {
			return errors.New("provider request failed")
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt < maxAttempts {
			if d, ok := retryAfter(resp.Header); ok {
				resp.Body.Close()
				if err := wait(ctx, d); err != nil {
					return err
				}
				continue
			}
		}
		err = decode(resp, out)
		resp.Body.Close()
		return err
	}
}

func decode(resp *http.Response, out any) error {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("provider request was rejected")
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return errors.New("provider response was invalid")
	}
	return nil
}

// retryAfter reads the wait a 429 asks for, in seconds (fractions allowed),
// from Retry-After or X-RateLimit-Reset-After. It reports false when there is
// none or it exceeds maxRetryAfter.
func retryAfter(h http.Header) (time.Duration, bool) {
	v := h.Get("Retry-After")
	if v == "" {
		v = h.Get("X-RateLimit-Reset-After")
	}
	secs, err := strconv.ParseFloat(v, 64)
	if err != nil || secs < 0 || math.IsNaN(secs) {
		return 0, false
	}
	d := time.Duration(secs * float64(time.Second))
	return d, d <= maxRetryAfter
}

func capped[T any](items []T, n int) []T {
	if len(items) > n {
		return items[:n]
	}
	if items == nil {
		return []T{}
	}
	return items
}

// idLess orders snowflakes numerically.
func idLess(a, b string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

// message is the part of a Discord message the connector decodes.
type message struct {
	ID              string     `json:"id"`
	ChannelID       string     `json:"channel_id"`
	Type            int        `json:"type"`
	Content         string     `json:"content"`
	Author          Author     `json:"author"`
	Timestamp       time.Time  `json:"timestamp"`
	EditedTimestamp *time.Time `json:"edited_timestamp"`
	Attachments     []struct{} `json:"attachments"`
	Reactions       []struct {
		Count int `json:"count"`
	} `json:"reactions"`
}

func (m message) redacted() Message {
	out := Message{
		ID: m.ID, ChannelID: m.ChannelID, Type: m.Type, Content: m.Content, Author: m.Author,
		Timestamp: m.Timestamp, EditedAt: m.EditedTimestamp, AttachmentCount: len(m.Attachments),
	}
	for _, r := range m.Reactions {
		out.ReactionCount += r.Count
	}
	return out
}
