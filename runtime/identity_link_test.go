package runtime

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type identityClaimTestClient struct {
	token string
	input IdentityClaimStartRequest
	resp  *IdentityClaimStartResponse
	err   error
}

func (c *identityClaimTestClient) ResolveIdentityStatus(context.Context, string, IdentityStatusRequest) (*IdentityStatusResponse, error) {
	return nil, nil
}

func (c *identityClaimTestClient) WhoAmI(context.Context, string) (*RuntimeIdentity, error) {
	return nil, nil
}
func (c *identityClaimTestClient) Heartbeat(context.Context, string, HeartbeatReport) error {
	return nil
}
func (c *identityClaimTestClient) RegisterCredentialSyncKey(context.Context, string, string, string, string) error {
	return nil
}
func (c *identityClaimTestClient) StartIdentityClaim(_ context.Context, token string, input IdentityClaimStartRequest) (*IdentityClaimStartResponse, error) {
	c.token, c.input = token, input
	return c.resp, c.err
}
func (c *identityClaimTestClient) SyncTools(context.Context, string, *ToolManifest) error { return nil }

type testRuntimeConfig struct {
	token           string
	controlPlaneURL string
	flushURL        string
}

func (c testRuntimeConfig) IsRuntime() bool         { return c.token != "" }
func (c testRuntimeConfig) Validate() error         { return ValidateRuntimeTokenFormat(c.token) }
func (c testRuntimeConfig) Token() string           { return c.token }
func (c testRuntimeConfig) ControlPlaneURL() string { return c.controlPlaneURL }
func (c testRuntimeConfig) FlushURL() string        { return c.flushURL }

func TestIdentityLinkBeginWritesOnlyClaimJSONAndUsesRuntimeConfiguration(t *testing.T) {
	const token = "kh_live_runtime_test_token_1234567890"
	client := &identityClaimTestClient{resp: &IdentityClaimStartResponse{ClaimURL: "https://kei.example/claim#claim=secret", ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}}
	cfg := testRuntimeConfig{token: token, controlPlaneURL: "https://control.example"}
	var stdout, stderr bytes.Buffer
	code := runIdentityLink([]string{"--platform", "discord", "--platform-user-id", "u-123", "--timeout", "3s"}, &stdout, &stderr, cfg,
		func(base string, timeout time.Duration) RuntimeClient {
			if base != cfg.controlPlaneURL || timeout != 3*time.Second {
				t.Fatalf("factory args = %q, %v", base, timeout)
			}
			return client
		})
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if client.token != token || client.input != (IdentityClaimStartRequest{Platform: "discord", PlatformUserID: "u-123"}) {
		t.Fatalf("claim args = %q, %#v", client.token, client.input)
	}
	if got, want := stdout.String(), "{\"claim_url\":\"https://kei.example/claim#claim=secret\",\"expires_at\":\"2030-01-01T00:00:00Z\"}\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestIdentityLinkBeginAcceptsTenantAndRejectsScopeOverrides(t *testing.T) {
	client := &identityClaimTestClient{resp: &IdentityClaimStartResponse{ClaimURL: "https://kei.example/claim#claim=x", ExpiresAt: time.Now()}}
	var stdout, stderr bytes.Buffer
	code := runIdentityLink([]string{"--platform", "slack", "--platform-user-id", "u", "--tenant-id", "team"}, &stdout, &stderr,
		testRuntimeConfig{token: "kh_live_runtime_test_token_1234567890", controlPlaneURL: "https://control.example"},
		func(string, time.Duration) RuntimeClient { return client })
	if code != 0 || client.input.TenantID != "team" {
		t.Fatalf("exit=%d tenant=%q stderr=%q", code, client.input.TenantID, stderr.String())
	}
	for _, flag := range []string{"--installation-id", "--workspace-id"} {
		stdout.Reset()
		stderr.Reset()
		code = runIdentityLink([]string{"--platform", "discord", "--platform-user-id", "u", flag, "override"}, &stdout, &stderr, testRuntimeConfig{}, func(string, time.Duration) RuntimeClient { t.Fatal("client must not be created"); return nil })
		if code != 2 || stdout.Len() != 0 {
			t.Fatalf("override %s: exit=%d stdout=%q", flag, code, stdout.String())
		}
	}
}

func TestIdentityLinkBeginErrorsAreSecretSafe(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cfg      testRuntimeConfig
		response *IdentityClaimStartResponse
		err      error
		want     string
	}{
		{name: "missing token", cfg: testRuntimeConfig{controlPlaneURL: "https://control.example"}, want: "KEI_RUNTIME_TOKEN"},
		{name: "invalid credential", cfg: testRuntimeConfig{token: "secret-token", controlPlaneURL: "https://control.example"}, want: "KEI_RUNTIME_TOKEN"},
		{name: "request failure", cfg: testRuntimeConfig{token: "kh_live_runtime_test_token_1234567890", controlPlaneURL: "https://control.example"}, err: errors.New("secret response"), want: "failed"},
		{name: "empty response", cfg: testRuntimeConfig{token: "kh_live_runtime_test_token_1234567890", controlPlaneURL: "https://control.example"}, want: "empty control-plane response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &identityClaimTestClient{resp: tc.response, err: tc.err}
			var stdout, stderr bytes.Buffer
			code := runIdentityLink([]string{"--platform", "discord", "--platform-user-id", "u"}, &stdout, &stderr, tc.cfg, func(string, time.Duration) RuntimeClient { return client })
			if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), tc.want) || strings.Contains(stderr.String(), "secret") {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestIdentityLinkBeginRequiresIdentityArguments(t *testing.T) {
	for _, args := range [][]string{{"--platform", "discord"}, {"--platform-user-id", "u"}, {"--platform", "discord", "--platform-user-id", "u", "unexpected"}, {"--platform", "discord", "--platform-user-id", "u", "--timeout", "0"}} {
		var stdout, stderr bytes.Buffer
		code := runIdentityLink(args, &stdout, &stderr, testRuntimeConfig{}, func(string, time.Duration) RuntimeClient { t.Fatal("client must not be created"); return nil })
		if code != 2 || stdout.Len() == 0 && stderr.Len() == 0 {
			t.Fatalf("args=%v exit=%d", args, code)
		}
	}
}
