package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
}

func (c testRuntimeConfig) IsRuntime() bool         { return c.token != "" }
func (c testRuntimeConfig) Validate() error         { return ValidateRuntimeTokenFormat(c.token) }
func (c testRuntimeConfig) Token() string           { return c.token }
func (c testRuntimeConfig) ControlPlaneURL() string { return c.controlPlaneURL }

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

// TestIdentityLinkCallsRuntimeClaimAPI drives `identity link` through the real
// runtime client against a fake control plane: the claim starts on the
// catalog runtime API (served on the runtime host, like heartbeat) with the
// runtime bearer only, and stdout keeps the {claim_url, expires_at} shape.
func TestIdentityLinkCallsRuntimeClaimAPI(t *testing.T) {
	const token = "kh_live_runtime_test_token_1234567890"
	const owuiUser = "0b7d5a52-9a8e-4f5e-8f3b-2f1c6a7d9e10"
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/runtime/chat-identity-claims" {
			t.Errorf("request = %s %s, want POST /api/v1/runtime/chat-identity-claims", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q, want the runtime bearer", got)
		}
		if got := r.Header.Get("X-KEI-API-Key"); got != "" {
			t.Errorf("X-KEI-API-Key = %q, want none", got)
		}
		var input map[string]string
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if want := map[string]string{"platform": "openwebui", "tenant_id": "", "platform_user_id": owuiUser}; fmt.Sprint(input) != fmt.Sprint(want) {
			t.Errorf("body = %#v, want %#v", input, want)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"claim_url":"https://console.example/identity/link#claim=opaque","expires_at":"2030-01-01T00:00:00Z"}`)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := runIdentityLink([]string{"--platform", "openwebui", "--platform-user-id", owuiUser}, &stdout, &stderr,
		testRuntimeConfig{token: token, controlPlaneURL: server.URL}, NewRuntimeClient)
	if code != 0 || stderr.Len() != 0 || calls != 1 {
		t.Fatalf("exit=%d calls=%d stderr=%q", code, calls, stderr.String())
	}
	if got, want := stdout.String(), "{\"claim_url\":\"https://console.example/identity/link#claim=opaque\",\"expires_at\":\"2030-01-01T00:00:00Z\"}\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}
