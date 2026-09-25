package connectorruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type statusCommandClient struct {
	RuntimeClient
	request IdentityStatusRequest
	result  *IdentityStatusResponse
	err     error
}

func (c *statusCommandClient) ResolveIdentityStatus(_ context.Context, _ string, r IdentityStatusRequest) (*IdentityStatusResponse, error) {
	c.request = r
	return c.result, c.err
}

func TestIdentityStatusCommandRecognizedResultsExitZero(t *testing.T) {
	for _, status := range []string{"unlinked", "linked_pending", "linked_approved", "linked_denied", "linked_unapproved", "linked_approved_other_workspace", "retry", "service_error"} {
		t.Run(status, func(t *testing.T) {
			c := &statusCommandClient{result: &IdentityStatusResponse{Status: status}}
			var out, stderr bytes.Buffer
			code := runIdentityStatus([]string{"--platform-user-id", "u", "--tenant-id", "guild"}, &out, &stderr, Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: "https://example.test"}, func(string, time.Duration) RuntimeClient { return c })
			var body map[string]any
			if err := json.Unmarshal(out.Bytes(), &body); err != nil || code != 0 || stderr.Len() != 0 || body["status"] != status {
				t.Fatalf("code=%d body=%s stderr=%q err=%v", code, out.String(), stderr.String(), err)
			}
			if c.request.PlatformUserID != "u" || c.request.TenantID != "guild" {
				t.Fatalf("request=%+v", c.request)
			}
		})
	}
}

func TestIdentityStatusCommandGlobalTenantAndSafeFailures(t *testing.T) {
	cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: "https://example.test"}
	client := &statusCommandClient{result: &IdentityStatusResponse{Status: "unlinked"}}
	var out, stderr bytes.Buffer
	if code := runIdentityStatus([]string{"--platform-user-id", "discord-user"}, &out, &stderr, cfg, func(string, time.Duration) RuntimeClient { return client }); code != 0 || client.request.TenantID != "" {
		t.Fatalf("code=%d request=%+v", code, client.request)
	}
	client.err = errors.New("Bearer kh_live_secret claim=private")
	out.Reset()
	stderr.Reset()
	code := runIdentityStatus([]string{"--platform-user-id", "u", "--tenant-id", "t"}, &out, &stderr, cfg, func(string, time.Duration) RuntimeClient { return client })
	if code == 0 || out.Len() != 0 || strings.Contains(stderr.String(), "secret") || strings.Contains(stderr.String(), "private") {
		t.Fatalf("code=%d out=%q stderr=%q", code, out.String(), stderr.String())
	}
	for _, args := range [][]string{{}, {"--platform-user-id", "u", "--org-id", "override"}, {"--platform-user-id", "u", "positional"}} {
		out.Reset()
		stderr.Reset()
		if code := runIdentityStatus(args, &out, &stderr, cfg, func(string, time.Duration) RuntimeClient { t.Fatal("must not create client"); return nil }); code == 0 || stderr.Len() == 0 {
			t.Fatalf("args=%v code=%d stderr=%q", args, code, stderr.String())
		}
	}
}
