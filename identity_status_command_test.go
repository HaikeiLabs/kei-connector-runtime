package connectorruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

type statusCommandClient struct {
	keiruntime.RuntimeClient
	request keiruntime.IdentityStatusRequest
	result  *keiruntime.IdentityStatusResponse
	err     error
}

func (c *statusCommandClient) ResolveIdentityStatus(_ context.Context, _ string, r keiruntime.IdentityStatusRequest) (*keiruntime.IdentityStatusResponse, error) {
	c.request = r
	return c.result, c.err
}

func TestIdentityStatusCommandRecognizedResultsExitZero(t *testing.T) {
	for _, status := range []string{"unlinked", "linked_pending", "linked_approved", "linked_denied", "linked_unapproved", "linked_approved_other_workspace", "retry", "service_error"} {
		t.Run(status, func(t *testing.T) {
			c := &statusCommandClient{result: &keiruntime.IdentityStatusResponse{Status: status}}
			var out, stderr bytes.Buffer
			code := keiruntime.RunIdentityStatus([]string{"--platform-user-id", "u", "--tenant-id", "guild"}, &out, &stderr, Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: "https://example.test"}, func(string, time.Duration) keiruntime.RuntimeClient { return c })
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

func TestIdentityStatusCommandEmitsOnlySafeFailureCategory(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failure  *keiruntime.IdentityStatusFailureError
		wantLine string
	}{
		{name: "pre-transport", failure: &keiruntime.IdentityStatusFailureError{Category: keiruntime.IdentityStatusFailurePreTransport}, wantLine: "category=pre_transport"},
		{name: "transport", failure: &keiruntime.IdentityStatusFailureError{Category: keiruntime.IdentityStatusFailureTransport}, wantLine: "category=transport_error"},
		{name: "http", failure: &keiruntime.IdentityStatusFailureError{Category: keiruntime.IdentityStatusFailureHTTP, HTTPStatusCode: 503}, wantLine: "category=http_response http_status=503"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &statusCommandClient{err: tc.failure}
			var out, stderr bytes.Buffer
			code := keiruntime.RunIdentityStatus([]string{"--platform-user-id", "private-user", "--tenant-id", "private-tenant"}, &out, &stderr, Config{RuntimeToken: "kh_live_private_token_12345678901234567890", RuntimeControlPlaneURL: "https://control.example"}, func(string, time.Duration) keiruntime.RuntimeClient { return client })
			if code != 1 || !strings.Contains(stderr.String(), tc.wantLine) {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
			for _, secret := range []string{"private-user", "private-tenant", "kh_live_private_token_12345678901234567890", "Bearer", "secret", "sensitive"} {
				if strings.Contains(stderr.String(), secret) {
					t.Fatalf("diagnostic leaked %q: %q", secret, stderr.String())
				}
			}
		})
	}
}

func TestIdentityStatusCommandGlobalTenantAndSafeFailures(t *testing.T) {
	cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: "https://example.test"}
	client := &statusCommandClient{result: &keiruntime.IdentityStatusResponse{Status: "unlinked"}}
	var out, stderr bytes.Buffer
	if code := keiruntime.RunIdentityStatus([]string{"--platform-user-id", "discord-user"}, &out, &stderr, cfg, func(string, time.Duration) keiruntime.RuntimeClient { return client }); code != 0 || client.request.TenantID != "" {
		t.Fatalf("code=%d request=%+v", code, client.request)
	}
	client.err = errors.New("Bearer kh_live_secret claim=private")
	out.Reset()
	stderr.Reset()
	code := keiruntime.RunIdentityStatus([]string{"--platform-user-id", "u", "--tenant-id", "t"}, &out, &stderr, cfg, func(string, time.Duration) keiruntime.RuntimeClient { return client })
	if code == 0 || out.Len() != 0 || strings.Contains(stderr.String(), "secret") || strings.Contains(stderr.String(), "private") {
		t.Fatalf("code=%d out=%q stderr=%q", code, out.String(), stderr.String())
	}
	for _, args := range [][]string{{}, {"--platform-user-id", "u", "--org-id", "override"}, {"--platform-user-id", "u", "positional"}} {
		out.Reset()
		stderr.Reset()
		if code := keiruntime.RunIdentityStatus(args, &out, &stderr, cfg, func(string, time.Duration) keiruntime.RuntimeClient { t.Fatal("must not create client"); return nil }); code == 0 || stderr.Len() == 0 {
			t.Fatalf("args=%v code=%d stderr=%q", args, code, stderr.String())
		}
	}
}
