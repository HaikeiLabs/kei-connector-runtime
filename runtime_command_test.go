package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingRuntimeClient struct {
	identity       *RuntimeIdentity
	whoamiErr      error
	heartbeatErr   error
	heartbeatCalls int
	registerCalls  int
	mu             sync.Mutex
}

func (c *recordingRuntimeClient) WhoAmI(context.Context, string) (*RuntimeIdentity, error) {
	return c.identity, c.whoamiErr
}

func (c *recordingRuntimeClient) Heartbeat(context.Context, string, string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.heartbeatCalls++
	return c.heartbeatErr
}
func (c *recordingRuntimeClient) RegisterCredentialSyncKey(context.Context, string, string, string, string) error {
	c.registerCalls++
	return nil
}

func TestRuntimeBootstrapReportsHeartbeatBeforeBotStartup(t *testing.T) {
	workspaceID := "workspace-1"
	client := &recordingRuntimeClient{identity: &RuntimeIdentity{ID: "installation-1", OrgID: "org-1", WorkspaceID: &workspaceID, Platform: "teams", Status: "pending", BindingStatus: "unverified"}}
	cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: "https://kei.example.test", RuntimeVersion: "test"}
	var stdout, stderr bytes.Buffer
	code := runRuntimeBootstrap(nil, &stdout, &stderr, cfg, func(string, time.Duration) RuntimeClient { return client })
	if code != 0 {
		t.Fatalf("bootstrap exit = %d, stderr=%s", code, stderr.String())
	}
	want := "{\"installation_id\":\"installation-1\",\"org_id\":\"org-1\",\"workspace_id\":\"workspace-1\",\"platform\":\"teams\",\"status\":\"pending\",\"binding_status\":\"unverified\"}\n"
	if client.heartbeatCalls != 1 || stdout.String() != want {
		t.Fatalf("unexpected startup report: calls=%d output=%q", client.heartbeatCalls, stdout.String())
	}
}

func TestRuntimeBootstrapRegistersCredentialSyncKey(t *testing.T) {
	client := &recordingRuntimeClient{identity: &RuntimeIdentity{ID: "installation-1", OrgID: "org-1", Platform: "teams", Status: "active"}}
	cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: "https://kei.example.test", RuntimeVersion: "test", CredentialStoreInstallationID: "store-1", CredentialSyncKeyID: "key-1", CredentialSyncPrivateKey: base64.RawStdEncoding.EncodeToString(make([]byte, 32))}
	var stdout, stderr bytes.Buffer
	if code := runRuntimeBootstrap(nil, &stdout, &stderr, cfg, func(string, time.Duration) RuntimeClient { return client }); code != 0 {
		t.Fatalf("bootstrap exit=%d stderr=%s", code, stderr.String())
	}
	if client.registerCalls != 1 {
		t.Fatalf("register calls=%d, want 1", client.registerCalls)
	}
}

func TestRuntimeBootstrapFailsWithoutRuntimeConfiguration(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runRuntimeBootstrap(nil, &stdout, &stderr, Config{}, func(string, time.Duration) RuntimeClient { return nil })
	if code != 1 || !bytes.Contains(stderr.Bytes(), []byte("KEI_RUNTIME_TOKEN")) {
		t.Fatalf("unexpected bootstrap failure: exit=%d stderr=%q", code, stderr.String())
	}
}

func TestMaintainRuntimeHeartbeatStopsOnContextCancellation(t *testing.T) {
	client := &recordingRuntimeClient{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- maintainRuntimeHeartbeat(ctx, client, "runtime-token", "test", time.Millisecond) }()
	deadline := time.After(time.Second)
	for {
		client.mu.Lock()
		calls := client.heartbeatCalls
		client.mu.Unlock()
		if calls > 0 {
			cancel()
			break
		}
		select {
		case <-deadline:
			t.Fatal("heartbeat loop did not report a heartbeat")
		case <-time.After(time.Millisecond):
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("heartbeat loop returned %v", err)
	}
}

func TestMaintainRuntimeHeartbeatFailsClosed(t *testing.T) {
	client := &recordingRuntimeClient{heartbeatErr: errors.New("control plane unavailable")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := maintainRuntimeHeartbeat(ctx, client, "runtime-token", "test", time.Millisecond); err == nil {
		t.Fatal("expected heartbeat loop to fail")
	}
}

// A legacy key minted before the workspace boundary has no workspace. The field
// is omitted rather than emitted empty, so a consumer can tell "this key has no
// workspace" from "the workspace is the empty string" and refuse rather than
// silently running unscoped.
func TestRuntimeBootstrapOmitsWorkspaceForLegacyKey(t *testing.T) {
	client := &recordingRuntimeClient{identity: &RuntimeIdentity{ID: "installation-1", OrgID: "org-1", Platform: "teams", Status: "pending", BindingStatus: "unverified"}}
	cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: "https://kei.example.test", RuntimeVersion: "test"}
	var stdout, stderr bytes.Buffer
	if code := runRuntimeBootstrap(nil, &stdout, &stderr, cfg, func(string, time.Duration) RuntimeClient { return client }); code != 0 {
		t.Fatalf("bootstrap exit = %d, stderr=%s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "workspace_id") {
		t.Fatalf("workspace_id should be omitted for a key without one: %q", stdout.String())
	}
}
