package connectorruntime

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingRuntimeClient struct {
	identity                      *RuntimeIdentity
	whoamiErr                     error
	heartbeatErr                  error
	heartbeatCalls, registerCalls int
	mu                            sync.Mutex
}

func (c *recordingRuntimeClient) WhoAmI(context.Context, string) (*RuntimeIdentity, error) {
	return c.identity, c.whoamiErr
}
func (c *recordingRuntimeClient) Heartbeat(context.Context, string, HeartbeatReport) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.heartbeatCalls++
	return c.heartbeatErr
}
func (c *recordingRuntimeClient) RegisterCredentialSyncKey(context.Context, string, string, string, string) error {
	c.registerCalls++
	return nil
}
func (c *recordingRuntimeClient) StartIdentityClaim(context.Context, string, IdentityClaimStartRequest) (*IdentityClaimStartResponse, error) {
	return nil, nil
}
func (c *recordingRuntimeClient) SyncTools(context.Context, string, *ToolManifest) error { return nil }

func newNotReadyBundleServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/runtime/policy-bundles/current":
			if r.Header.Get("Accept") != "application/vnd.kei.policy-bundle.v1+json, application/vnd.kei.policy-bundle.v2+json" {
				http.Error(w, "bad accept", 400)
				return
			}
			http.Error(w, "not ready", http.StatusConflict)
		default:
			http.NotFound(w, r)
		}
	}))
}
func TestRuntimeBootstrapReportsIdentityAndLeavesColdWhenCatalogNotReady(t *testing.T) {
	workspace := "workspace-1"
	client := &recordingRuntimeClient{identity: &RuntimeIdentity{ID: "installation-1", OrgID: "org-1", WorkspaceID: &workspace, Platform: "teams", Status: "pending", BindingStatus: "unverified"}}
	catalog := newNotReadyBundleServer()
	defer catalog.Close()
	cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: catalog.URL, RuntimeStateDir: t.TempDir()}
	var stdout, stderr bytes.Buffer
	code := runRuntimeBootstrap(nil, &stdout, &stderr, cfg, func(string, time.Duration) RuntimeClient { return client })
	if code != 0 {
		t.Fatalf("bootstrap=%d stderr=%s", code, stderr.String())
	}
	want := "{\"installation_id\":\"installation-1\",\"org_id\":\"org-1\",\"workspace_id\":\"workspace-1\",\"platform\":\"teams\",\"status\":\"pending\",\"binding_status\":\"unverified\"}\n"
	if client.heartbeatCalls != 1 || stdout.String() != want {
		t.Fatalf("bootstrap output=%q heartbeat=%d", stdout.String(), client.heartbeatCalls)
	}
}
func TestRuntimeBootstrapRegistersCredentialSyncKey(t *testing.T) {
	workspace := "workspace-1"
	client := &recordingRuntimeClient{identity: &RuntimeIdentity{ID: "installation-1", OrgID: "org-1", WorkspaceID: &workspace, Platform: "teams", Status: "active"}}
	catalog := newNotReadyBundleServer()
	defer catalog.Close()
	cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: catalog.URL, RuntimeStateDir: t.TempDir(), CredentialStoreInstallationID: "store-1", CredentialSyncKeyID: "key-1", CredentialSyncPrivateKey: base64.RawStdEncoding.EncodeToString(make([]byte, 32))}
	var stdout, stderr bytes.Buffer
	if code := runRuntimeBootstrap(nil, &stdout, &stderr, cfg, func(string, time.Duration) RuntimeClient { return client }); code != 0 {
		t.Fatalf("bootstrap=%d stderr=%s", code, stderr.String())
	}
	if client.registerCalls != 1 {
		t.Fatalf("register calls=%d", client.registerCalls)
	}
}
func TestRuntimeBootstrapFailsWithoutRuntimeConfiguration(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runRuntimeBootstrap(nil, &stdout, &stderr, Config{}, func(string, time.Duration) RuntimeClient { return nil })
	if code != 1 || !bytes.Contains(stderr.Bytes(), []byte("KEI_RUNTIME_TOKEN")) {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
}
func TestRuntimeBootstrapRejectsMissingWorkspaceAudience(t *testing.T) {
	client := &recordingRuntimeClient{identity: &RuntimeIdentity{ID: "installation-1", OrgID: "org-1", Platform: "teams", Status: "pending"}}
	catalog := newNotReadyBundleServer()
	defer catalog.Close()
	cfg := Config{RuntimeToken: "kh_live_runtime_test_token_1234567890", RuntimeControlPlaneURL: catalog.URL, RuntimeStateDir: t.TempDir()}
	var stdout, stderr bytes.Buffer
	if code := runRuntimeBootstrap(nil, &stdout, &stderr, cfg, func(string, time.Duration) RuntimeClient { return client }); code != 1 || !strings.Contains(stderr.String(), "workspace audience") {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
}
