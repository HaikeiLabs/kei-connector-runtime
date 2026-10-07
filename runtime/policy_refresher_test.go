package runtime_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

func TestStartPolicyRefresherNoopWhenNotRuntime(t *testing.T) {
	stop := keiruntime.StartPolicyRefresher(
		context.Background(),
		fakePolicyConfig{isRuntime: false},
		func() (*keiruntime.Identity, error) { t.Error("whoami called"); return nil, nil },
		func(*keiruntime.Identity) error { t.Error("sync called"); return nil },
		nil, nil, nil, nil,
	)
	stop() // must not block
}

func TestStartPolicyRefresherStopCancels(t *testing.T) {
	catalog := &fakePolicyCatalog{body: unsignedExampleBundle(t, time.Now().UTC())}
	server := httptest.NewServer(catalog)
	defer server.Close()
	dir := t.TempDir()
	cfg := policyTestConfig(server.URL, dir)

	whoami := func() (*keiruntime.Identity, error) {
		return &keiruntime.Identity{ID: "test-id", OrgID: "test-org", WorkspaceID: strPtr("test-ws")}, nil
	}
	syncFn := func(identity *keiruntime.Identity) error {
		return connectorruntime.SyncPolicyBundle(context.Background(), cfg, &connectorruntime.RuntimeIdentity{
			ID: identity.ID, OrgID: identity.OrgID, WorkspaceID: identity.WorkspaceID,
		}, 10*time.Second)
	}

	stop := keiruntime.StartPolicyRefresher(
		context.Background(), cfg, whoami, syncFn,
		connectorruntime.IsRuntimeRevocation,
		func() { connectorruntime.RevokePolicyState(cfg) },
		nil, nil,
	)

	// Stop should not block indefinitely.
	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not complete before timeout")
	}
}

// fakePolicyConfig is a PolicyConfig that satisfies the interface for testing.
type fakePolicyConfig struct {
	isRuntime    bool
	policyState  string
	token        string
	controlPlane string
}

func (f fakePolicyConfig) PolicyStateDir() string     { return f.policyState }
func (f fakePolicyConfig) Token() string              { return f.token }
func (f fakePolicyConfig) ControlPlaneURL() string    { return f.controlPlane }
func (f fakePolicyConfig) IsProduction() bool         { return false }
func (f fakePolicyConfig) Validate() error            { return nil }
func (f fakePolicyConfig) IsRuntime() bool            { return f.isRuntime }
func (f fakePolicyConfig) PolicyAuditPath() string    { return "" }
func (f fakePolicyConfig) PolicyAuditMaxBytes() int64 { return 0 }
