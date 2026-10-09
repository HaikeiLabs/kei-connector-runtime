package runtime_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/harnessresync"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

type countingRunner struct{ checked chan struct{} }

func (c countingRunner) Check(context.Context) (harnessresync.Report, error) {
	c.checked <- struct{}{}
	return harnessresync.Report{}, nil
}

func (countingRunner) Sync(context.Context) error { return nil }

func TestPolicyRefresherRunsHarnessResyncAfterRefresh(t *testing.T) {
	catalog := &fakePolicyCatalog{body: unsignedExampleBundle(t, time.Now().UTC())}
	server := httptest.NewServer(catalog)
	defer server.Close()
	cfg := policyTestConfig(server.URL, t.TempDir())
	whoami := func() (*keiruntime.Identity, error) {
		id := policyTestIdentity
		return &keiruntime.Identity{ID: id.ID, OrgID: id.OrgID, WorkspaceID: id.WorkspaceID}, nil
	}
	syncFn := func(identity *keiruntime.Identity) error {
		return connectorruntime.SyncPolicyBundle(context.Background(), cfg, &connectorruntime.RuntimeIdentity{
			ID: identity.ID, OrgID: identity.OrgID, WorkspaceID: identity.WorkspaceID,
		}, 10*time.Second)
	}
	runner := countingRunner{checked: make(chan struct{}, 4)}
	resync := harnessresync.New(runner, func() bool { return true }, time.Hour, cfg.PolicyStateDir())
	resync.After = func(time.Duration) <-chan time.Time { return nil }

	stop := keiruntime.StartPolicyRefresher(context.Background(), cfg, whoami, syncFn,
		connectorruntime.IsRuntimeRevocation, func() { connectorruntime.RevokePolicyState(cfg) }, nil, nil,
		keiruntime.WithHarnessResync(resync))
	select {
	case <-runner.checked:
	case <-time.After(5 * time.Second):
		t.Fatal("no harness drift check after the first bundle refresh")
	}
	stop()

	var stdout, stderr bytes.Buffer
	if code := keiruntime.RunPolicyShow(nil, &stdout, &stderr, cfg); code != 0 {
		t.Fatalf("policy show exit=%d %s", code, stderr.String())
	}
	var show struct {
		State         string `json:"state"`
		HarnessResync *struct {
			State           string `json:"state"`
			IntervalSeconds int    `json:"interval_seconds"`
		} `json:"harness_resync"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &show); err != nil {
		t.Fatal(err)
	}
	if show.State == "" || show.HarnessResync == nil || show.HarnessResync.State != harnessresync.StateActive || show.HarnessResync.IntervalSeconds != 3600 {
		t.Fatalf("policy show = %s", stdout.String())
	}
}

func TestNewHarnessResyncDisabled(t *testing.T) {
	for _, v := range []string{"off", "0", "soon", "-5m"} {
		env := map[string]string{keiruntime.HarnessResyncIntervalEnv: v}
		if r := keiruntime.NewHarnessResync(fakePolicyConfig{}, func(k string) string { return env[k] }); r != nil {
			t.Fatalf("%s=%q returned a resyncer", keiruntime.HarnessResyncIntervalEnv, v)
		}
	}
}
