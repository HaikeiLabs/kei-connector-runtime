package harnessresync

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner stands in for the `kei` binary: no real binary, no real HOME.
type fakeRunner struct {
	mu       sync.Mutex
	reports  []Report
	checkErr error
	syncErr  error
	checks   int
	syncs    int
	checked  chan struct{}
}

func (f *fakeRunner) Check(context.Context) (Report, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks++
	if f.checked != nil {
		defer func() { f.checked <- struct{}{} }()
	}
	if f.checkErr != nil {
		return Report{}, f.checkErr
	}
	if len(f.reports) == 0 {
		return Report{Harnesses: []HarnessDrift{{Kind: "claude_code"}}}, nil
	}
	r := f.reports[0]
	if len(f.reports) > 1 {
		f.reports = f.reports[1:]
	}
	return r, nil
}

func (f *fakeRunner) Sync(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncs++
	return f.syncErr
}

func (f *fakeRunner) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checks, f.syncs
}

func rewritten(kind string) Report {
	return Report{Drift: true, Harnesses: []HarnessDrift{{Kind: kind, Drifted: true, Missing: 2}}}
}

func inSync() Report {
	return Report{Harnesses: []HarnessDrift{{Kind: "claude_code"}}}
}

func newTestResyncer(t *testing.T, runner Runner, desktop bool) (*Resyncer, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	r := New(runner, func() bool { return desktop }, 0, t.TempDir())
	r.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r.Now = func() time.Time { return time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC) }
	return r, &logs
}

func TestCycleDriftRunsSync(t *testing.T) {
	runner := &fakeRunner{reports: []Report{rewritten("claude_code")}}
	r, logs := newTestResyncer(t, runner, true)
	r.Cycle(context.Background())
	if checks, syncs := runner.counts(); checks != 1 || syncs != 1 {
		t.Fatalf("checks=%d syncs=%d, want 1 and 1", checks, syncs)
	}
	if !strings.Contains(logs.String(), "msg=harness_resync ") || !strings.Contains(logs.String(), "drifted=1") || !strings.Contains(logs.String(), "synced=true") {
		t.Fatalf("log = %q, want one harness_resync line with counts", logs.String())
	}
	if n := strings.Count(strings.TrimSpace(logs.String()), "\n"); n != 0 {
		t.Fatalf("log has %d extra lines: %q", n, logs.String())
	}
	status, err := LoadStatus(r.StateDir)
	if err != nil || status == nil {
		t.Fatalf("LoadStatus = %v, %v", status, err)
	}
	if status.State != StateActive || status.LastDrifted != 1 || status.LastSync.IsZero() {
		t.Fatalf("status = %+v", status)
	}
}

func TestCycleNoDriftSkipsSync(t *testing.T) {
	runner := &fakeRunner{reports: []Report{inSync()}}
	r, logs := newTestResyncer(t, runner, true)
	r.Cycle(context.Background())
	if checks, syncs := runner.counts(); checks != 1 || syncs != 0 {
		t.Fatalf("checks=%d syncs=%d, want 1 and 0", checks, syncs)
	}
	if logs.Len() != 0 {
		t.Fatalf("in-sync cycle logged %q", logs.String())
	}
}

func TestCycleSkippedWithoutDesktopConfig(t *testing.T) {
	runner := &fakeRunner{reports: []Report{rewritten("claude_code")}}
	r, logs := newTestResyncer(t, runner, false)
	r.Cycle(context.Background())
	if checks, syncs := runner.counts(); checks != 0 || syncs != 0 {
		t.Fatalf("checks=%d syncs=%d on a server install, want none", checks, syncs)
	}
	if status, _ := LoadStatus(r.StateDir); status != nil {
		t.Fatalf("server install wrote resync state %+v", status)
	}
	if logs.Len() != 0 {
		t.Fatalf("server install logged %q", logs.String())
	}
}

func TestCycleFailuresAreLoggedAndIgnored(t *testing.T) {
	runner := &fakeRunner{checkErr: errors.New("kei harness sync --check exited 2")}
	r, logs := newTestResyncer(t, runner, true)
	r.Cycle(context.Background())
	if !strings.Contains(logs.String(), "harness_resync_failed") || !strings.Contains(logs.String(), "step=check") {
		t.Fatalf("log = %q", logs.String())
	}
	runner = &fakeRunner{reports: []Report{rewritten("codex")}, syncErr: errors.New("kei harness sync exited 1")}
	r, logs = newTestResyncer(t, runner, true)
	r.Cycle(context.Background())
	if !strings.Contains(logs.String(), "step=sync") {
		t.Fatalf("log = %q", logs.String())
	}
	status, _ := LoadStatus(r.StateDir)
	if status == nil || status.LastError != "sync_failed" {
		t.Fatalf("status = %+v", status)
	}
}

func TestBackoffDoublesOnRepeatedRewriteAndResets(t *testing.T) {
	runner := &fakeRunner{}
	r, _ := newTestResyncer(t, runner, true)
	step := func(report Report) {
		runner.mu.Lock()
		runner.reports = []Report{report}
		runner.mu.Unlock()
		r.Cycle(context.Background())
	}

	step(rewritten("claude_code")) // first rewrite: no backoff yet
	if got := r.Interval(); got != DefaultInterval {
		t.Fatalf("after first rewrite interval = %v", got)
	}
	step(inSync())
	step(rewritten("claude_code")) // again within 3 cycles: double
	if got := r.Interval(); got != 2*DefaultInterval {
		t.Fatalf("after repeat interval = %v, want %v", got, 2*DefaultInterval)
	}
	status, _ := LoadStatus(r.StateDir)
	if status == nil || status.State != "harness resync backoff" || len(status.BackoffKinds) != 1 || status.BackoffKinds[0] != "claude_code" {
		t.Fatalf("status = %+v, want harness resync backoff for claude_code", status)
	}
	for range 10 {
		step(rewritten("claude_code"))
	}
	if got := r.Interval(); got != MaxInterval {
		t.Fatalf("interval = %v, want capped at %v", got, MaxInterval)
	}

	// A bundle change (pending entries only) is not a rewrite.
	step(Report{Drift: true, Harnesses: []HarnessDrift{{Kind: "claude_code", Drifted: true, Pending: 3}}})
	step(inSync())
	step(inSync())
	if got := r.Interval(); got != DefaultInterval {
		t.Fatalf("after 3 clean cycles interval = %v, want reset to %v", got, DefaultInterval)
	}
	status, _ = LoadStatus(r.StateDir)
	if status.State != StateActive || len(status.BackoffKinds) != 0 {
		t.Fatalf("status = %+v, want active", status)
	}
}

func TestBackoffIgnoresRewriteOutsideWindow(t *testing.T) {
	runner := &fakeRunner{}
	r, _ := newTestResyncer(t, runner, true)
	for _, report := range []Report{rewritten("codex"), inSync(), inSync(), inSync(), rewritten("codex")} {
		runner.mu.Lock()
		runner.reports = []Report{report}
		runner.mu.Unlock()
		r.Cycle(context.Background())
	}
	if got := r.Interval(); got != DefaultInterval {
		t.Fatalf("interval = %v, want %v for a rewrite 4 cycles later", got, DefaultInterval)
	}
}

func TestRunChecksOnBundleChangeOnlyAndOnTimer(t *testing.T) {
	runner := &fakeRunner{checked: make(chan struct{}, 8)}
	r, _ := newTestResyncer(t, runner, true)
	tick := make(chan time.Time)
	var mu sync.Mutex
	var intervals []time.Duration
	r.After = func(d time.Duration) <-chan time.Time {
		mu.Lock()
		intervals = append(intervals, d)
		mu.Unlock()
		return tick
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()

	wait := func(what string) {
		t.Helper()
		select {
		case <-runner.checked:
		case <-time.After(5 * time.Second):
			t.Fatalf("no check after %s", what)
		}
	}
	r.BundleRefreshed("b/1/sha256:a")
	wait("first refresh")
	r.BundleRefreshed("b/1/sha256:a") // same bundle: no check
	tick <- time.Now()
	wait("timer tick")
	r.BundleRefreshed("b/2/sha256:b")
	wait("bundle change")
	cancel()
	<-done
	if checks, _ := runner.counts(); checks != 3 {
		t.Fatalf("checks = %d, want 3", checks)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, d := range intervals {
		if d != DefaultInterval {
			t.Fatalf("timer interval = %v, want %v", d, DefaultInterval)
		}
	}
}

func TestBundleRefreshedNeverBlocks(t *testing.T) {
	r, _ := newTestResyncer(t, &fakeRunner{}, true)
	done := make(chan struct{})
	go func() {
		for i := range 100 {
			r.BundleRefreshed(string(rune('a' + i%26)))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("BundleRefreshed blocked with no Run loop")
	}
}

// tokenShaped matches runtime tokens, bearer tokens, JWTs and long
// base64/hex secrets.
var tokenShaped = regexp.MustCompile(`kei_[a-z]{2,4}_[A-Za-z0-9]{8,}|(?i)bearer\s+\S+|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|[A-Za-z0-9+/_-]{32,}`)

const secretReport = `{
  "schema": "kei.harness-drift/v1",
  "drift": true,
  "bundle": {"version": 7, "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "expired": false},
  "harnesses": [
    {"kind": "claude_code", "status": "drift", "synced_bundle_version": 6,
     "missing": [{"file": "/home/u/.claude/settings.json", "effect": "allow", "entry": "Bash(curl -H 'Authorization: Bearer kei_rt_AbCdEf0123456789XyZ' *)"}],
     "altered_files": ["/home/u/.claude/settings.json"],
     "pending": [{"file": "/home/u/.claude/settings.json", "effect": "allow", "entry": "Bash(export GH_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789)"}],
     "stale": []},
    {"kind": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0", "status": "in_sync", "missing": [], "altered_files": [], "pending": [], "stale": []}
  ]
}`

func TestOutputNeverContainsTokenShapedStrings(t *testing.T) {
	report, err := ParseReport([]byte(secretReport))
	if err != nil {
		t.Fatal(err)
	}
	if !tokenShaped.MatchString(secretReport) {
		t.Fatal("fixture must contain token-shaped strings")
	}
	runner := &fakeRunner{reports: []Report{report}}
	r, logs := newTestResyncer(t, runner, true)
	for range 3 {
		r.Cycle(context.Background())
	}
	state, err := os.ReadFile(filepath.Join(r.StateDir, StateFile))
	if err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"log": logs.String(), "state": string(state)} {
		if m := tokenShaped.FindString(out); m != "" {
			t.Fatalf("%s contains token-shaped %q: %s", name, m, out)
		}
		for _, leak := range []string{"settings.json", "Bash(", "GH_TOKEN", "Authorization"} {
			if strings.Contains(out, leak) {
				t.Fatalf("%s leaks report content %q: %s", name, leak, out)
			}
		}
	}
	if !strings.Contains(logs.String(), "drifted=1") {
		t.Fatalf("log = %q, want counts", logs.String())
	}
}

func TestStatusFileMode(t *testing.T) {
	dir := t.TempDir()
	if err := SaveStatus(dir, Status{State: StateActive}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, StateFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", info.Mode().Perm())
	}
	if s, err := LoadStatus(t.TempDir()); s != nil || err != nil {
		t.Fatalf("missing state = %v, %v; want nil, nil", s, err)
	}
}
