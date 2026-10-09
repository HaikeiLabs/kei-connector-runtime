package harnessresync

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseReportKeepsCountsOnly(t *testing.T) {
	report, err := ParseReport([]byte(secretReport))
	if err != nil {
		t.Fatal(err)
	}
	if !report.Drift || report.BundleExpired || len(report.Harnesses) != 2 {
		t.Fatalf("report = %+v", report)
	}
	claude := report.Harnesses[0]
	want := HarnessDrift{Kind: "claude_code", Drifted: true, Missing: 1, AlteredFiles: 1, Pending: 1, Stale: 0}
	if claude != want {
		t.Fatalf("claude = %+v, want %+v", claude, want)
	}
	if !claude.Rewritten() {
		t.Fatal("missing entries must count as a rewrite")
	}
	if report.Harnesses[1].Kind != "unknown" {
		t.Fatalf("non-kind string kept as kind: %q", report.Harnesses[1].Kind)
	}
	if report.DriftedCount() != 1 {
		t.Fatalf("drifted = %d", report.DriftedCount())
	}
}

func TestParseReportRejectsUnknownSchemaWithoutQuotingInput(t *testing.T) {
	for _, in := range []string{`{"schema":"other/v1","secret":"kei_rt_AbCdEf0123456789"}`, `kei_rt_AbCdEf0123456789 not json`} {
		_, err := ParseReport([]byte(in))
		if err == nil {
			t.Fatalf("ParseReport(%q) succeeded", in)
		}
		if strings.Contains(err.Error(), "kei_rt_") {
			t.Fatalf("error quotes input: %v", err)
		}
	}
}

func TestDesktopConfigPresent(t *testing.T) {
	home := t.TempDir()
	if DesktopConfigPresent(home, "") {
		t.Fatal("empty home reported a desktop config")
	}
	if DesktopConfigPresent("", "") {
		t.Fatal("unset HOME reported a desktop config")
	}
	for _, dir := range []string{".claude", ".codex", filepath.Join(".config", "opencode")} {
		home := t.TempDir()
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
		if !DesktopConfigPresent(home, "") {
			t.Fatalf("%s not detected", dir)
		}
	}
	xdg := t.TempDir()
	if err := os.Mkdir(filepath.Join(xdg, "opencode"), 0o700); err != nil {
		t.Fatal(err)
	}
	if !DesktopConfigPresent(t.TempDir(), xdg) {
		t.Fatal("XDG opencode dir not detected")
	}
}

func TestResolveKeiPrefersSiblingThenPath(t *testing.T) {
	binDir := t.TempDir()
	self := filepath.Join(binDir, "kei-proxy")
	executable := func() (string, error) { return self, nil }
	lookPath := func(string) (string, error) { return "/path/kei", nil }
	noPath := func(string) (string, error) { return "", errors.New("not found") }

	if got, err := ResolveKei(executable, lookPath); err != nil || got != "/path/kei" {
		t.Fatalf("no sibling: got %q, %v; want PATH kei", got, err)
	}
	if _, err := ResolveKei(executable, noPath); !errors.Is(err, ErrKeiNotFound) {
		t.Fatalf("no kei anywhere: err = %v", err)
	}
	sibling := filepath.Join(binDir, "kei")
	if err := os.WriteFile(sibling, []byte("not a real binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := ResolveKei(executable, lookPath); got != "/path/kei" {
		t.Fatalf("non-executable sibling used: %q", got)
	}
	if err := os.Chmod(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := ResolveKei(executable, noPath); err != nil || got != sibling {
		t.Fatalf("sibling: got %q, %v; want %q", got, err, sibling)
	}
}
