package harnessresync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Runner runs the `kei` harness commands. Tests inject a fake.
type Runner interface {
	// Check runs `kei harness sync --check --json`.
	Check(ctx context.Context) (Report, error)
	// Sync runs `kei harness sync`.
	Sync(ctx context.Context) error
}

// ErrKeiNotFound means no `kei` binary sits next to kei-proxy or on PATH.
var ErrKeiNotFound = errors.New("kei binary not found")

const (
	checkTimeout   = time.Minute
	syncTimeout    = 2 * time.Minute
	maxReportBytes = 1 << 20
)

// ExecRunner runs the `kei` binary at Path. Its output is never logged: the
// check's stdout is decoded to counts, sync's stdout and both stderrs are
// discarded.
type ExecRunner struct {
	Path string
}

// ResolveKei finds `kei` next to the running kei-proxy, then on PATH.
func ResolveKei(executable func() (string, error), lookPath func(string) (string, error)) (string, error) {
	if self, err := executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(self), "kei")
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return candidate, nil
		}
	}
	if path, err := lookPath("kei"); err == nil {
		return path, nil
	}
	return "", ErrKeiNotFound
}

// Check runs `kei harness sync --check --json`. Exit 0 is in sync, exit 1 is
// drift (or a bundle change); anything else is an error.
func (r ExecRunner) Check(ctx context.Context) (Report, error) {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, r.Path, "harness", "sync", "--check", "--json")
	cmd.Stdout = &limitedWriter{w: &stdout, n: maxReportBytes}
	cmd.Stderr = io.Discard
	code, err := exitCode(cmd.Run())
	if err != nil {
		return Report{}, err
	}
	if code != 0 && code != 1 {
		return Report{}, fmt.Errorf("kei harness sync --check exited %d", code)
	}
	report, err := ParseReport(stdout.Bytes())
	if err != nil {
		return Report{}, err
	}
	if code == 1 {
		report.Drift = true
	}
	return report, nil
}

// Sync runs `kei harness sync`.
func (r ExecRunner) Sync(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.Path, "harness", "sync")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	code, err := exitCode(cmd.Run())
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("kei harness sync exited %d", code)
	}
	return nil
}

// exitCode turns a Run error into an exit code, or an error that names no
// output when the process did not run to completion.
func exitCode(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.Exited() {
		return exitErr.ExitCode(), nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return 0, err
	}
	return 0, errors.New("kei did not run to completion")
}

// limitedWriter keeps the first n bytes and drops the rest.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		keep := p
		if len(keep) > l.n {
			keep = keep[:l.n]
		}
		written, err := l.w.Write(keep)
		l.n -= written
		if err != nil {
			return written, err
		}
	}
	return len(p), nil
}
