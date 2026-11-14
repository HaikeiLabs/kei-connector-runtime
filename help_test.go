package connectorruntime

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSubcommandHelp runs the built binary, since several subcommands write
// to os.Stdout and os.Stderr directly. Every subcommand must answer --help
// and -h with exit 0 and a usage line, and must not act: no control plane,
// token or stdin is available here.
func TestSubcommandHelp(t *testing.T) {
	if testing.Short() {
		t.Skip("builds kei-proxy")
	}
	binary := filepath.Join(t.TempDir(), "kei-proxy")
	buildKeiProxy(t, binary, "netgo")

	commands := []string{
		"serve", "runtime", "policy", "credential", "identity", "hook",
		"model", "run", "harness", "collector",
	}
	for _, command := range commands {
		for _, flag := range []string{"--help", "-h"} {
			t.Run(command+" "+flag, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, binary, command, flag)
				cmd.Env = []string{"HOME=" + t.TempDir(), "KEI_RUNTIME_STATE_DIR=" + t.TempDir()}
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				err := cmd.Run()
				output := stdout.String() + stderr.String()
				if err != nil {
					t.Fatalf("kei-proxy %s %s: %v\n%s", command, flag, err, output)
				}
				usageLine := "Usage: kei-proxy " + command
				if !strings.Contains(output, usageLine) {
					t.Fatalf("kei-proxy %s %s: output has no %q line:\n%s", command, flag, usageLine, output)
				}
			})
		}
	}
}

// TestAuthorizeHelpIsNotAPermit: exit 0 is the deprecated authorize command's
// permit contract, so its --help prints usage but exits 2 (error), never 0.
func TestAuthorizeHelpIsNotAPermit(t *testing.T) {
	if testing.Short() {
		t.Skip("builds kei-proxy")
	}
	binary := filepath.Join(t.TempDir(), "kei-proxy")
	buildKeiProxy(t, binary, "netgo")
	for _, flag := range []string{"--help", "-h"} {
		cmd := exec.Command(binary, "authorize", flag)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != authorizeExitError {
			t.Fatalf("authorize %s: err = %v, want exit %d", flag, err, authorizeExitError)
		}
		if stdout.Len() != 0 {
			t.Fatalf("authorize %s wrote to stdout (the decision stream): %q", flag, stdout.String())
		}
		if !strings.Contains(stderr.String(), "Usage: kei-proxy authorize") {
			t.Fatalf("authorize %s: stderr has no usage line:\n%s", flag, stderr.String())
		}
	}
}
