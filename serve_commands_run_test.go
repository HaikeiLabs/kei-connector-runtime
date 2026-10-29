package connectorruntime

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// HAI-346 L3c: POST /v1/commands:run on the serve daemon, and `kei-proxy run`
// as its thin client. The child is this test binary re-executed with
// KEI_RUN_HELPER=1 (see runHelperChild): it reports the SHA-256 of $GH_TOKEN
// and its environment's keys, echoes the raw token on stdout and stderr, and
// exits with $KEI_RUN_HELPER_EXIT. The session's GitHub token is
// credentialCanary (newSocketRig).

const githubTokenRef = "kei://connectors/" + githubConnectorID + "/token"

func helperBinary(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// runProxyRunCLI runs `kei-proxy run` through the root command's wiring with
// KEI_CREDENTIAL_RELEASE=identity and the given extra environment.
func runProxyRunCLI(t *testing.T, socketPath string, env map[string]string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Setenv("KEI_RUNTIME_TOKEN", credTestToken)
	t.Setenv("KEI_RUNTIME_CONTROL_PLANE_URL", "https://kei.example")
	t.Setenv("KEI_CREDENTIAL_RELEASE", "identity")
	t.Setenv("KEI_RUNTIME_SOCKET_PATH", socketPath)
	t.Setenv("KEI_RUN_HELPER", "1")
	for k, v := range env {
		t.Setenv(k, v)
	}
	stdout, stderr = captureFDs(t, func() {
		code = runProxyRun(args)
	})
	// The CLI's own environment must not make *this* process a helper.
	return code, stdout, stderr
}

// A v2 bundle decides connector credential references only through preflight,
// so the daemon denies every kei://connectors reference fail closed and the
// child never runs. The credential-injection mechanics are unit-tested in
// internal/run with an allowing grant.
func TestCommandRunDenyPaths(t *testing.T) {
	rig := newSocketRig(t)
	helper := helperBinary(t)

	t.Run("no session", func(t *testing.T) {
		code, stdout, stderr := runProxyRunCLI(t, rig.socket, map[string]string{"GH_TOKEN": githubTokenRef}, "--", helper)
		if code != 1 || stdout != "" || !strings.Contains(stderr, "session_not_found") {
			t.Fatalf("exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
	})

	rig.startSession(t)
	for _, tc := range []struct {
		name   string
		env    map[string]string
		args   []string
		code   int
		reason string
	}{
		{"no reference", map[string]string{"GH_TOKEN": ""}, []string{"--", helper}, 2, "credential_reference_missing"},
		{"connector mismatch", map[string]string{"GH_TOKEN": githubTokenRef}, []string{"--connector", "conn-other", "--", helper}, 1, "credential_reference_mismatch"},
		{"github reference", map[string]string{"GH_TOKEN": githubTokenRef}, []string{"--", helper}, 1, "preflight_required"},
		{"unknown connector", map[string]string{"GH_TOKEN": "kei://connectors/conn-unknown-0001/token"}, []string{"--", helper}, 1, "preflight_required"},
		{"linear reference", map[string]string{"GH_TOKEN": "kei://connectors/conn-linear-0001/token"}, []string{"--", helper}, 1, "preflight_required"},
		{"notion reference", map[string]string{"GH_TOKEN": "kei://connectors/conn-notion-0001/token"}, []string{"--", helper}, 1, "preflight_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runProxyRunCLI(t, rig.socket, tc.env, tc.args...)
			if code != tc.code || !strings.Contains(stderr, tc.reason) {
				t.Fatalf("exit %d (want %d)\nstderr %s", code, tc.code, stderr)
			}
			if strings.Contains(stdout, "token-sha256") {
				t.Fatalf("child ran on a deny:\n%s", stdout)
			}
		})
	}
	t.Run("no daemon", func(t *testing.T) {
		missing := filepath.Join(shortSocketTempDir(t), "absent.sock")
		code, stdout, stderr := runProxyRunCLI(t, missing, map[string]string{"GH_TOKEN": githubTokenRef}, "--", helper)
		if code != 1 || stdout != "" || !strings.Contains(stderr, "not reachable") {
			t.Fatalf("exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
	})
	t.Run("bad mode fails closed", func(t *testing.T) {
		code, stdout, stderr := runProxyRunCLI(t, rig.socket, map[string]string{"GH_TOKEN": githubTokenRef, "KEI_CREDENTIAL_RELEASE": "option-c"}, "--", helper)
		if code != 1 || stdout != "" || !strings.Contains(stderr, "KEI_CREDENTIAL_RELEASE") {
			t.Fatalf("exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
	})
	if i11, _ := rig.counts(); len(i11) != 1 {
		t.Fatalf("I11 calls = %v, want only the session start", i11)
	}
}

func TestCommandRunRequiresRuntimeTokenAndIdentityMode(t *testing.T) {
	rig := newSocketRig(t)
	req, _ := http.NewRequest(http.MethodPost, "http://unix/v1/commands:run", strings.NewReader(`{}`))
	resp, err := rig.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated run = %d, want 401", resp.StatusCode)
	}

	cfg := rig.cfg
	cfg.CredentialRelease = CredentialReleaseLegacy
	local, err := newServeLocalPDP(cfg, serveSeams{})
	if err != nil {
		t.Fatal(err)
	}
	_, h := newServeHandlers(cfg, local)
	_, legacySocket := serveSocketForTest(t, h)
	code, _, stderr := runProxyRunCLI(t, legacySocket, map[string]string{"GH_TOKEN": githubTokenRef}, "--", helperBinary(t))
	if code != 1 || !strings.Contains(stderr, "does not run commands") {
		t.Fatalf("legacy daemon: exit %d stderr %s", code, stderr)
	}
}
