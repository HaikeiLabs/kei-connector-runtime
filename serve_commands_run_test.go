package connectorruntime

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
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
// credentialCanary (newInvokeRig).

var credentialCanaryDigest = sha256Hex(credentialCanary)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

const githubTokenRef = "kei://connectors/" + invokeConnector + "/token"

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

type runStream struct {
	stdout, stderr string
	done           map[string]any
	raw            string
}

// postRun calls POST /v1/commands:run directly and collects its frames.
func postRun(t *testing.T, rig *invokeRig, argv, env []string) runStream {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"schema": "kei.command-run-request/v1", "argv": argv, "env": env, "dir": t.TempDir()})
	resp := socketDo(t, rig.client, http.MethodPost, "/v1/commands:run", string(body))
	if resp.code != http.StatusOK {
		t.Fatalf("POST /v1/commands:run = %s", resp.dump)
	}
	out := runStream{raw: resp.dump}
	scanner := bufio.NewScanner(strings.NewReader(resp.dump[strings.Index(resp.dump, "{"):]))
	for scanner.Scan() {
		var frame struct {
			Stream string         `json:"stream"`
			Data   []byte         `json:"data"`
			Done   map[string]any `json:"done"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &frame); err != nil {
			t.Fatalf("frame %q: %v", scanner.Text(), err)
		}
		switch {
		case frame.Done != nil:
			out.done = frame.Done
		case frame.Stream == "stdout":
			out.stdout += string(frame.Data)
		case frame.Stream == "stderr":
			out.stderr += string(frame.Data)
		}
	}
	if out.done == nil {
		t.Fatalf("no done frame: %s", resp.dump)
	}
	return out
}

func TestCommandRunInjectsSessionCredentialIntoChildOnly(t *testing.T) {
	var logs bytes.Buffer
	prevLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prevLog) })

	rig := newInvokeRig(t)
	rig.startSession(t)
	code, stdout, stderr := runProxyRunCLI(t, rig.socket,
		map[string]string{"GH_TOKEN": githubTokenRef, "KEI_RUN_HELPER_EXIT": "7"},
		"--", helperBinary(t))

	if code != 7 {
		t.Fatalf("exit = %d, want the child's 7\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "token-sha256="+credentialCanaryDigest) {
		t.Fatalf("child did not receive the session credential:\n%s", stdout)
	}
	if !strings.Contains(stdout, "raw=[REDACTED]") || !strings.Contains(stderr, "err-raw=[REDACTED]") {
		t.Fatalf("child output not redacted:\nstdout %s\nstderr %s", stdout, stderr)
	}
	spool := readSpool(t, rig.cfg.AuditPath)
	if !strings.Contains(spool, `"schema":"kei.proxy-run-event/v1"`) || !strings.Contains(spool, `"exit_code":7`) {
		t.Fatalf("audit spool lacks the run event: %s", spool)
	}
	if i11, _ := rig.counts(); len(i11) != 1 {
		t.Fatalf("I11 calls = %v, want only the session start", i11)
	}
	for name, content := range map[string]string{"stdout": stdout, "stderr": stderr, "log": logs.String(), "audit spool": spool} {
		for _, canary := range []string{credentialCanary, subjectCanary} {
			if strings.Contains(content, canary) {
				t.Errorf("%s leaked %s:\n%s", name, canary, content)
			}
		}
	}

	// Exit code 0 propagates too.
	if code, _, stderr := runProxyRunCLI(t, rig.socket, map[string]string{"GH_TOKEN": githubTokenRef, "KEI_RUN_HELPER_EXIT": "0"}, "--", helperBinary(t)); code != 0 {
		t.Fatalf("exit = %d, want 0: %s", code, stderr)
	}
}

func TestCommandRunChildEnvironmentIsCallerEnvPlusRefs(t *testing.T) {
	rig := newInvokeRig(t)
	rig.startSession(t)
	// The daemon process has its own environment (KEI_RUNTIME_STATE_DIR,
	// HOME, ...); none of it may reach the child.
	got := postRun(t, rig, []string{helperBinary(t)}, []string{"KEI_RUN_HELPER=1", "KEI_RUN_HELPER_EXIT=3", "GH_TOKEN=" + githubTokenRef, "PATH=/usr/bin:/bin"})
	if !strings.Contains(got.stdout, "env-keys=GH_TOKEN,KEI_RUN_HELPER,KEI_RUN_HELPER_EXIT,PATH\n") {
		t.Fatalf("child environment:\n%s", got.stdout)
	}
	if !strings.Contains(got.stdout, "token-sha256="+credentialCanaryDigest) {
		t.Fatalf("child did not receive the credential:\n%s", got.stdout)
	}
	if got.done["decision"] != "allow" || got.done["exit_code"] != float64(3) {
		t.Fatalf("done = %v", got.done)
	}
	if strings.Contains(got.raw, credentialCanary) || strings.Contains(got.raw, subjectCanary) {
		t.Fatalf("socket response leaked a credential:\n%s", got.raw)
	}
}

func TestCommandRunDenyPaths(t *testing.T) {
	rig := newInvokeRig(t)
	helper := helperBinary(t)

	t.Run("no session", func(t *testing.T) {
		code, stdout, stderr := runProxyRunCLI(t, rig.socket, map[string]string{"GH_TOKEN": githubTokenRef}, "--", helper)
		if code != 1 || stdout != "" || !strings.Contains(stderr, "no active kei-proxy session") {
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
		{"policy deny", map[string]string{"GH_TOKEN": "kei://connectors/" + invokeConnector + "/access_token"}, []string{"--", helper}, 1, "no_matching_policy"},
		{"unregistered connector", map[string]string{"GH_TOKEN": "kei://connectors/conn-unknown-0001/token"}, []string{"--", helper}, 1, "tool_not_registered"},
		{"provider not connected", map[string]string{"GH_TOKEN": "kei://connectors/conn-linear-0001/token"}, []string{"--", helper}, 1, "connector_not_connected"},
		{"opaque_ref provider", map[string]string{"GH_TOKEN": "kei://connectors/conn-notion-0001/token"}, []string{"--", helper}, 1, "credential_source_not_supported"},
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
	t.Run("command not found", func(t *testing.T) {
		code, _, stderr := runProxyRunCLI(t, rig.socket, map[string]string{"GH_TOKEN": githubTokenRef}, "--", "kei-no-such-command-l3c")
		if code != 127 || !strings.Contains(stderr, "command_not_started") {
			t.Fatalf("exit %d stderr %s", code, stderr)
		}
	})
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
	rig := newInvokeRig(t)
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
