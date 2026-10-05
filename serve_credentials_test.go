package connectorruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/credrelease"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/socket"
)

const (
	credentialCanary = "kei-canary-credential-5d1c0a9e"
	subjectCanary    = "kei-canary-subject-token-b62f4e70"
	credTestToken    = "kh_live_12345678901234567890"
)

type canaryKeychain struct{ token string }

func (k *canaryKeychain) Token() (string, error)                             { return k.token, nil }
func (k *canaryKeychain) Verify(_ context.Context, _ string) (string, error) { return "u-canary", nil }

// canaryI11 serves connectorCredentials:resolve with the canary credential, or
// a 503 whose body carries the canary when the subject token asks for one.
func canaryI11(t *testing.T, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != credrelease.ResolvePath {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		if r.Header.Get("X-Kei-Subject-Token") != subjectCanary {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":{"message":"`+credentialCanary+`"}}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"credentials": []map[string]string{{"provider": "github", "access_token": credentialCanary, "token_type": "Bearer"}},
			"failures":    []map[string]string{{"provider": "linear", "reason": "NOT_CONNECTED"}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// serveSocketForTest serves the daemon's socket handler on a real Unix socket
// and returns a client for it.
func serveSocketForTest(t *testing.T, h http.Handler) *http.Client {
	t.Helper()
	path := filepath.Join(shortSocketTempDir(t), "runtime.sock")
	l, err := socket.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

type socketResponse struct {
	route string
	code  int
	dump  string // status, headers and body
}

func socketDo(t *testing.T, c *http.Client, method, path, body string) socketResponse {
	t.Helper()
	req, err := http.NewRequest(method, "http://unix"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+credTestToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var dump bytes.Buffer
	_ = resp.Header.Write(&dump)
	return socketResponse{route: method + " " + path, code: resp.StatusCode, dump: fmt.Sprintf("%d\n%s\n%s", resp.StatusCode, dump.String(), b)}
}

// socketRouteMatrix is every route the daemon serves plus the credential
// routes rejected under option C and the later L3b/L3c routes.
var socketRouteMatrix = []struct{ method, path, body string }{
	{http.MethodGet, "/v1/session", ""},
	{http.MethodPost, "/v1/session", `{}`},
	{http.MethodPatch, "/v1/session", `{}`},
	{http.MethodPost, "/v1/authorize", `{"schema":"kei.authorize-request/v1","tool":"web_search"}`},
	{http.MethodPost, "/v1/authorize", `{"schema":"kei.authorize-request/v1","connector":{"connector_id":"github","capability":"read"}}`},
	{http.MethodGet, "/v1/session/credential", ""},
	{http.MethodPost, "/v1/session/credential", `{"provider":"github"}`},
	{http.MethodGet, "/v1/session/credentials", ""},
	{http.MethodGet, "/v1/credentials", ""},
	{http.MethodGet, "/v1/credentials/github", ""},
	{http.MethodPost, "/v1/connectors:invoke", `{"tool":"github"}`},
	{http.MethodPost, "/v1/commands:run", `{"argv":["gh"]}`},
	{http.MethodGet, "/healthz", ""},
	{http.MethodGet, "/readyz", ""},
	{http.MethodGet, "/v1/models", ""},
	{http.MethodPost, "/v1/chat/completions", `{"model":"x"}`},
	{http.MethodGet, "/", ""},
	{http.MethodGet, "/debug/vars", ""},
	{http.MethodGet, "/debug/pprof/", ""},
}

// identityServeConfig is a serve config with KEI_CREDENTIAL_RELEASE=identity
// pointing I11 at baseURL.
func identityServeConfig(t *testing.T, baseURL string) Config {
	t.Helper()
	return Config{
		RuntimeToken:           credTestToken,
		RuntimeControlPlaneURL: baseURL,
		RuntimeStateDir:        t.TempDir(),
		AuditPath:              filepath.Join(t.TempDir(), "audit.jsonl"),
		CredentialRelease:      CredentialReleaseIdentity,
	}
}

// TestServeSessionCredentialsNeverLeak runs a linked session through the
// daemon's real socket wiring and checks that neither credential canary
// appears on stdout, stderr, the log, the audit spool, any error string, or
// any socket response (GET /v1/session included).
func TestServeSessionCredentialsNeverLeak(t *testing.T) {
	var calls atomic.Int32
	i11 := canaryI11(t, &calls)
	cfg := identityServeConfig(t, i11.URL)

	var logs bytes.Buffer
	prevLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prevLog) })

	var responses []socketResponse
	var errs []string
	keychain := &canaryKeychain{token: subjectCanary}
	stdout, stderr := captureFDs(t, func() {
		func() {
			local, err := newServeLocalPDP(cfg)
			if err != nil {
				t.Fatal(err)
			}
			local.SetKeychain(keychain)
			_, socketHandler := newServeHandlers(cfg, local)
			c := serveSocketForTest(t, socketHandler)

			put := socketDo(t, c, http.MethodPut, "/v1/session", `{"schema":"kei.session/v1","source":"cli"}`)
			if put.code != http.StatusNoContent {
				t.Fatalf("PUT /v1/session = %s", put.dump)
			}
			responses = append(responses, put)
			get := socketDo(t, c, http.MethodGet, "/v1/session", "")
			if get.code != http.StatusOK {
				t.Fatalf("GET /v1/session = %s", get.dump)
			}
			responses = append(responses, get)

			// The credential is held: in-daemon use sees it.
			held := false
			if err := local.UseCredential(context.Background(), "github", func(token string) error {
				held = token == credentialCanary
				return nil
			}); err != nil || !held {
				t.Fatalf("credential not held in the daemon: %v", err)
			}
			// Callback failures and denials, including the 401 path.
			for _, provider := range []string{"github", "linear", "slack"} {
				err := local.UseCredential(context.Background(), provider, func(token string) error {
					return fmt.Errorf("provider said 401: %w", credrelease.ErrProviderUnauthorized)
				})
				if err == nil {
					t.Fatalf("%s: expected a denial", provider)
				}
				errs = append(errs, err.Error(), fmt.Sprintf("%+v %#v", err, err))
			}

			for _, r := range socketRouteMatrix {
				responses = append(responses, socketDo(t, c, r.method, r.path, r.body))
			}

			// A failed load logs only its error class.
			keychain.token = "subject-without-credentials"
			responses = append(responses, socketDo(t, c, http.MethodPut, "/v1/session", `{"schema":"kei.session/v1","source":"cli"}`))
			responses = append(responses, socketDo(t, c, http.MethodDelete, "/v1/session", ""))
			local.Close()
		}()
	})

	spool := readSpool(t, cfg.AuditPath)
	if !strings.Contains(spool, "u-canary") {
		t.Fatalf("audit spool has no session decision to check: %q", spool)
	}
	if calls.Load() != 3 {
		// start, the github 401 re-fetch, and the failed second session
		t.Fatalf("I11 calls = %d, want 3", calls.Load())
	}
	sinks := map[string]string{"stdout": stdout, "stderr": stderr, "log": logs.String(), "audit spool": spool, "errors": strings.Join(errs, "\n")}
	for _, r := range responses {
		sinks["socket "+r.route] += r.dump
	}
	for name, content := range sinks {
		for _, canary := range []string{credentialCanary, subjectCanary} {
			if strings.Contains(content, canary) {
				t.Errorf("%s leaked %s:\n%s", name, canary, content)
			}
		}
	}
}

// TestServeNoSocketRouteReturnsCredential checks that no socket route, with
// or without a linked session holding credentials, returns a 2xx carrying
// credential material, and that the option-C routes do not exist.
func TestServeNoSocketRouteReturnsCredential(t *testing.T) {
	var calls atomic.Int32
	i11 := canaryI11(t, &calls)
	cfg := identityServeConfig(t, i11.URL)
	local, err := newServeLocalPDP(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.Close)
	local.SetKeychain(&canaryKeychain{token: subjectCanary})
	_, socketHandler := newServeHandlers(cfg, local)
	c := serveSocketForTest(t, socketHandler)

	if r := socketDo(t, c, http.MethodPut, "/v1/session", `{"schema":"kei.session/v1","source":"cli"}`); r.code != http.StatusNoContent {
		t.Fatalf("PUT = %s", r.dump)
	}
	for _, r := range socketRouteMatrix {
		resp := socketDo(t, c, r.method, r.path, r.body)
		if strings.Contains(resp.dump, credentialCanary) || strings.Contains(resp.dump, subjectCanary) {
			t.Errorf("%s returned credential material:\n%s", resp.route, resp.dump)
		}
		if strings.Contains(r.path, "credential") || r.path == "/v1/connectors:invoke" || r.path == "/v1/commands:run" {
			if resp.code != http.StatusNotFound {
				t.Errorf("%s = %d, want 404 (no credential route in L3a)", resp.route, resp.code)
			}
		}
	}
	var session map[string]any
	get := socketDo(t, c, http.MethodGet, "/v1/session", "")
	body := get.dump[strings.Index(get.dump, "{"):]
	if err := json.Unmarshal([]byte(body), &session); err != nil {
		t.Fatalf("GET /v1/session body %q: %v", body, err)
	}
	for key := range session {
		if key != "schema" && key != "user_id" && key != "status" {
			t.Errorf("GET /v1/session has field %q", key)
		}
	}
}

// captureFDs redirects the process's file descriptors 1 and 2 while f runs,
// so fmt, the log package, slog's default handler and raw runtime writes are
// all captured. The descriptors are restored even if f calls t.Fatal.
func captureFDs(t *testing.T, f func()) (stdout, stderr string) {
	t.Helper()
	out, errOut := redirectFD(t, 1), redirectFD(t, 2)
	func() {
		defer out.restore()
		defer errOut.restore()
		f()
	}()
	return out.wait(), errOut.wait()
}

type fdCapture struct {
	fd, saved int
	w         *os.File
	buf       bytes.Buffer
	done      chan struct{}
}

func redirectFD(t *testing.T, fd int) *fdCapture {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved, err := unix.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup2(int(w.Fd()), fd); err != nil {
		t.Fatal(err)
	}
	c := &fdCapture{fd: fd, saved: saved, w: w, done: make(chan struct{})}
	go func() {
		defer close(c.done)
		_, _ = io.Copy(&c.buf, r)
		_ = r.Close()
	}()
	return c
}

func (c *fdCapture) restore() {
	_ = unix.Dup2(c.saved, c.fd)
	_ = unix.Close(c.saved)
	_ = c.w.Close()
}

func (c *fdCapture) wait() string {
	<-c.done
	return c.buf.String()
}

func readSpool(t *testing.T, auditPath string) string {
	t.Helper()
	matches, err := filepath.Glob(auditPath + "*")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		b.Write(data)
	}
	return b.String()
}

func TestSessionCredentialStoreMode(t *testing.T) {
	for _, tc := range []struct {
		mode, url string
		store     bool
		err       bool
	}{
		{mode: "", store: false},
		{mode: CredentialReleaseLegacy, store: false},
		{mode: CredentialReleaseIdentity, url: "https://kei.example", store: true},
		{mode: CredentialReleaseIdentity, url: "http://identity.example", err: true},
		{mode: CredentialReleaseIdentity, url: "", err: true},
		{mode: "option-c", url: "https://kei.example", err: true},
	} {
		store, err := newSessionCredentialStore(Config{CredentialRelease: tc.mode, RuntimeControlPlaneURL: tc.url, RuntimeToken: credTestToken})
		if (err != nil) != tc.err || (store != nil) != tc.store {
			t.Errorf("mode %q url %q: store=%v err=%v", tc.mode, tc.url, store != nil, err)
		}
	}
	t.Setenv("KEI_CREDENTIAL_RELEASE", "")
	if got := configFromEnv().CredentialRelease; got != CredentialReleaseLegacy {
		t.Fatalf("default KEI_CREDENTIAL_RELEASE = %q, want legacy", got)
	}
}
