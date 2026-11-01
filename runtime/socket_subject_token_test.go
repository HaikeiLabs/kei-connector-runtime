package runtime_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

const (
	stAgentID     = "20000000-0000-0000-0000-000000000006"
	stPrincipalID = "sp-bug-intake"
	stPrincipal   = "kei-bug-intake"
	stToken       = "principal-subject-token"
)

// subjectTokenBundle is principalBundle with its issue window shifted by
// shift and the principal token expiring at tokenExpiry.
func subjectTokenBundle(t *testing.T, principalID string, tokenExpiry time.Time, shift time.Duration) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(principalBundle(t, stAgentID, principalID, tokenExpiry), &doc); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(shift)
	doc["issued_at"], doc["not_after"] = now.Format(time.RFC3339Nano), now.Add(12*time.Hour).Format(time.RFC3339Nano)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type subjectTokenRig struct {
	l     *keiruntime.LocalPDP
	h     http.Handler
	dir   string
	mu    sync.Mutex
	audit []json.RawMessage
}

func (r *subjectTokenRig) events() []json.RawMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]json.RawMessage(nil), r.audit...)
}

// newSubjectTokenRig serves the owner-only socket handler (runtime token
// accepted) over bundle activated at activatedAt, with allow as the
// KEI_EXPORTABLE_SERVICE_PRINCIPALS list.
func newSubjectTokenRig(t *testing.T, bundle []byte, activatedAt time.Time, allow []string) *subjectTokenRig {
	t.Helper()
	validator := subjectV2SchemaValidator(t)
	policybundle.SetV2SchemaValidator(validator)
	t.Cleanup(func() { policybundle.SetV2SchemaValidator(validator) })
	rig := &subjectTokenRig{dir: t.TempDir()}
	store, err := policybundle.OpenStore(rig.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(bundle, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", activatedAt.UTC()); err != nil {
		t.Fatal(err)
	}
	rig.l = keiruntime.NewLocalPDP(connectorruntime.Config{RuntimeToken: policyTestToken, RuntimeControlPlaneURL: "https://kei.example", RuntimeStateDir: rig.dir}, func(raw json.RawMessage) {
		rig.mu.Lock()
		rig.audit = append(rig.audit, append(json.RawMessage(nil), raw...))
		rig.mu.Unlock()
	})
	t.Cleanup(rig.l.Close)
	rig.l.SetIdentity(&keiruntime.Identity{ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: strPtr("ws-fixture-0001"), AgentID: stAgentID})
	rig.l.SetExportableServicePrincipals(allow)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	rig.h = rig.l.NewSocketHandler(next, func() error { return nil }, func(*http.Request) bool { return true })
	return rig
}

func (r *subjectTokenRig) principalSession(t *testing.T) string {
	t.Helper()
	id, err := r.l.Sessions.Create(pdp.Subject{SubjectKind: "service_principal", UserID: stPrincipalID, Groups: []string{"bug-intake"}, Status: pdp.StatusLinked, Source: "cli", Token: stToken})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func postSubjectToken(h http.Handler, sessionID, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/session:subjectToken", strings.NewReader(body))
	if sessionID != "" {
		req.Header.Set(session.Header, sessionID)
	}
	h.ServeHTTP(rec, req)
	return rec
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body %q: %v", rec.Body.String(), err)
	}
	return body.Error.Code
}

func TestSubjectTokenRoute(t *testing.T) {
	allow := []string{stPrincipal}
	fresh := func(t *testing.T) []byte {
		return subjectTokenBundle(t, stPrincipalID, time.Now().Add(8*time.Hour), 0)
	}
	for _, tc := range []struct {
		name     string
		bundle   func(t *testing.T) []byte
		activate time.Duration // activation time offset from now
		allow    []string
		session  func(t *testing.T, r *subjectTokenRig) string
		status   int
		code     string
	}{
		{name: "happy path", bundle: fresh, allow: allow, status: http.StatusOK},
		{name: "allow-list among several", bundle: fresh, allow: []string{"other", " " + stPrincipal + " "}, status: http.StatusOK},
		{
			name: "user session", bundle: fresh, allow: allow, status: http.StatusForbidden, code: "principal_session_required",
			session: func(t *testing.T, r *subjectTokenRig) string {
				id, err := r.l.Sessions.Create(pdp.Subject{UserID: "u-alice", Status: pdp.StatusLinked, Source: "discord", ExternalID: "ext", Token: "user-subject-token"})
				if err != nil {
					t.Fatal(err)
				}
				return id
			},
		},
		{
			name: "revoked principal session", bundle: fresh, allow: allow, status: http.StatusForbidden, code: "principal_session_required",
			session: func(t *testing.T, r *subjectTokenRig) string {
				id, err := r.l.Sessions.Create(pdp.Subject{SubjectKind: "service_principal", UserID: stPrincipalID, Status: pdp.StatusRevoked})
				if err != nil {
					t.Fatal(err)
				}
				return id
			},
		},
		{
			name: "unknown session", bundle: fresh, allow: allow, status: http.StatusNotFound, code: "session_not_found",
			session: func(*testing.T, *subjectTokenRig) string { return "ks_never_created" },
		},
		{
			name: "no session header", bundle: fresh, allow: allow, status: http.StatusNotFound, code: "session_not_found",
			session: func(*testing.T, *subjectTokenRig) string { return "" },
		},
		{
			name: "expired session", bundle: fresh, allow: allow, status: http.StatusNotFound, code: "session_not_found",
			session: func(t *testing.T, r *subjectTokenRig) string {
				clock := time.Now()
				r.l.SetSessionIdleTTL(time.Minute)
				r.l.SetSessionNow(func() time.Time { return clock })
				id := r.principalSession(t)
				clock = clock.Add(2 * time.Minute)
				return id
			},
		},
		{name: "not allow-listed", bundle: fresh, allow: []string{"analytics-seed"}, status: http.StatusForbidden, code: "service_principal_not_exportable"},
		{name: "empty allow-list", bundle: fresh, allow: nil, status: http.StatusForbidden, code: "subject_token_export_disabled"},
		{name: "blank allow-list", bundle: fresh, allow: []string{" ", ""}, status: http.StatusForbidden, code: "subject_token_export_disabled"},
		{
			name: "principal missing from bundle", allow: allow, status: http.StatusForbidden, code: "service_principal_unavailable",
			bundle: func(t *testing.T) []byte {
				return subjectTokenBundle(t, "sp-replacement", time.Now().Add(8*time.Hour), 0)
			},
		},
		{
			// Activated 10 minutes ago: older than stale_after_seconds (300).
			name: "stale bundle", allow: allow, status: http.StatusServiceUnavailable, code: "subject_snapshot_stale",
			activate: -10 * time.Minute,
			bundle: func(t *testing.T) []byte {
				return subjectTokenBundle(t, stPrincipalID, time.Now().Add(8*time.Hour), -20*time.Minute)
			},
		},
		{
			name: "expired bundle", allow: allow, status: http.StatusServiceUnavailable, code: "policy_bundle_expired",
			activate: -2 * time.Hour,
			bundle: func(t *testing.T) []byte {
				return subjectTokenBundle(t, stPrincipalID, time.Now().Add(-90*time.Minute), -13*time.Hour)
			},
		},
		{
			name: "near-expiry token", allow: allow, status: http.StatusServiceUnavailable, code: "subject_token_expiring",
			bundle: func(t *testing.T) []byte {
				return subjectTokenBundle(t, stPrincipalID, time.Now().Add(30*time.Second), 0)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newSubjectTokenRig(t, tc.bundle(t), time.Now().Add(tc.activate), tc.allow)
			var id string
			if tc.session != nil {
				id = tc.session(t, rig)
			} else {
				id = rig.principalSession(t)
			}
			rec := postSubjectToken(rig.h, id, "")
			if rec.Code != tc.status {
				t.Fatalf("status=%d want %d body=%s", rec.Code, tc.status, rec.Body.String())
			}
			events := rig.events()
			if len(events) != 1 {
				t.Fatalf("audit events = %d, want 1: %s", len(events), events)
			}
			var audit struct {
				Decision        string   `json:"decision"`
				ReasonCode      string   `json:"reason_code"`
				ToolName        string   `json:"tool_name"`
				InvokingSubject string   `json:"invoking_subject"`
				SessionID       *string  `json:"session_id"`
				PolicyReason    string   `json:"policy_reason"`
				Resources       []string `json:"resources_touched"`
				AgentID         string   `json:"agent_id"`
			}
			if err := json.Unmarshal(events[0], &audit); err != nil {
				t.Fatal(err)
			}
			if audit.ToolName != "kei:session.subjectToken" || audit.AgentID != stAgentID {
				t.Fatalf("audit = %s", events[0])
			}
			if strings.Contains(string(events[0]), stToken) || strings.Contains(string(events[0]), "user-subject-token") {
				t.Fatalf("audit leaks a token: %s", events[0])
			}
			if tc.status != http.StatusOK {
				if got := errorCode(t, rec); got != tc.code {
					t.Fatalf("code=%q want %q body=%s", got, tc.code, rec.Body.String())
				}
				if strings.Contains(rec.Body.String(), stToken) {
					t.Fatalf("refusal leaks the token: %s", rec.Body.String())
				}
				if audit.Decision != "deny" || audit.ReasonCode != tc.code {
					t.Fatalf("deny audit = %s", events[0])
				}
				return
			}
			if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
				t.Fatalf("Cache-Control=%q", cc)
			}
			var resp map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if len(resp) != 4 || resp["schema"] != "kei.subject-token/v1" || resp["subject_token"] != stToken || resp["service_principal_id"] != stPrincipalID {
				t.Fatalf("response = %v", resp)
			}
			expire, err := time.Parse(time.RFC3339, resp["expire_time"])
			if err != nil || time.Until(expire) < 7*time.Hour {
				t.Fatalf("expire_time=%q err=%v", resp["expire_time"], err)
			}
			if audit.Decision != "allow" || audit.InvokingSubject != "service_principal:"+stPrincipalID ||
				audit.SessionID == nil || *audit.SessionID != id ||
				audit.PolicyReason != "subject token issued; expire_time="+resp["expire_time"] ||
				len(audit.Resources) != 1 || audit.Resources[0] != "service_principal:"+stPrincipalID {
				t.Fatalf("allow audit = %s", events[0])
			}
		})
	}
}

// The token always comes from the current bundle: after a refresh the route
// returns the new token, not the one the session was created with.
func TestSubjectTokenUsesCurrentBundleToken(t *testing.T) {
	rig := newSubjectTokenRig(t, subjectTokenBundle(t, stPrincipalID, time.Now().Add(8*time.Hour), 0), time.Now(), []string{stPrincipal})
	id, err := rig.l.Sessions.Create(pdp.Subject{SubjectKind: "service_principal", UserID: stPrincipalID, Status: pdp.StatusLinked, Token: "stale-session-token"})
	if err != nil {
		t.Fatal(err)
	}
	rec := postSubjectToken(rig.h, id, "{}")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"subject_token":"`+stToken+`"`) || strings.Contains(rec.Body.String(), "stale-session-token") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSubjectTokenRejectsRequestBody(t *testing.T) {
	rig := newSubjectTokenRig(t, subjectTokenBundle(t, stPrincipalID, time.Now().Add(8*time.Hour), 0), time.Now(), []string{stPrincipal})
	id := rig.principalSession(t)
	for _, body := range []string{`{"subject_token":"forged"}`, `{"service_principal_name":"other"}`, `[]`, `not json`} {
		rec := postSubjectToken(rig.h, id, body)
		if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), stToken) {
			t.Fatalf("body %q: status=%d %s", body, rec.Code, rec.Body.String())
		}
	}
}

// The route requires the runtime token, even with tokenless owner sessions on,
// and is served only by the owner-only socket handler.
func TestSubjectTokenRequiresRuntimeTokenAndSocket(t *testing.T) {
	rig := newSubjectTokenRig(t, subjectTokenBundle(t, stPrincipalID, time.Now().Add(8*time.Hour), 0), time.Now(), []string{stPrincipal})
	id := rig.principalSession(t)
	rig.l.SetTokenlessOwnerSession(true)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	unauth := rig.l.NewSocketHandler(next, func() error { return nil }, func(*http.Request) bool { return false })
	for _, sid := range []string{id, ""} {
		if rec := postSubjectToken(unauth, sid, ""); rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), stToken) {
			t.Fatalf("unauthenticated session=%q: status=%d body=%s", sid, rec.Code, rec.Body.String())
		}
	}
	tcp := rig.l.NewHandler(next, func() error { return nil }, func(*http.Request) bool { return true })
	if rec := postSubjectToken(tcp, id, ""); rec.Code != http.StatusTeapot {
		t.Fatalf("non-socket handler served the route: status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/session:subjectToken", nil)
	req.Header.Set(session.Header, id)
	rig.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET status=%d", rec.Code)
	}
}

// Neither the token nor any request header value reaches the logs or audit.
func TestSubjectTokenNeverLogged(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	rig := newSubjectTokenRig(t, subjectTokenBundle(t, stPrincipalID, time.Now().Add(8*time.Hour), 0), time.Now(), []string{stPrincipal})
	id := rig.principalSession(t)
	const authHeader = "Bearer kh_live_header_value_must_not_be_logged"
	for _, allow := range [][]string{{stPrincipal}, {"other"}, nil} {
		rig.l.SetExportableServicePrincipals(allow)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/session:subjectToken", nil)
		req.Header.Set(session.Header, id)
		req.Header.Set("Authorization", authHeader)
		rig.h.ServeHTTP(rec, req)
	}
	events := rig.events()
	if len(events) != 3 {
		t.Fatalf("audit events = %d, want 3", len(events))
	}
	var all []string
	for _, e := range events {
		all = append(all, string(e))
	}
	audit := strings.Join(all, "\n")
	for _, secret := range []string{stToken, authHeader, "kh_live_header_value"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("logs contain %q: %s", secret, logs.String())
		}
		if strings.Contains(audit, secret) {
			t.Fatalf("audit contains %q: %s", secret, audit)
		}
	}
	if strings.Contains(logs.String(), id) {
		t.Fatalf("logs contain the session header value: %s", logs.String())
	}
}
