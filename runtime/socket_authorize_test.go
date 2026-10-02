package runtime_test

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

func TestSocketSessionGetReturnsSubjectMinimalResponse(t *testing.T) {
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	_ = l.Sessions.Start(pdp.Subject{UserID: "user-abc", Email: "user@test", Status: pdp.StatusLinked, Enrollment: json.RawMessage(`"https://claim.url"`)})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	checkConfig := func() error { return nil }
	checkAuth := func(r *http.Request) bool { return true }
	handler := l.NewHandler(next, checkConfig, checkAuth)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/session", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var keys struct {
		Schema     string `json:"schema"`
		UserID     string `json:"user_id"`
		Status     string `json:"status"`
		Email      string `json:"email,omitempty"`
		Enrollment any    `json:"enrollment,omitempty"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	if keys.Schema != "kei.session/v1" || keys.UserID != "user-abc" || keys.Status != "linked" {
		t.Fatalf("response %+v", keys)
	}
	if keys.Email != "" {
		t.Fatal("email leaked in GET /v1/session response")
	}
	if keys.Enrollment != nil {
		t.Fatal("enrollment leaked in GET /v1/session response")
	}
}

func TestSocketSessionGetReturns401WithoutRuntimeToken(t *testing.T) {
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	checkConfig := func() error { return nil }
	checkAuth := func(r *http.Request) bool { return false }
	handler := l.NewHandler(next, checkConfig, checkAuth)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/session", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSocketSessionGetReturns404WhenNoSession(t *testing.T) {
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	checkConfig := func() error { return nil }
	checkAuth := func(r *http.Request) bool { return true }
	handler := l.NewHandler(next, checkConfig, checkAuth)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/session", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSocketAuthorizeDeniesBeforeIdentityResolves(t *testing.T) {
	l := keiruntime.NewLocalPDP(connectorruntime.Config{
		RuntimeToken:           policyTestToken,
		RuntimeControlPlaneURL: "https://kei.example",
	}, nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	checkConfig := func() error { return nil }
	checkAuth := func(r *http.Request) bool {
		const prefix = "Bearer "
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, prefix) {
			return false
		}
		token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
		return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(policyTestToken)) == 1
	}
	handler := l.NewHandler(next, checkConfig, checkAuth)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(`{"schema":"kei.authorize-request/v1","tool":"search_wiki"}`))
	req.Header.Set("Authorization", "Bearer "+policyTestToken)
	handler.ServeHTTP(rec, req)
	var out struct {
		Schema      string `json:"schema"`
		Decision    string `json:"decision"`
		ReasonCode  string `json:"reason_code"`
		DenySource  string `json:"deny_source"`
		BundleState string `json:"bundle_state"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || out.Decision != "deny" || out.ReasonCode != "policy_bundle_missing" || out.DenySource != "runtime_state" || out.BundleState != "cold" {
		t.Fatalf("status %d response %+v", rec.Code, out)
	}
}
