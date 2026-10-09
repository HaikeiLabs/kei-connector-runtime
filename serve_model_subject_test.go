package connectorruntime

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

func TestModelSubjectRequestShapePerSessionSource(t *testing.T) {
	const owuiUser = "7d1c3e1a-4f7b-4a7e-9a52-0b0f6c1e2d3a"
	cases := []struct {
		name     string
		sub      pdp.Subject
		provider string
		tenant   string
		want     keiruntime.SubjectResolveRequest
		wantOK   bool
	}{
		{
			name:   "cli session resolves by Kei user_id",
			sub:    pdp.Subject{UserID: "kei-user-1", Source: "cli", Status: pdp.StatusLinked},
			want:   keiruntime.SubjectResolveRequest{UserID: "kei-user-1"},
			wantOK: true,
		},
		{
			name:   "openwebui session resolves by platform_user_id, never user_id",
			sub:    pdp.Subject{UserID: "kei-user-1", Source: "openwebui", ExternalID: owuiUser, Status: pdp.StatusLinked},
			want:   keiruntime.SubjectResolveRequest{PlatformUserID: owuiUser},
			wantOK: true,
		},
		{
			name:   "chat session carries the configured tenant",
			sub:    pdp.Subject{UserID: "kei-user-1", Source: "slack", ExternalID: "U123", Status: pdp.StatusLinked},
			tenant: "T999",
			want:   keiruntime.SubjectResolveRequest{PlatformUserID: "U123", TenantID: "T999"},
			wantOK: true,
		},
		{
			name:     "unlinked session falls back to the configured provider user",
			sub:      pdp.Subject{Status: pdp.StatusUnlinked},
			provider: "provider-user-1",
			want:     keiruntime.SubjectResolveRequest{PlatformUserID: "provider-user-1"},
			wantOK:   true,
		},
		{
			name:   "no subject and no provider user resolves nothing",
			sub:    pdp.Subject{Status: pdp.StatusUnlinked},
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := modelSubjectRequest(tc.sub, tc.provider, tc.tenant)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("modelSubjectRequest = %+v, %v; want %+v, %v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// modelSubjectFixture serves an openwebui installation whose catalog answers
// subject resolution with resolve, recording each request it receives.
func modelSubjectFixture(t *testing.T, resolve func(w http.ResponseWriter, req keiruntime.SubjectResolveRequest)) (http.Handler, *[]keiruntime.SubjectResolveRequest, *int) {
	t.Helper()
	const runtimeToken = "kh_live_runtime_test_token_1234567890"
	stateDir := t.TempDir()
	mustActivateTestBundle(t, stateDir, time.Now().UTC())
	workspace := "ws-fixture-0001"

	var requests []keiruntime.SubjectResolveRequest
	catalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/runtime/subject-attributes:resolve" {
			t.Errorf("unexpected catalog request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var req keiruntime.SubjectResolveRequest
		if err := dec.Decode(&req); err != nil {
			t.Errorf("decode subject resolve request: %v", err)
		}
		requests = append(requests, req)
		resolve(w, req)
	}))
	t.Cleanup(catalog.Close)
	var providerCalls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { providerCalls++ }))
	t.Cleanup(provider.Close)
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/runtime/whoami":
			_ = json.NewEncoder(w).Encode(RuntimeIdentity{
				ID: "inst-fixture-0001", OrgID: "org-fixture-0001", WorkspaceID: &workspace,
				Platform: "openwebui", Status: "active", BindingStatus: "verified",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/runtime/model-profiles/assigned":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"profile_id":   "00000000-0000-0000-0000-000000000011",
				"org_id":       "00000000-0000-0000-0000-000000000012",
				"agent_id":     "00000000-0000-0000-0000-000000000013",
				"display_name": "Test model", "endpoint": provider.URL,
				"default_model": "m1", "auth_type": "none", "status": "active",
			})
		default:
			t.Errorf("unexpected control plane request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(controlPlane.Close)

	sessions := pdp.NewSessions()
	if err := sessions.Start(pdp.Subject{
		UserID: "kei-user-0001", Source: "openwebui", ExternalID: "7d1c3e1a-4f7b-4a7e-9a52-0b0f6c1e2d3a", Status: pdp.StatusLinked,
	}); err != nil {
		t.Fatal(err)
	}
	handler := newRuntimeHTTPHandler(Config{
		RuntimeControlPlaneURL: controlPlane.URL,
		ABACURL:                catalog.URL,
		RuntimeToken:           runtimeToken,
		RuntimeStateDir:        stateDir,
	}, sessions)
	return handler, &requests, &providerCalls
}

func serveModelCall(handler http.Handler) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"00000000-0000-0000-0000-000000000011"}`))
	request.Header.Set("Authorization", "Bearer kh_live_runtime_test_token_1234567890")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestRuntimeHTTPHandlerResolvesOpenWebUISessionByPlatformUserID(t *testing.T) {
	handler, requests, _ := modelSubjectFixture(t, func(w http.ResponseWriter, req keiruntime.SubjectResolveRequest) {
		_ = json.NewEncoder(w).Encode(policybundle.Subject{
			Status: "linked_approved", UserID: "kei-user-0001",
			EffectiveGroups: []string{"members"}, OrgRoles: []string{"member"}, MaxAgeSeconds: 60,
		})
	})
	response := serveModelCall(handler)

	if len(*requests) != 1 {
		t.Fatalf("subject resolve requests = %d, want 1", len(*requests))
	}
	want := keiruntime.SubjectResolveRequest{PlatformUserID: "7d1c3e1a-4f7b-4a7e-9a52-0b0f6c1e2d3a"}
	if got := (*requests)[0]; got != want {
		t.Fatalf("subject resolve request = %+v, want %+v (chat sessions must not send user_id)", got, want)
	}
	// The test bundle has no model:invoke allow, so the call is a policy
	// denial, not a subject resolution failure.
	if strings.Contains(response.Body.String(), "subject resolution unavailable") {
		t.Fatalf("subject resolution failed: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRuntimeHTTPHandlerOpenWebUISubjectResolutionFailsClosed(t *testing.T) {
	handler, _, providerCalls := modelSubjectFixture(t, func(w http.ResponseWriter, req keiruntime.SubjectResolveRequest) {
		w.WriteHeader(http.StatusBadRequest)
	})
	response := serveModelCall(handler)

	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "subject resolution unavailable") {
		t.Fatalf("status=%d body=%s, want 403 subject resolution unavailable", response.Code, response.Body.String())
	}
	if *providerCalls != 0 {
		t.Fatalf("provider calls = %d, want 0 when subject resolution fails", *providerCalls)
	}
}
