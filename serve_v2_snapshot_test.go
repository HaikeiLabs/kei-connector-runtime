package connectorruntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// v2ModelFixture activates the v2 example bundle (its agent_model_profiles
// assign profile-gpt, active, to agent-chat and profile-claude, disabled, to
// agent-review) issued issuedAgo before now, and returns a local PDP whose
// refresher identity is resolved for its audience.
func v2ModelFixture(t *testing.T, issuedAgo time.Duration) (Config, *keiruntime.LocalPDP) {
	t.Helper()
	now := time.Now().UTC()
	raw, err := os.ReadFile("docs/contracts/examples/policy-bundle-v2.payload.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	payload["issued_at"] = now.Add(-issuedAgo).Format(time.RFC3339Nano)
	payload["not_after"] = now.Add(time.Hour).Format(time.RFC3339Nano)
	raw, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Clean(t.TempDir())
	store, err := policybundle.OpenStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(raw, "inst-v2", "org-v2", "ws-v2", now); err != nil {
		t.Fatalf("activate v2 test bundle: %v", err)
	}
	cfg := Config{RuntimeToken: "kh_live_model_test_token_123456", RuntimeStateDir: stateDir}
	local := keiruntime.NewLocalPDP(cfg, nil)
	workspace := "ws-v2"
	local.SetIdentity(&keiruntime.Identity{ID: "inst-v2", OrgID: "org-v2", WorkspaceID: &workspace})
	return cfg, local
}

// noControlPlane fails the test on any control-plane request: the v2 model
// path decides from the refresher's identity and the bundle alone.
func noControlPlane(t *testing.T) string {
	t.Helper()
	var calls atomic.Int32
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "v2 model authorization must not call the control plane", http.StatusInternalServerError)
	}))
	t.Cleanup(func() {
		control.Close()
		if n := calls.Load(); n != 0 {
			t.Errorf("v2 model authorization made %d control-plane requests", n)
		}
	})
	return control.URL
}

var linkedDiscordSubject = pdp.Subject{UserID: "kei-user-123", Source: "discord", ExternalID: "discord-user-123", Status: pdp.StatusLinked}

func TestV2ModelAuthorizationIsTheAgentAssignment(t *testing.T) {
	cases := []struct {
		name, agent, profile string
		subject              *pdp.Subject
		issuedAgo            time.Duration
		reason               string
	}{
		{name: "assigned active profile", agent: "agent-chat", profile: "profile-gpt", subject: &linkedDiscordSubject, issuedAgo: time.Second},
		{name: "another agent's profile", agent: "agent-chat", profile: "profile-claude", subject: &linkedDiscordSubject, issuedAgo: time.Second, reason: policybundle.ReasonModelNotAssigned},
		{name: "unknown agent", agent: "agent-other", profile: "profile-gpt", subject: &linkedDiscordSubject, issuedAgo: time.Second, reason: policybundle.ReasonModelNotAssigned},
		{name: "no agent", agent: "", profile: "profile-gpt", subject: &linkedDiscordSubject, issuedAgo: time.Second, reason: policybundle.ReasonModelNotAssigned},
		{name: "assigned profile disabled", agent: "agent-review", profile: "profile-claude", subject: &linkedDiscordSubject, issuedAgo: time.Second, reason: policybundle.ReasonModelProfileInactive},
		{name: "no session subject", agent: "agent-chat", profile: "profile-gpt", issuedAgo: time.Second, reason: "subject_unlinked"},
		{name: "pending subject", agent: "agent-chat", profile: "profile-gpt", subject: &pdp.Subject{UserID: "kei-user-123", Source: "discord", ExternalID: "discord-user-123", Status: pdp.StatusPending}, issuedAgo: time.Second, reason: "subject_pending"},
		{name: "subject absent from snapshot", agent: "agent-chat", profile: "profile-gpt", subject: &pdp.Subject{UserID: "kei-user-999", Source: "discord", ExternalID: "discord-user-999", Status: pdp.StatusLinked}, issuedAgo: time.Second, reason: "subject_unlinked"},
		{name: "stale snapshot", agent: "agent-chat", profile: "profile-gpt", subject: &linkedDiscordSubject, issuedAgo: 31 * time.Second, reason: "subject_snapshot_stale"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, local := v2ModelFixture(t, tc.issuedAgo)
			cfg.RuntimeControlPlaneURL = noControlPlane(t)
			sessionID := pdp.DefaultSession
			if tc.subject != nil {
				id, err := local.Sessions.Create(*tc.subject)
				if err != nil {
					t.Fatal(err)
				}
				sessionID = id
			}
			handler := &runtimeHTTPHandler{cfg: cfg, sessions: local.Sessions, models: local}
			err := handler.authorizeModel(context.Background(), &ModelProfile{ProfileID: tc.profile, AgentID: tc.agent}, sessionID, pdp.Subject{})
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("authorizeModel = %v, want allow", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "("+tc.reason+")") {
				t.Fatalf("authorizeModel = %v, want deny %s", err, tc.reason)
			}
		})
	}
}

func TestV2ModelAuthorizationDeniesRevokedInstallation(t *testing.T) {
	cfg, local := v2ModelFixture(t, time.Second)
	cfg.RuntimeControlPlaneURL = noControlPlane(t)
	store, err := policybundle.OpenStore(cfg.RuntimeStateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	id, err := local.Sessions.Create(linkedDiscordSubject)
	if err != nil {
		t.Fatal(err)
	}
	handler := &runtimeHTTPHandler{cfg: cfg, sessions: local.Sessions, models: local}
	err = handler.authorizeModel(context.Background(), &ModelProfile{ProfileID: "profile-gpt", AgentID: "agent-chat"}, id, pdp.Subject{})
	if err == nil || !strings.Contains(err.Error(), "(installation_revoked)") {
		t.Fatalf("authorizeModel = %v, want installation_revoked", err)
	}
}

type fixedModelProfiles struct{ profile *ModelProfile }

func (f fixedModelProfiles) GetRuntimeModelProfile(context.Context, string) (*ModelProfile, error) {
	return f.profile, nil
}
func (f fixedModelProfiles) GetRuntimeDefaultModelProfile(context.Context) (*ModelProfile, error) {
	return f.profile, nil
}
func (f fixedModelProfiles) GetRuntimeAssignedModelProfile(context.Context) (*ModelProfile, error) {
	return f.profile, nil
}

func TestV2ChatCompletionsDeniesUnassignedModelBeforeProvider(t *testing.T) {
	for _, tc := range []struct {
		agent  string
		status int
		code   string
	}{
		{agent: "agent-chat", status: http.StatusOK},
		{agent: "agent-other", status: http.StatusForbidden, code: policybundle.ReasonModelNotAssigned},
	} {
		t.Run(tc.agent, func(t *testing.T) {
			cfg, local := v2ModelFixture(t, time.Second)
			cfg.RuntimeControlPlaneURL = noControlPlane(t)
			var providerCalls atomic.Int32
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				providerCalls.Add(1)
				_, _ = w.Write([]byte(`{"choices":[]}`))
			}))
			defer provider.Close()
			id, err := local.Sessions.Create(linkedDiscordSubject)
			if err != nil {
				t.Fatal(err)
			}
			handler := &runtimeHTTPHandler{
				cfg: cfg, client: provider.Client(), sessions: local.Sessions, models: local,
				profiles: fixedModelProfiles{&ModelProfile{ProfileID: "profile-gpt", AgentID: tc.agent, Status: "active", Endpoint: provider.URL, DefaultModel: "gpt-test"}},
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"profile-gpt","messages":[]}`))
			req.Header.Set("Authorization", "Bearer "+cfg.RuntimeToken)
			req.Header.Set(session.Header, id)
			rec := httptest.NewRecorder()
			handler.handleChatCompletions(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d body = %s", rec.Code, rec.Body)
			}
			if tc.code != "" {
				if !strings.Contains(rec.Body.String(), "("+tc.code+")") {
					t.Fatalf("body = %s, want reason %s", rec.Body, tc.code)
				}
				if n := providerCalls.Load(); n != 0 {
					t.Fatalf("denied model call reached the provider %d times", n)
				}
			} else if n := providerCalls.Load(); n != 1 {
				t.Fatalf("allowed model call reached the provider %d times", n)
			}
		})
	}
}
