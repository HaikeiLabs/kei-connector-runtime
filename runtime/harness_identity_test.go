package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveHarnessIdentityUsesServiceCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/internal/harness-identity" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-KEI-API-Key"); got != "abac-secret" {
			t.Fatalf("X-KEI-API-Key = %q", got)
		}
		var request map[string]string
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request["harness_token"] != "harness-token" {
			t.Fatalf("unexpected harness token %q", request["harness_token"])
		}
		json.NewEncoder(w).Encode(HarnessIdentity{OrgID: "org-1", AgentID: "agent-1", ModelProfileID: "profile-1"})
	}))
	defer server.Close()

	identity, err := ResolveHarnessIdentity(context.Background(), server.URL, "abac-secret", "harness-token")
	if err != nil {
		t.Fatalf("resolve identity: %v", err)
	}
	if identity.OrgID != "org-1" || identity.AgentID != "agent-1" || identity.ModelProfileID != "profile-1" {
		t.Fatalf("unexpected identity: %+v", identity)
	}
}
