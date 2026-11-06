package connectorruntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveModelInvokeProfileSelectsRequestedAgentAndProfile(t *testing.T) {
	const agentID = "00000000-0000-0000-0000-000000000061"
	const profileID = "00000000-0000-0000-0000-000000000062"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/model-profiles/"+profileID || r.URL.Query().Get("agent_id") != agentID {
			t.Fatalf("request = %s, want profile selection scoped to agent", r.URL.String())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"profile_id": profileID,
			"org_id":     "00000000-0000-0000-0000-000000000063",
			"agent_id":   agentID,
			"status":     "active",
		})
	}))
	defer server.Close()

	var request ModelInvokeRequest
	if err := json.Unmarshal([]byte(`{"request":{},"agent_id":"`+agentID+`","profile_id":"`+profileID+`"}`), &request); err != nil {
		t.Fatal(err)
	}
	client := NewControlPlaneModelProfileClient(server.URL, "runtime-token", 0)
	profile, err := resolveModelInvokeProfile(context.Background(), client, request.AgentID, request.ProfileID)
	if err != nil || profile == nil || profile.ProfileID != profileID {
		t.Fatalf("profile = %+v, err = %v", profile, err)
	}
}
