package connectorruntime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

func TestModelAuthorizationStopsAtStaleV2SnapshotBeforeSubjectResolution(t *testing.T) {
	now := time.Now().UTC()
	raw, err := os.ReadFile("docs/contracts/examples/policy-bundle-v2.payload.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	payload["audience"] = map[string]any{"installation_id": "inst-v2", "org_id": "org-v2", "workspace_id": "ws-v2"}
	payload["issued_at"] = now.Add(-31 * time.Second).Format(time.RFC3339Nano)
	payload["not_after"] = now.Add(time.Hour).Format(time.RFC3339Nano)
	payload["subject_resolution"] = map[string]any{"mode": "bundle", "max_cache_seconds": 30}
	raw, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	store, err := policybundle.OpenStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(raw, "inst-v2", "org-v2", "ws-v2", now); err != nil {
		t.Fatalf("activate v2 test bundle: %v", err)
	}

	resolveCalls := 0
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/runtime/whoami":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "inst-v2", "org_id": "org-v2", "workspace_id": "ws-v2", "platform": "cli", "status": "active", "binding_status": "verified"})
		case "/api/v1/runtime/subject-attributes:resolve":
			resolveCalls++
			http.Error(w, "should not resolve a v2 subject online", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer control.Close()
	cfg := Config{RuntimeToken: "kh_live_model_test_token_123456", RuntimeControlPlaneURL: control.URL, RuntimeStateDir: filepath.Clean(stateDir)}
	handler := &runtimeHTTPHandler{cfg: cfg}
	err = handler.authorizeModel(context.Background(), &ModelProfile{ProfileID: "model-v2"}, "user-alice")
	if !errors.Is(err, policybundle.ErrSubjectSnapshotStale) {
		t.Fatalf("authorizeModel error=%v", err)
	}
	if resolveCalls != 0 {
		t.Fatalf("stale v2 model call made %d subject-resolution requests", resolveCalls)
	}
}
