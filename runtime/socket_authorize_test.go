package runtime_test

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	connectorruntime "github.com/HaikeiLabs/kei-connector-runtime"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

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
