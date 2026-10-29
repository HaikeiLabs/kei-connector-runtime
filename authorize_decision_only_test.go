package connectorruntime

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
)

// TestAuthorizeDecisionOnlyWhenNonDecisionComponentsAreBroken pins the
// HAI-724 slice-3 invariant: the daemon decides from the local policy bundle
// alone, and breaking or removing every non-decision component never changes
// an authorize result.
//
// Since HAI-724 the module contains no provider-call code at all (the native
// connector executors and the http_api invoker are deleted), so this test
// runs in a binary whose only connector behavior is the decision path. It
// compares two runs of the same bundle, session, and request:
//
//   - healthy: a live control plane (I11) serves credential release, so the
//     session start loads a GitHub credential;
//   - broken: the control plane URL points at a closed server (credential
//     release, credential sync, the identity APIs, and audit crypto are
//     unreachable), the state dir has no connector reference index and no
//     tenant secrets, and no executor package exists in the module.
//
// Both runs must answer byte-identical decisions, and neither may touch a
// provider.
func TestAuthorizeDecisionOnlyWhenNonDecisionComponentsAreBroken(t *testing.T) {
	// One bundle for both rigs, so the only difference between the runs is
	// the health of the non-decision components.
	bundle := connectorTestBundle(t)
	authorizeBody := `{"schema":"kei.authorize-request/v1","tool":"github.repository_read"}`

	healthy := newSocketRigWithBundle(t, bundle, nil)
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close() // every connection to this URL is refused from here on
	broken := newSocketRigWithBundle(t, bundle, func(cfg *Config) { cfg.RuntimeControlPlaneURL = dead.URL })

	healthyID := healthy.startNamedSession(t)
	brokenID := broken.startNamedSession(t)

	// The break took: no control-plane call succeeded and no connector
	// reference index was ever written.
	if i11, _ := broken.counts(); len(i11) != 0 {
		t.Fatalf("the broken rig reached the control plane %d times, want 0", len(i11))
	}
	if _, err := os.Stat(credentials.ConnectorIndexPath(broken.cfg.RuntimeStateDir)); err == nil {
		t.Errorf("the broken state dir has a connector reference index, want none")
	}

	healthyResp := socketDoSession(t, healthy.client, http.MethodPost, "/v1/authorize", healthyID, authorizeBody)
	brokenResp := socketDoSession(t, broken.client, http.MethodPost, "/v1/authorize", brokenID, authorizeBody)
	if healthyResp.code != http.StatusOK || brokenResp.code != http.StatusOK {
		t.Fatalf("authorize statuses: healthy %s, broken %s", healthyResp.dump, brokenResp.dump)
	}
	if healthyResp.dump != brokenResp.dump {
		t.Fatalf("the authorize decision changed when the non-decision components broke\nhealthy: %s\nbroken:  %s", healthyResp.dump, brokenResp.dump)
	}

	// The shared decision is the bundle's permit for the registered harness tool.
	var resp struct {
		Decision string `json:"decision"`
		PolicyID string `json:"policy_id"`
	}
	if err := json.Unmarshal([]byte(healthyResp.dump[strings.Index(healthyResp.dump, "{"):]), &resp); err != nil {
		t.Fatalf("healthy authorize body: %v", err)
	}
	if resp.Decision != "permit" || resp.PolicyID != "pol-github-read" {
		t.Fatalf("authorize decision = %+v, want permit by pol-github-read", resp)
	}

	// No provider call happened on either path: the decision is not an
	// execution.
	for name, rig := range map[string]*socketRig{"healthy": healthy, "broken": broken} {
		if paths := rig.providerPaths(); len(paths) != 0 {
			t.Errorf("%s rig's decision path called providers: %v", name, paths)
		}
	}
}
