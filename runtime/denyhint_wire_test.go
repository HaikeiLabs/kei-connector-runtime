package runtime

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
)

// TestAuthorizeOutputCarriesHintOnDeny drives the one-shot authorize path to a
// registry deny and asserts the JSON carries a non-empty hint next to
// reason_code.
func TestAuthorizeOutputCarriesHintOnDeny(t *testing.T) {
	bundle, _ := mustActivateTestBundle(t, t.TempDir(), time.Now().UTC())
	out, err := AuthorizeTool(AuthorizeParams{
		Ctx:          context.Background(),
		PolicyBundle: bundle,
		Tool:         "totally_unknown_tool_xyz",
		Action:       "tool:totally_unknown_tool_xyz",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Decision != "deny" || out.ReasonCode == "" {
		t.Fatalf("want a deny with a reason code, got %+v", out)
	}
	raw, _ := json.Marshal(out)
	if !strings.Contains(string(raw), `"reason_code":"`+out.ReasonCode+`"`) {
		t.Fatalf("deny output missing reason_code: %s", raw)
	}
	if !strings.Contains(string(raw), `"hint":"`) {
		t.Fatalf("deny output missing hint next to reason_code: %s", raw)
	}
}

// TestSocketAuthorizeResponseCarriesHintOnDeny asserts the socket route's
// response carries a hint for a known deny code and omits it (omitempty) for a
// code outside the table.
func TestSocketAuthorizeResponseCarriesHintOnDeny(t *testing.T) {
	known := socketAuthorizeResponseForDecision(pdp.Decision{ReasonCode: "no_matching_policy", DenySource: "policy", Reason: "no policy matched"}, false)
	raw, _ := json.Marshal(known)
	if !strings.Contains(string(raw), `"reason_code":"no_matching_policy"`) || !strings.Contains(string(raw), `"hint":"`) {
		t.Fatalf("socket deny missing hint: %s", raw)
	}

	unknown := socketAuthorizeResponseForDecision(pdp.Decision{ReasonCode: "some_unknown_code", DenySource: "policy", Reason: "x"}, false)
	raw2, _ := json.Marshal(unknown)
	if !strings.Contains(string(raw2), `"reason_code":"some_unknown_code"`) {
		t.Fatalf("socket deny missing reason_code: %s", raw2)
	}
	if strings.Contains(string(raw2), `"hint"`) {
		t.Fatalf("socket deny with an unknown code must omit hint: %s", raw2)
	}
}
