package runtime

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
)

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
