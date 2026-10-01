package connectorruntime

import (
	"encoding/json"
	"testing"
)

func TestLocalDecisionReasonFieldsSerialize(t *testing.T) {
	got, err := json.Marshal(AuthorizeResponse{Decision: "deny", Reason: "no matching policy", ReasonCode: "no_matching_policy", DenySource: "policy"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["reason_code"] != "no_matching_policy" || decoded["deny_source"] != "policy" {
		t.Fatalf("local denial wire fields = %s", got)
	}
}
