package runtime

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
)

func TestSocketAuthorizeResponseHidesEnrollmentFromUnauthenticatedCallers(t *testing.T) {
	const claimURL = "https://kei.example/one-time-claim"
	decision := pdp.Decision{
		Enrollment: json.RawMessage(`{"url":"` + claimURL + `"}`),
	}

	unauthenticated, err := json.Marshal(socketAuthorizeResponseForDecision(decision, false))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(unauthenticated), claimURL) || strings.Contains(string(unauthenticated), "enrollment") {
		t.Fatalf("unauthenticated response exposed enrollment data: %s", unauthenticated)
	}

	authenticated, err := json.Marshal(socketAuthorizeResponseForDecision(decision, true))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(authenticated), claimURL) {
		t.Fatalf("authenticated response omitted enrollment data: %s", authenticated)
	}
}
