package runtime

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
)

func TestPiShellCommandIsExcludedFromSocketAuditEvent(t *testing.T) {
	const command = "git status --short"
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	local := &LocalPDP{Sessions: pdp.NewSessions()}
	event := local.decisionEventJSON(socketAuthorizeRequest{
		Tool: "pi.bash", ShellCommand: command, ToolArgsDigest: digest,
	}, pdp.DefaultSession, pdp.Decision{ReasonCode: "policy_unmatched"})
	if strings.Contains(string(event), command) {
		t.Fatalf("audit event included shell command: %s", event)
	}
	if !strings.Contains(string(event), digest) {
		t.Fatalf("audit event omitted argument digest: %s", event)
	}
}

func TestValidArgumentDigest(t *testing.T) {
	if !validArgumentDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatal("valid digest rejected")
	}
	for _, invalid := range []string{"", "sha256:short", "sha256:" + strings.Repeat("G", 64)} {
		if validArgumentDigest(invalid) {
			t.Fatalf("invalid digest accepted: %q", invalid)
		}
	}
}

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
