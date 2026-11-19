package runtime

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
)

func TestShellCommandIsExcludedFromSocketAuditEvent(t *testing.T) {
	const command = "git status --short > private-marker"
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	local := &LocalPDP{Sessions: pdp.NewSessions()}
	event := local.decisionEventJSON(socketAuthorizeRequest{
		Tool: "shell", ShellCommand: command, ToolArgsDigest: digest,
	}, pdp.DefaultSession, pdp.Decision{
		ReasonCode: pdp.ReasonUnsupportedShellSyntax, SyntaxCode: "unsupported_redirection",
	}, "")
	if strings.Contains(string(event), command) {
		t.Fatalf("audit event included shell command: %s", event)
	}
	if !strings.Contains(string(event), digest) {
		t.Fatalf("audit event omitted argument digest: %s", event)
	}
	if !strings.Contains(string(event), `"syntax_code":"unsupported_redirection"`) {
		t.Fatalf("audit event omitted bounded syntax category: %s", event)
	}
	response, err := json.Marshal(socketAuthorizeResponseForDecision(pdp.Decision{
		ReasonCode: pdp.ReasonUnsupportedShellSyntax, SyntaxCode: "unsupported_redirection",
	}, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{command, "status", "short", "private"} {
		if strings.Contains(string(response), secret) {
			t.Fatalf("response echoed command content %q: %s", secret, response)
		}
	}
	if !strings.Contains(string(response), `"reason_code":"unsupported_shell_syntax"`) || !strings.Contains(string(response), `"syntax_code":"unsupported_redirection"`) || !strings.Contains(string(response), `"hint":"`) {
		t.Fatalf("syntax denial response lacks compatibility fields/remediation: %s", response)
	}
	const unknownCategory = "private-command-fragment"
	unknownResponse, err := json.Marshal(socketAuthorizeResponseForDecision(pdp.Decision{
		ReasonCode: pdp.ReasonUnsupportedShellSyntax, SyntaxCode: unknownCategory,
	}, false))
	if err != nil {
		t.Fatal(err)
	}
	unknownAudit := local.decisionEventJSON(socketAuthorizeRequest{
		Tool: "shell", ShellCommand: command,
	}, pdp.DefaultSession, pdp.Decision{
		ReasonCode: pdp.ReasonUnsupportedShellSyntax, SyntaxCode: unknownCategory,
	}, "")
	for surface, data := range map[string][]byte{"response": unknownResponse, "audit": unknownAudit} {
		if strings.Contains(string(data), unknownCategory) {
			t.Fatalf("unknown syntax category leaked into %s: %s", surface, data)
		}
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
