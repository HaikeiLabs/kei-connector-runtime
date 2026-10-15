package invoke

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/credentials/obo"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

// HAI-669 (R2), ADR-036 amendment decision 3: the harness hands the user's
// Entra token to POST /v1/connectors:invoke as user_assertion, per call. The
// daemon checks it against the session subject before anything else runs
// for an on_behalf_of connector, and it is never echoed, logged or audited.

const assertionCanary = "eyJhbGciOiJub25lIn0.assertion-canary-5c1e.sig"

func oboConnector() *policybundle.Connector {
	c := crmDescriptor()
	c.CredentialSource, c.AccountModel, c.CredentialRef = string(contract.CredentialSourceOnBehalfOf), string(contract.AccountModelPerUser), ""
	c.OnBehalfOf = &contract.OnBehalfOf{
		TenantID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", ClientID: "11111111-2222-3333-4444-555555555555",
		Resource: "https://api.example.com", Scopes: []string{"https://api.example.com/Data.Read"},
		ClientSecretRef: "kei://connectors/" + execConnector + "/client_secret",
	}
	return c
}

// fakeChecker records CheckAssertion calls and answers err.
type fakeChecker struct {
	calls [][3]string
	err   error
}

func (f *fakeChecker) CheckAssertion(subject, connectorID, assertion string) error {
	f.calls = append(f.calls, [3]string{subject, connectorID, assertion})
	return f.err
}

func (rig *descriptorRig) invokeWithAssertion(assertion string) (daemonResponse, string) {
	rig.t.Helper()
	body, _ := json.Marshal(daemonRequest{Schema: daemonRequestSchema, ConnectorID: execConnector, Capability: "http.get", Action: "read", Resource: "/leads/42", Input: json.RawMessage(`{"path":"/leads/42"}`), TraceID: "trace-hai-669", AgentID: execAgent, UserAssertion: assertion})
	rec := httptest.NewRecorder()
	rig.daemon.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, DaemonInvokePath, bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		rig.t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out daemonResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		rig.t.Fatal(err)
	}
	return out, rec.Body.String()
}

func (rig *descriptorRig) assertNoAssertionLeak(bodies ...string) {
	rig.t.Helper()
	for name, text := range map[string]string{"socket response": strings.Join(bodies, "\n"), "audit": strings.Join(rig.audit, "\n"), "log": rig.logs.String()} {
		if strings.Contains(text, assertionCanary) || strings.Contains(text, "assertion-canary") {
			rig.t.Fatalf("%s leaked the user assertion:\n%s", name, text)
		}
	}
}

func (rig *descriptorRig) noProviderCalls() {
	rig.t.Helper()
	rig.mu.Lock()
	defer rig.mu.Unlock()
	if len(rig.crmRequests) != 0 {
		rig.t.Fatalf("provider called %d times on a deny", len(rig.crmRequests))
	}
}

func TestDaemonOnBehalfOfRequiresAUserAssertion(t *testing.T) {
	rig := newDescriptorRig(t)
	checker := &fakeChecker{}
	rig.daemon.Assertions = checker
	rig.grant.Connector = oboConnector()
	out, _ := rig.invokeWithAssertion("")
	if out.Decision != "deny" || out.ReasonCode != "assertion_required" {
		t.Fatalf("decision=%s reason=%s", out.Decision, out.ReasonCode)
	}
	if len(checker.calls) != 0 {
		t.Fatal("checked an absent assertion")
	}
	rig.noProviderCalls()
}

func TestDaemonOnBehalfOfChecksTheAssertionAgainstTheSessionSubject(t *testing.T) {
	rig := newDescriptorRig(t)
	checker := &fakeChecker{err: &obo.Error{Code: "assertion_subject_mismatch", Reason: "the user token is not the session subject's"}}
	rig.daemon.Assertions = checker
	rig.grant.Connector = oboConnector()
	out, body := rig.invokeWithAssertion(assertionCanary)
	if out.Decision != "deny" || out.ReasonCode != "assertion_subject_mismatch" {
		t.Fatalf("decision=%s reason=%s", out.Decision, out.ReasonCode)
	}
	if len(checker.calls) != 1 || checker.calls[0] != [3]string{execUser, execConnector, assertionCanary} {
		t.Fatalf("CheckAssertion calls = %q", checker.calls)
	}
	rig.noProviderCalls()
	rig.assertNoAssertionLeak(body)
}

// A matching assertion passes the gate; executing on_behalf_of connectors
// (injecting the exchanged token) is HAI-669 R3, so the call still denies
// without reaching the provider.
func TestDaemonOnBehalfOfAcceptsAMatchingAssertion(t *testing.T) {
	rig := newDescriptorRig(t)
	checker := &fakeChecker{}
	rig.daemon.Assertions = checker
	rig.grant.Connector = oboConnector()
	out, body := rig.invokeWithAssertion(assertionCanary)
	if len(checker.calls) != 1 {
		t.Fatalf("CheckAssertion calls = %d, want 1", len(checker.calls))
	}
	if out.Decision != "deny" || out.ReasonCode != "credential_source_not_supported" {
		t.Fatalf("decision=%s reason=%s", out.Decision, out.ReasonCode)
	}
	rig.noProviderCalls()
	rig.assertNoAssertionLeak(body)
}

func TestDaemonOnBehalfOfWithoutACheckerFailsClosed(t *testing.T) {
	rig := newDescriptorRig(t)
	rig.grant.Connector = oboConnector()
	out, body := rig.invokeWithAssertion(assertionCanary)
	if out.Decision != "deny" || out.ReasonCode != "credential_source_not_supported" {
		t.Fatalf("decision=%s reason=%s", out.Decision, out.ReasonCode)
	}
	rig.noProviderCalls()
	rig.assertNoAssertionLeak(body)
}

// An assertion is refused for any connector that does not exchange one: it
// is never silently accepted, held or forwarded.
func TestDaemonRefusesAUserAssertionForOtherConnectors(t *testing.T) {
	rig := newDescriptorRig(t)
	checker := &fakeChecker{}
	rig.daemon.Assertions = checker
	out, body := rig.invokeWithAssertion(assertionCanary)
	if out.Decision != "deny" || out.ReasonCode != "assertion_not_applicable" {
		t.Fatalf("decision=%s reason=%s", out.Decision, out.ReasonCode)
	}
	if len(checker.calls) != 0 {
		t.Fatal("checked an assertion for a non-on_behalf_of connector")
	}
	rig.noProviderCalls()
	rig.assertNoAssertionLeak(body)
}

func TestDaemonRefusesAnOversizedUserAssertion(t *testing.T) {
	rig := newDescriptorRig(t)
	checker := &fakeChecker{}
	rig.daemon.Assertions = checker
	rig.grant.Connector = oboConnector()
	out, body := rig.invokeWithAssertion(assertionCanary + strings.Repeat("A", maxUserAssertionBytes))
	if out.Decision != "deny" || out.ReasonCode != "assertion_invalid" {
		t.Fatalf("decision=%s reason=%s", out.Decision, out.ReasonCode)
	}
	if len(checker.calls) != 0 {
		t.Fatal("checked an oversized assertion")
	}
	rig.assertNoAssertionLeak(body)
}
