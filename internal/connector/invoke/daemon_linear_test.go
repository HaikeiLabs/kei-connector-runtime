package invoke

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
)

// Per-user Linear writes reach the runtime through the serve daemon's
// POST /v1/connectors:invoke JSON body, the same request a harness sends over
// the Unix socket. These tests drive that route; the CLI flag tests in
// execute_test.go cover the direct (shared connector) path.

const daemonLinearSession = "ks_linear_write"

func linearWriteDaemon(t *testing.T, fake *fakeLinearGraphQL, providerCalls *int) *Daemon {
	return &Daemon{
		Env: Env{ProviderTransport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			*providerCalls++
			if req.URL.Host != "api.linear.app" {
				t.Errorf("provider request = %s", req.URL)
			}
			response := httptest.NewRecorder()
			fake.serve(response, req)
			return response.Result(), nil
		})},
		Authorize: func(_ context.Context, call DaemonCall) (Grant, error) {
			if call.Session != daemonLinearSession || call.ConnectorID != execConnector {
				t.Errorf("policy decision call = %+v", call)
			}
			return Grant{Allow: true, HasSession: true, Subject: execUser, Provider: "linear", ConnectorID: execConnector,
				Capabilities: []string{"team.read", "issue.read", "issue.create", "comment.create"},
				TenantID:     execTenant, WorkspaceID: execWorkspace}, nil
		},
		UseCredential: func(_ context.Context, gotSession, subject, provider string, fn func(string) error) error {
			if gotSession != daemonLinearSession || subject != execUser || provider != "linear" {
				t.Errorf("credential scope = %q/%q/%q", gotSession, subject, provider)
			}
			return fn(execToken)
		},
	}
}

func serveDaemonLinear(t *testing.T, d *Daemon, body string) daemonResponse {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, DaemonInvokePath, strings.NewReader(body))
	session.SetHeader(request, daemonLinearSession)
	response := httptest.NewRecorder()
	d.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("invoke status=%d body=%s", response.Code, response.Body.String())
	}
	var got daemonResponse
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestDaemonLinearIssueCreateFromJSONBody(t *testing.T) {
	fake := &fakeLinearGraphQL{t: t, answers: map[string]string{
		"TeamID": `{"data":{"teams":{"nodes":[{"id":"` + linearTeamUUID + `","key":"ENG"}]}}}`,
	}}
	providerCalls := 0
	d := linearWriteDaemon(t, fake, &providerCalls)
	transport := d.Env.ProviderTransport
	d.Env.ProviderTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if len(fake.operations) == 1 {
			id := fake.inputsAfter(req)
			fake.answers["IssueCreate"] = `{"data":{"issueCreate":{"success":true,"issue":{"id":"` + id + `","identifier":"ENG-42","url":"https://linear.app/acme/issue/ENG-42","team":{"key":"ENG"}}}}}`
		}
		return transport.RoundTrip(req)
	})
	body := `{"schema":"kei.connector-invoke-request/v1","connector_id":"` + execConnector + `","capability":"issue.create","action":"create",` +
		`"resource":"linear/team/ENG","idempotency_key":"idem-1",` +
		`"input":{"team_id":"ENG","title":"Login crashes","description":"private-bug-body","priority":2}}`
	got := serveDaemonLinear(t, d, body)
	if got.Decision != "allow" {
		t.Fatalf("decision=%s reason=%s %s", got.Decision, got.ReasonCode, got.Reason)
	}
	if ops := strings.Join(fake.operations, ","); ops != "TeamID,IssueCreate" {
		t.Fatalf("linear operations = %s (the mutation must run exactly once)", ops)
	}
	var result map[string]any
	if err := json.Unmarshal(got.Result, &result); err != nil {
		t.Fatal(err)
	}
	if result["identifier"] != "ENG-42" || result["team_key"] != "ENG" || fake.inputs[1]["id"] != result["id"] {
		t.Fatalf("result = %v, issueCreate input = %v", result, fake.inputs[1])
	}
}

func TestDaemonLinearCommentCreateFromJSONBody(t *testing.T) {
	fake := &fakeLinearGraphQL{t: t, answers: map[string]string{}}
	providerCalls := 0
	d := linearWriteDaemon(t, fake, &providerCalls)
	transport := d.Env.ProviderTransport
	d.Env.ProviderTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		id := fake.inputsAfter(req)
		fake.answers["CommentCreate"] = `{"data":{"commentCreate":{"success":true,"comment":{"id":"` + id + `","url":"https://linear.app/acme/issue/ENG-42#comment-1","issue":{"id":"issue-uuid"}}}}}`
		return transport.RoundTrip(req)
	})
	body := `{"schema":"kei.connector-invoke-request/v1","connector_id":"` + execConnector + `","capability":"comment.create","action":"create",` +
		`"resource":"linear/issue/ENG-42","idempotency_key":"idem-1","input":{"issue_id":"ENG-42","body":"private-comment-body"}}`
	got := serveDaemonLinear(t, d, body)
	if got.Decision != "allow" || strings.Join(fake.operations, ",") != "CommentCreate" {
		t.Fatalf("decision=%s reason=%s operations=%v", got.Decision, got.ReasonCode, fake.operations)
	}
	if strings.Contains(string(got.Result), "private-comment-body") {
		t.Fatalf("result carries the comment body: %s", got.Result)
	}
}

func TestDaemonLinearWriteDenials(t *testing.T) {
	cases := []struct {
		name, fields, reason string
	}{
		{"no idempotency key", `"capability":"issue.create","action":"create","resource":"linear/team/ENG","input":{"team_id":"ENG","title":"t"}`, "input_invalid"},
		{"team_id differs from resource", `"capability":"issue.create","action":"create","resource":"linear/team/ENG","idempotency_key":"idem-1","input":{"team_id":"OPS","title":"t"}`, "input_invalid"},
		{"workspace argument", `"capability":"issue.create","action":"create","resource":"linear/team/ENG","idempotency_key":"idem-1","input":{"team_id":"ENG","title":"t","workspace_id":"w"}`, "input_invalid"},
		{"comment on another issue", `"capability":"comment.create","action":"create","resource":"linear/issue/ENG-42","idempotency_key":"idem-1","input":{"issue_id":"ENG-7","body":"b"}`, "input_invalid"},
		{"action mismatch", `"capability":"issue.create","action":"read","resource":"linear/team/ENG","idempotency_key":"idem-1","input":{"team_id":"ENG","title":"t"}`, "descriptor_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeLinearGraphQL{t: t, answers: map[string]string{}}
			providerCalls := 0
			d := linearWriteDaemon(t, fake, &providerCalls)
			got := serveDaemonLinear(t, d, `{"schema":"kei.connector-invoke-request/v1","connector_id":"`+execConnector+`",`+tc.fields+`}`)
			if got.Decision != "deny" || got.ReasonCode != tc.reason || providerCalls != 0 {
				t.Fatalf("decision=%s reason=%s provider calls=%d, want deny %s before any provider call", got.Decision, got.ReasonCode, providerCalls, tc.reason)
			}
		})
	}
}
