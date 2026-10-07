package invoke

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
)

func TestDaemonV2ConsumesExactArgsContextAndProviderPlanBeforeProvider(t *testing.T) {
	providerInput := json.RawMessage(`{}`)
	sum := sha256.Sum256(providerInput)
	inputDigest := "sha256:" + hex.EncodeToString(sum[:])
	expected := policybundle.Operation{ID: "get-repository", ConnectorID: execConnector, Capability: "repository.read", Action: "read", Resource: "repos/acme/kei", ResourceType: "repository", ResourceID: "acme/kei", InputDigest: inputDigest, ProviderInput: providerInput}
	for _, tc := range []struct {
		name, handle, args, context, approvedArgs, approvedContext string
		allow, replay, expired                                     bool
		wantProviderCalls                                          int
	}{
		{name: "missing handle", args: `{}`, context: `{}`, approvedArgs: `{}`, approvedContext: `{}`},
		{name: "denied whole plan", handle: "opaque-handle", args: `{"note":"approved"}`, context: `{"repository":"acme/kei"}`, approvedArgs: `{"note":"approved"}`, approvedContext: `{"repository":"acme/kei"}`},
		{name: "changed args", handle: "opaque-handle", args: `{"note":"changed"}`, context: `{"repository":"acme/kei"}`, approvedArgs: `{"note":"approved"}`, approvedContext: `{"repository":"acme/kei"}`, allow: true},
		{name: "changed context", handle: "opaque-handle", args: `{"note":"approved"}`, context: `{"repository":"acme/other"}`, approvedArgs: `{"note":"approved"}`, approvedContext: `{"repository":"acme/kei"}`, allow: true},
		{name: "expired handle", handle: "expired-handle", args: `{"note":"approved"}`, context: `{"repository":"acme/kei"}`, approvedArgs: `{"note":"approved"}`, approvedContext: `{"repository":"acme/kei"}`, allow: true, expired: true},
		{name: "successful one-request plan", handle: "opaque-handle", args: `{"note":"approved"}`, context: `{"repository":"acme/kei"}`, approvedArgs: `{"note":"approved"}`, approvedContext: `{"repository":"acme/kei"}`, allow: true, wantProviderCalls: 1},
		{name: "replay", handle: "opaque-handle", args: `{"note":"approved"}`, context: `{"repository":"acme/kei"}`, approvedArgs: `{"note":"approved"}`, approvedContext: `{"repository":"acme/kei"}`, allow: true, replay: true, wantProviderCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			providerCalls, consumeCalls := 0, 0
			used := false
			d := &Daemon{
				Env: Env{ProviderTransport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					providerCalls++
					if req.URL.Host != "api.github.com" {
						t.Fatalf("provider host=%s", req.URL.Host)
					}
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"name":"kei","owner":{"login":"acme"},"description":"","default_branch":"main","private":true}`)), Request: req}, nil
				})},
				Authorize: func(context.Context, DaemonCall) (Grant, error) {
					return Grant{V2Tool: true, HasSession: true, Subject: execUser, AgentID: execAgent, Provider: "github", ConnectorID: execConnector, Capabilities: []string{"repository.read"}, TenantID: execTenant, WorkspaceID: execWorkspace}, nil
				},
				PlanV2: func(_ context.Context, sessionID, tool, agent string, args, contextValues []byte, _ string, _ int) ([]policybundle.Operation, error) {
					if tool != "github.get_issue" || agent != execAgent || len(args) == 0 || len(contextValues) == 0 {
						return nil, errors.New("untrusted route or missing separated context")
					}
					return []policybundle.Operation{expected}, nil
				},
				ValidateV2: func(_ context.Context, handle, sessionID, tool, agent string, args, contextValues []byte, ops []policybundle.Operation, _ string, _ int) error {
					if handle != tc.handle || tc.expired || !tc.allow || tool != "github.get_issue" || agent != execAgent || string(args) != tc.approvedArgs || string(contextValues) != tc.approvedContext || !sameTestOps(ops, []policybundle.Operation{expected}) {
						return errors.New("plan mismatch")
					}
					return nil
				},
				ConsumeV2Plan: func(_ context.Context, handle, sessionID, tool, agent string, args, contextValues []byte, ops []policybundle.Operation, _ string, _ int) error {
					consumeCalls++
					if handle != tc.handle || tc.expired || !tc.allow || string(args) != tc.approvedArgs || string(contextValues) != tc.approvedContext || !sameTestOps(ops, []policybundle.Operation{expected}) {
						return errors.New("authorization mismatch")
					}
					if tc.replay && used {
						return errors.New("replay")
					}
					used = true
					return nil
				},
				UseCredential: func(_ context.Context, sessionID, subject, provider string, fn func(string) error) error {
					if subject != execUser || provider != "github" {
						t.Errorf("credential subject/provider=%q/%q", subject, provider)
					}
					return fn("fake-github-token")
				},
			}
			runs := 1
			if tc.replay {
				runs = 2
			}
			for attempt := 0; attempt < runs; attempt++ {
				body, _ := json.Marshal(daemonRequest{Schema: daemonRequestSchema, SessionID: "ks_test", ToolName: "github.get_issue", PreflightHandle: tc.handle, AgentID: execAgent, Input: json.RawMessage(tc.args), Context: json.RawMessage(tc.context), TraceID: "v4-trace"})
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, DaemonInvokePath, bytes.NewReader(body))
				session.SetHeader(req, "ks_test")
				d.ServeHTTP(rec, req)
				if tc.name == "missing handle" {
					if rec.Code != http.StatusBadRequest {
						t.Fatalf("missing handle status=%d", rec.Code)
					}
					continue
				}
				if rec.Code != http.StatusOK {
					t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
				}
				var got daemonResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				shouldAllow := tc.wantProviderCalls == 1 && attempt == 0
				if (got.Decision == "allow") != shouldAllow {
					t.Fatalf("decision=%s reason=%s provider calls=%d", got.Decision, got.ReasonCode, providerCalls)
				}
			}
			if providerCalls != tc.wantProviderCalls {
				t.Fatalf("provider calls=%d want=%d", providerCalls, tc.wantProviderCalls)
			}
			if tc.wantProviderCalls == 1 {
				wantConsumes := 1
				if tc.replay {
					wantConsumes = 2
				}
				if consumeCalls != wantConsumes {
					t.Fatalf("whole-plan consume calls=%d want %d", consumeCalls, wantConsumes)
				}
			}
		})
	}
}

func sameTestOps(a, b []policybundle.Operation) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Capability != b[i].Capability || a[i].Resource != b[i].Resource || a[i].InputDigest != b[i].InputDigest || !bytes.Equal(a[i].ProviderInput, b[i].ProviderInput) {
			return false
		}
	}
	return true
}

func TestDaemonV2RejectsMixedCallerOperationFields(t *testing.T) {
	providerCalls := 0
	d := &Daemon{Env: Env{ProviderTransport: roundTripFunc(func(*http.Request) (*http.Response, error) { providerCalls++; return nil, nil })}}
	body, _ := json.Marshal(daemonRequest{Schema: daemonRequestSchema, SessionID: "ks_test", ToolName: "github.get_issue", PreflightHandle: "opaque", ConnectorID: execConnector, Capability: "repository.read", Action: "read", Resource: "repos/acme/kei"})
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, DaemonInvokePath, bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest || providerCalls != 0 {
		t.Fatalf("status=%d provider calls=%d", rec.Code, providerCalls)
	}
}
