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
)

func TestDaemonV2ConsumesExactInputPlanBeforeProvider(t *testing.T) {
	canonical := []byte(`{}`)
	sum := sha256.Sum256(canonical)
	goodDigest := "sha256:" + hex.EncodeToString(sum[:])
	expected := policybundle.Operation{ConnectorID: execConnector, Capability: "repository.read", Action: "read", Resource: "repos/acme/kei", ResourceType: "repository", ResourceID: "acme/kei", InputDigest: goodDigest}
	for _, tc := range []struct {
		name              string
		handle            string
		input             string
		allow             bool
		replay            bool
		expired           bool
		wantProviderCalls int
	}{
		{name: "missing handle", handle: "", input: `{}`, allow: true},
		{name: "denied consume", handle: "opaque-handle", input: `{}`, allow: false},
		{name: "changed input with same target", handle: "opaque-handle", input: `{"filter":"changed"}`, allow: true},
		{name: "expired handle", handle: "expired-handle", input: `{}`, allow: true, expired: true},
		{name: "successful consume", handle: "opaque-handle", input: `{}`, allow: true, wantProviderCalls: 1},
		{name: "replay", handle: "opaque-handle", input: `{}`, allow: true, replay: true, wantProviderCalls: 1},
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
				ValidateV2: func(_ context.Context, handle, tool, agent string, ops []policybundle.Operation, _ string, _ int) error {
					if handle != tc.handle || tc.expired || tool != "github.review_pr" || agent != execAgent || len(ops) != 1 || ops[0].ConnectorID != expected.ConnectorID || ops[0].Capability != expected.Capability || ops[0].Resource != expected.Resource || ops[0].InputDigest != expected.InputDigest {
						return errors.New("plan mismatch")
					}
					return nil
				},
				PlanV2: func(_ context.Context, tool, agent string, args []byte, _ string, _ int) ([]policybundle.Operation, error) {
					if tool != "github.review_pr" || agent != execAgent {
						return nil, errors.New("untrusted route")
					}
					digest := sha256.Sum256(args)
					op := expected
					op.InputDigest = "sha256:" + hex.EncodeToString(digest[:])
					return []policybundle.Operation{op}, nil
				},
				ConsumeV2: func(_ context.Context, handle, tool, agent string, op policybundle.Operation, _ string, _ int) error {
					consumeCalls++
					if handle != tc.handle || tc.expired || tool != "github.review_pr" || agent != execAgent || !tc.allow || op.ConnectorID != expected.ConnectorID || op.Capability != expected.Capability || op.Resource != expected.Resource || op.InputDigest != expected.InputDigest {
						return errors.New("authorization mismatch")
					}
					if tc.replay && used {
						return errors.New("replay")
					}
					used = true
					return nil
				},
				UseCredential: func(_ context.Context, subject, provider string, fn func(string) error) error {
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
				body, _ := json.Marshal(daemonRequest{Schema: daemonRequestSchema, ToolName: "github.review_pr", PreflightHandle: tc.handle, AgentID: execAgent, Input: json.RawMessage(tc.input), TraceID: "v2-trace"})
				rec := httptest.NewRecorder()
				d.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, DaemonInvokePath, bytes.NewReader(body)))
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
			if tc.name == "successful consume" && consumeCalls != 1 {
				t.Fatalf("consume calls=%d want 1", consumeCalls)
			}
		})
	}
}

func TestDaemonV2RejectsMixedCallerOperationFields(t *testing.T) {
	providerCalls := 0
	d := &Daemon{Env: Env{ProviderTransport: roundTripFunc(func(*http.Request) (*http.Response, error) { providerCalls++; return nil, nil })}}
	body, _ := json.Marshal(daemonRequest{Schema: daemonRequestSchema, ToolName: "github.review_pr", PreflightHandle: "opaque", ConnectorID: execConnector, Capability: "repository.read", Action: "read", Resource: "repos/acme/kei"})
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, DaemonInvokePath, bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest || providerCalls != 0 {
		t.Fatalf("status=%d provider calls=%d", rec.Code, providerCalls)
	}
}
