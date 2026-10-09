package invoke

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
)

func TestV2DriveListFilesRoutesTrustedPlanToReadOnlyGoogleProvider(t *testing.T) {
	const (
		sessionID = "ks_drive_list"
		driveID   = "0AFx"
	)
	providerInput := json.RawMessage(`{"limit":2,"mime_type":"text/plain","query":"plan"}`)
	providerCalls := 0
	d := &Daemon{
		Env: Env{ProviderTransport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			providerCalls++
			if req.Method != http.MethodGet || req.URL.Host != "www.googleapis.com" || req.URL.Path != "/drive/v3/files" {
				t.Errorf("Drive request = %s %s", req.Method, req.URL)
			}
			if req.URL.Query().Get("driveId") != driveID || req.URL.Query().Get("corpora") != "drive" ||
				req.URL.Query().Get("supportsAllDrives") != "true" || req.URL.Query().Get("pageToken") != "" {
				t.Errorf("Drive request has wrong scope or pagination: %v", req.URL.Query())
			}
			if req.Header.Get("Authorization") != "Bearer fixture-google-token" {
				t.Errorf("provider OAuth header was not supplied by session credential boundary")
			}
			response := httptest.NewRecorder()
			_, _ = io.WriteString(response, `{"files":[{"id":"f-1","driveId":"0AFx","name":"Plan","mimeType":"text/plain"},{"id":"f-2","driveId":"0AFx","name":"Plan doc","mimeType":"application/vnd.google-apps.document"},{"id":"f-3","driveId":"other","name":"Plan external","mimeType":"text/plain","content":"private"}]}`)
			return response.Result(), nil
		})},
		Authorize: func(_ context.Context, call DaemonCall) (Grant, error) {
			if call.ToolName != "drive.list_files" || call.AgentID != execAgent {
				t.Errorf("policy decision call = %+v", call)
			}
			return Grant{V2Tool: true, HasSession: true, Subject: execUser, AgentID: execAgent,
				Provider: "google_drive", ConnectorID: execConnector, Capabilities: []string{"drive.search"},
				TenantID: execTenant, WorkspaceID: execWorkspace}, nil
		},
		PlanV2: func(_ context.Context, gotSession, tool, agent string, args, contextValues []byte, _ string, _ int) ([]policybundle.Operation, error) {
			if gotSession != sessionID || tool != "drive.list_files" || agent != execAgent ||
				string(args) != `{"limit":2,"mime_type":"text/plain","query":"plan"}` ||
				string(contextValues) != `{"drive_id":"0AFx"}` {
				return nil, io.ErrUnexpectedEOF
			}
			return []policybundle.Operation{{ID: "list-files", ConnectorID: execConnector, Capability: "drive.search", Action: "read",
				Resource: "drive/" + driveID, InputDigest: sha256Digest(providerInput), ProviderInput: providerInput}}, nil
		},
		ValidateV2: func(context.Context, string, string, string, string, []byte, []byte, []policybundle.Operation, string, int) error {
			return nil
		},
		ConsumeV2Plan: func(context.Context, string, string, string, string, []byte, []byte, []policybundle.Operation, string, int) error {
			return nil
		},
		UseCredential: func(_ context.Context, gotSession, subject, provider string, fn func(string) error) error {
			if gotSession != sessionID || subject != execUser || provider != "google_drive" {
				t.Errorf("credential scope = %q/%q/%q", gotSession, subject, provider)
			}
			return fn("fixture-google-token")
		},
	}
	body, _ := json.Marshal(daemonRequest{Schema: daemonRequestSchema, SessionID: sessionID, ToolName: "drive.list_files",
		PreflightHandle: "opaque-preflight", AgentID: execAgent, Input: json.RawMessage(`{"limit":2,"mime_type":"text/plain","query":"plan"}`),
		Context: json.RawMessage(`{"drive_id":"0AFx"}`), TraceID: "trace-drive-list"})
	request := httptest.NewRequest(http.MethodPost, DaemonInvokePath, strings.NewReader(string(body)))
	session.SetHeader(request, sessionID)
	response := httptest.NewRecorder()
	d.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("invoke status=%d body=%s", response.Code, response.Body.String())
	}
	var got daemonResponse
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Decision != "allow" || providerCalls != 1 {
		t.Fatalf("decision=%s reason=%s provider calls=%d", got.Decision, got.ReasonCode, providerCalls)
	}
	result := string(got.Result)
	if !strings.Contains(result, `"f-1"`) || strings.Contains(result, `"f-2"`) || strings.Contains(result, `"f-3"`) || strings.Contains(result, "private") {
		t.Fatalf("normalized result = %s", result)
	}
}
