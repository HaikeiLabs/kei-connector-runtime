package runtime

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWhoAmIRoundTripsWorkspaceID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/whoami" {
			t.Fatalf("unexpected runtime path %q", r.URL.Path)
		}
		fmt.Fprint(w, `{"id":"installation-1","org_id":"org-1","workspace_id":"workspace-9","platform":"discord","status":"active","binding_status":"verified"}`)
	}))
	defer server.Close()

	identity, err := NewRuntimeClient(server.URL, time.Second).WhoAmI(context.Background(), "runtime-token")
	if err != nil {
		t.Fatal(err)
	}
	if identity.WorkspaceID == nil {
		t.Fatal("workspace_id = nil, want \"workspace-9\"")
	}
	if *identity.WorkspaceID != "workspace-9" {
		t.Fatalf("workspace_id = %q, want \"workspace-9\"", *identity.WorkspaceID)
	}
}

func TestWhoAmIOmittedWorkspaceIDStaysNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"installation-1","org_id":"org-1","platform":"discord","status":"active","binding_status":"verified"}`)
	}))
	defer server.Close()

	identity, err := NewRuntimeClient(server.URL, time.Second).WhoAmI(context.Background(), "runtime-token")
	if err != nil {
		t.Fatal(err)
	}
	if identity.WorkspaceID != nil {
		t.Fatalf("workspace_id = %q, want nil", *identity.WorkspaceID)
	}
}

func TestRuntimeClientFailsClosedOnRejectedRuntimeToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	if _, err := NewRuntimeClient(server.URL, time.Second).WhoAmI(context.Background(), "bad-token"); err == nil {
		t.Fatal("expected rejected runtime token to fail")
	}
}
