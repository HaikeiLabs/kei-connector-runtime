package gmail

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-contracts/providers"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/connectortest"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

const token = "fake-gmail-token"

func routes(t *testing.T, wantFormat string) *connectortest.Routes {
	r := connectortest.NewRoutes()
	r.Handle("gmail.googleapis.com", func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("authorization = %q", req.Header.Get("Authorization"))
		}
		switch req.URL.Path {
		case "/gmail/v1/users/me/messages":
			if q := req.URL.Query(); q.Get("q") != "from:alice" || q.Get("maxResults") != "5" {
				t.Errorf("search query = %v", q)
			}
			_, _ = io.WriteString(w, `{"messages":[{"id":"m-1","threadId":"th-1"}],"nextPageToken":"p-2"}`)
		case "/gmail/v1/users/me/messages/m-1":
			if f := req.URL.Query().Get("format"); f != wantFormat {
				t.Errorf("format = %q, want %q", f, wantFormat)
			}
			_, _ = io.WriteString(w, `{"id":"m-1","threadId":"th-1","snippet":"hi","internalDate":"1700000000123","payload":{"mimeType":"text/plain","headers":[{"name":"Subject","value":"Hello"}],"body":{"data":"Ym9keSB0ZXh0"}}}`)
		default:
			http.NotFound(w, req)
		}
	})
	return r
}

func TestSearchReturnsMetadataAndSnippetOnly(t *testing.T) {
	r := routes(t, "metadata")
	call := connectortest.Call(r, contract.ProviderGmail, "message.search", contract.ActionRead, "gmail/messages", input.GmailMessageSearch{Query: "from:alice", PageSize: 5}, token)
	got, err := Connector{}.Execute(context.Background(), call)
	if err != nil {
		t.Fatal(err)
	}
	page := got.(providers.GmailMessagePage)
	if len(page.Messages) != 1 || page.Messages[0].Subject != "Hello" || page.Messages[0].Body != "" || page.NextPageToken != "p-2" {
		t.Fatalf("page = %+v", page)
	}
}

// The body is returned only when the connector opts in with
// gmail_include_body; otherwise it is never even fetched.
func TestGetReturnsBodyOnlyWithPolicyOptIn(t *testing.T) {
	call := connectortest.Call(routes(t, "metadata"), contract.ProviderGmail, "message.get", contract.ActionRead, "gmail/messages/m-1", input.GmailMessageGet{}, token)
	got, err := Connector{}.Execute(context.Background(), call)
	if err != nil || got.(providers.GmailMessage).Body != "" {
		t.Fatalf("default get = %+v, %v", got, err)
	}
	call = connectortest.Call(routes(t, "full"), contract.ProviderGmail, "message.get", contract.ActionRead, "gmail/messages/m-1", input.GmailMessageGet{}, token)
	call.Meta.Policy.GmailIncludeBody = true
	got, err = Connector{}.Execute(context.Background(), call)
	if err != nil || got.(providers.GmailMessage).Body != "body text" {
		t.Fatalf("opted-in get = %+v, %v", got, err)
	}
}

func TestRejectsInputForAnotherCapability(t *testing.T) {
	r := connectortest.NewRoutes()
	call := connectortest.Call(r, contract.ProviderGmail, "message.search", contract.ActionRead, "gmail/messages", input.DriveSearch{Query: "x"}, token)
	if _, err := (Connector{}).Execute(context.Background(), call); !errors.Is(err, connector.ErrInput) || r.Count() != 0 {
		t.Fatalf("err = %v, requests = %d", err, r.Count())
	}
}
