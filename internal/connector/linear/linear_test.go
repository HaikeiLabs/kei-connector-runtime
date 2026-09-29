package linear

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-contracts/providers"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/connectortest"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

func TestIssueReadUsesTheOAuthToken(t *testing.T) {
	r := connectortest.NewRoutes()
	r.Handle("api.linear.app", func(w http.ResponseWriter, req *http.Request) {
		if !strings.Contains(req.Header.Get("Authorization"), "fake-linear-token") {
			t.Errorf("authorization = %q", req.Header.Get("Authorization"))
		}
		_, _ = io.WriteString(w, `{"data":{"issue":{"id":"i-1","identifier":"ENG-1","title":"Fix it","state":{"name":"Todo"},"team":{"key":"ENG"},"project":null}}}`)
	})
	call := connectortest.Call(r, contract.ProviderLinear, "issue.read", contract.ActionRead, "linear/issue/ENG-1", input.Empty{}, "fake-linear-token")
	got, err := Connector{}.Execute(context.Background(), call)
	if err != nil {
		t.Fatal(err)
	}
	if issue := got.(providers.LinearIssue); issue.Identifier != "ENG-1" || issue.State != "Todo" {
		t.Fatalf("issue = %+v", issue)
	}
}
