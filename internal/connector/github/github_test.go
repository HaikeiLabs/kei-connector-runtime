package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/connectortest"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

func TestRepositoryReadUsesTheOAuthToken(t *testing.T) {
	r := connectortest.NewRoutes()
	r.Handle("api.github.com", func(w http.ResponseWriter, req *http.Request) {
		if !strings.Contains(req.Header.Get("Authorization"), "fake-github-token") {
			t.Errorf("authorization = %q", req.Header.Get("Authorization"))
		}
		_, _ = io.WriteString(w, `{"name":"kei","owner":{"login":"acme"},"description":"d","default_branch":"main","private":true}`)
	})
	call := connectortest.Call(r, contract.ProviderGitHub, "repository.read", contract.ActionRead, "repos/acme/kei", input.Empty{}, "fake-github-token")
	got, err := Connector{}.Execute(context.Background(), call)
	raw, _ := json.Marshal(got)
	if err != nil || !strings.Contains(string(raw), `"default_branch":"main"`) {
		t.Fatalf("repository.read = %s, %v", raw, err)
	}
}
