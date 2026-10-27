package connectorruntime

import (
	"net/http"
	"strings"
	"testing"
)

// HAI-724 slice 2: `connector invoke` and the POST /v1/connectors:invoke
// route are deleted (the runtime is decision-only; ADR-039). The serve
// daemon must 404 the route — including in identity mode, where the invoker
// used to be wired — and the CLI must treat `connector` as an unknown
// command.

func TestConnectorInvokeRouteIsRemoved(t *testing.T) {
	cfg := identityServeConfig(t, "https://kei.example")
	local, err := newServeLocalPDP(cfg, serveSeams{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.Close)
	_, h := newServeHandlers(cfg, local)
	c, _ := serveSocketForTest(t, h)
	if r := socketDo(t, c, http.MethodPost, "/v1/connectors:invoke", `{"schema":"kei.connector-invoke-request/v1"}`); r.code != http.StatusNotFound {
		t.Fatalf("POST /v1/connectors:invoke = %d, want 404:\n%s", r.code, r.dump)
	}
}

func TestConnectorInvokeCommandIsRemoved(t *testing.T) {
	var code int
	_, stderr := captureFDs(t, func() { code = Main("test", []string{"connector", "invoke"}) })
	if code != 1 || !strings.Contains(stderr, `unknown command "connector"`) {
		t.Fatalf("exit %d, want 1 with an unknown-command error. stderr:\n%s", code, stderr)
	}
}
