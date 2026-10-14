package mcproute

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ADR-036 §4.9: if an upstream response contains the released credential,
// the route drops it and denies with -31502 credential_echo. Nothing of the
// response reaches the harness.

// echoToken has a "/" so a JSON encoder may write it as "\/".
const echoToken = "ct_echo/secret-token-for-test-581"

func echoRig(t *testing.T, onCall http.HandlerFunc) (*Handler, string, *listingUpstream, *recordingAuditor) {
	t.Helper()
	creds := &fakeCredentials{}
	h, key, up := credentialRig(t, creds, "oauth", onCall)
	creds.cred = goodCredential(up.srv.URL)
	creds.cred.AccessToken = echoToken
	aud := &recordingAuditor{}
	h.config.Auditor = aud
	return h, key, up, aud
}

func TestMCPRouteCredentialEcho_JSONResponseIsDropped(t *testing.T) {
	for name, text := range map[string]string{
		"raw":            echoToken,
		"slash escaped":  strings.ReplaceAll(echoToken, "/", `\/`),
		"unicode escape": strings.ReplaceAll(echoToken, "c", `\u0063`),
	} {
		t.Run(name, func(t *testing.T) {
			h, key, _, aud := echoRig(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"leak: %s"}]}}`, text)
			})

			w := httptest.NewRecorder()
			h.ServeHTTP(w, routeRequest(key, callBody("search")))

			assertDenied(t, w, -31502, "credential_echo")
			if strings.Contains(w.Body.String(), "leak") {
				t.Fatalf("the echoing response reached the harness: %s", w.Body.Bytes())
			}
			if rec := aud.only(t); rec.ReasonCode != "credential_echo" {
				t.Fatalf("audit reason %q, want credential_echo", rec.ReasonCode)
			}
		})
	}
}

func TestMCPRouteCredentialEcho_SSEStreamEndsBeforeTheEchoingEvent(t *testing.T) {
	h, key, _, _ := echoRig(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n\n")
		fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"%s\"}]}}\n\n", strings.ReplaceAll(echoToken, "/", `\/`))
	})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("search")))

	out := w.Body.String()
	if !strings.Contains(out, "notifications/progress") {
		t.Fatalf("the clean event before the echo was not relayed: %s", out)
	}
	if strings.Contains(out, "secret-token-for-test-581") {
		t.Fatalf("the echoing event reached the harness: %s", out)
	}
	if !strings.Contains(out, `"credential_echo"`) {
		t.Fatalf("the stream does not end with credential_echo: %s", out)
	}
}

func TestMCPRouteCredentialEcho_ListingIsDropped(t *testing.T) {
	h, key, up, _ := echoRig(t, nil)
	leaky := namedTool("search")
	leaky["description"] = "use token " + echoToken
	up.setTools(leaky)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, listBody))

	assertDenied(t, w, -31502, "credential_echo")
	if strings.Contains(w.Body.String(), "secret-token") {
		t.Fatalf("the echoing listing reached the harness: %s", w.Body.Bytes())
	}
}

func TestMCPRouteCredentialEcho_CleanResponsePasses(t *testing.T) {
	h, key, up, _ := echoRig(t, nil)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, routeRequest(key, callBody("search")))

	if up.calls.Load() != 1 || strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("a clean response was not relayed: %s", w.Body.Bytes())
	}
}
