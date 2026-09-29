package tito

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

const token = "fake-tito-token-000000001"

func routes(t *testing.T) *connectortest.Routes {
	r := connectortest.NewRoutes()
	r.Handle("api.tito.io", func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Token token="+token {
			t.Errorf("authorization = %q", req.Header.Get("Authorization"))
		}
		switch req.URL.Path {
		case "/v3/acme/events/past":
			_, _ = io.WriteString(w, `{"events":[{"slug":"conf","title":"Conf","url":"https://ti.to/acme/conf","start_date":"2026-10-01","end_date":"2026-10-02","live":true}],"meta":{"next_page":null}}`)
		case "/v3/acme/conf/tickets":
			_, _ = io.WriteString(w, `{"tickets":[{"state":"complete","release_title":"GA","name":"FAKE-ATTENDEE","email":"attendee@example.test","phone_number":"FAKE-PHONE"}],"meta":{"next_page":null}}`)
		default:
			http.NotFound(w, req)
		}
	})
	return r
}

func TestEventListUsesTheSharedSecretToken(t *testing.T) {
	call := connectortest.Call(routes(t), contract.ProviderTito, "event.list", contract.ActionRead, "tito/acme/events", input.TitoEventList{Status: "past"}, token)
	got, err := Connector{}.Execute(context.Background(), call)
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(got); !strings.Contains(string(raw), `"title":"Conf"`) {
		t.Fatalf("result = %s", raw)
	}
}

// Attendee PII never leaves the runtime: ticket.summary returns counts only.
func TestTicketSummaryCarriesNoAttendeePII(t *testing.T) {
	call := connectortest.Call(routes(t), contract.ProviderTito, "ticket.summary", contract.ActionRead, "tito/acme/events/conf/ticket-summary", input.Empty{}, token)
	got, err := Connector{}.Execute(context.Background(), call)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(got)
	for _, pii := range []string{"FAKE-ATTENDEE", "attendee@example.test", "FAKE-PHONE"} {
		if strings.Contains(string(raw), pii) {
			t.Fatalf("summary leaked %q: %s", pii, raw)
		}
	}
	if !strings.Contains(string(raw), `"total":1`) {
		t.Fatalf("summary = %s", raw)
	}
}
