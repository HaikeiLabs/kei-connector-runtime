package runtime_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// authorizeWithBody posts body to /v1/authorize in a fresh named session and
// returns the response code, the body and every audit event emitted.
func authorizeWithBody(t *testing.T, body string) (int, string, []map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var events []map[string]any
	emit := func(data json.RawMessage) {
		var e map[string]any
		_ = json.Unmarshal(data, &e)
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}
	_, h := multiSessionPDP(t, &perSubjectI11{}, emit)
	id := createSession(t, h, "ext-alice")
	rec := sessionRequest(h, http.MethodPost, "/v1/authorize", id, body)
	mu.Lock()
	defer mu.Unlock()
	return rec.Code, rec.Body.String(), append([]map[string]any(nil), events...)
}

// TestAuthorizeAuditsCallerMetadata covers HAI-527: the optional caller object
// of kei.authorize-request/v1 (kei-connector-contracts authorizerequest) is
// accepted and recorded on the decision event; a request without it is
// unchanged and its event carries no caller fields (unknown).
func TestAuthorizeAuditsCallerMetadata(t *testing.T) {
	t.Run("recorded when sent", func(t *testing.T) {
		code, out, events := authorizeWithBody(t, `{"schema":"kei.authorize-request/v1","tool":"web_search","caller":{"harness":"openwebui","origin":"automation","session_ref":"chat:8f3a-2b"}}`)
		if code != http.StatusOK || len(events) != 1 {
			t.Fatalf("status = %d events = %d body = %s", code, len(events), out)
		}
		e := events[0]
		if e["caller_harness"] != "openwebui" || e["caller_origin"] != "automation" || e["caller_session_ref"] != "chat:8f3a-2b" {
			t.Errorf("event caller fields = %v %v %v", e["caller_harness"], e["caller_origin"], e["caller_session_ref"])
		}
	})

	t.Run("a partial caller records only what was sent", func(t *testing.T) {
		code, _, events := authorizeWithBody(t, `{"schema":"kei.authorize-request/v1","tool":"web_search","caller":{"origin":"interactive"}}`)
		if code != http.StatusOK || len(events) != 1 {
			t.Fatalf("status = %d events = %d", code, len(events))
		}
		if events[0]["caller_origin"] != "interactive" {
			t.Errorf("caller_origin = %v", events[0]["caller_origin"])
		}
		for _, key := range []string{"caller_harness", "caller_session_ref"} {
			if _, ok := events[0][key]; ok {
				t.Errorf("%s present, want omitted", key)
			}
		}
	})

	t.Run("absent stays unknown", func(t *testing.T) {
		code, _, events := authorizeWithBody(t, `{"schema":"kei.authorize-request/v1","tool":"web_search"}`)
		if code != http.StatusOK || len(events) != 1 {
			t.Fatalf("status = %d events = %d", code, len(events))
		}
		for _, key := range []string{"caller_harness", "caller_origin", "caller_session_ref"} {
			if _, ok := events[0][key]; ok {
				t.Errorf("%s present, want omitted", key)
			}
		}
	})

	for name, caller := range map[string]string{
		"origin outside the closed set": `{"origin":"fake-secret-marker"}`,
		"harness with uppercase":        `{"harness":"OpenWebUI"}`,
		"session ref with whitespace":   `{"session_ref":"what is the plan"}`,
		"session ref too long":          `{"session_ref":"` + strings.Repeat("a", 129) + `"}`,
		"unknown caller field":          `{"origin":"interactive","message":"hello"}`,
	} {
		t.Run("rejected: "+name, func(t *testing.T) {
			code, out, events := authorizeWithBody(t, `{"schema":"kei.authorize-request/v1","tool":"web_search","caller":`+caller+`}`)
			if code != http.StatusBadRequest || !strings.Contains(out, "invalid_request") {
				t.Fatalf("status = %d body = %s, want 400 invalid_request", code, out)
			}
			if len(events) != 0 {
				t.Errorf("an invalid request emitted %d audit events", len(events))
			}
			if strings.Contains(out, "fake-secret-marker") {
				t.Errorf("error echoes the submitted value: %s", out)
			}
		})
	}
}

// The spool is read back into DecisionEvent before the collector flushes it,
// so the caller fields must survive that round trip to reach the catalog.
func TestDecisionEventKeepsCallerMetadataThroughTheSpool(t *testing.T) {
	line := `{"span_id":"s1","invoked_at":"2026-10-27T10:00:00Z","invoking_subject":"user:u","delegation_depth":0,"agent_id":"a","framework":"open-webui","tool_name":"web_search","resources_touched":[],"decision":"allow","caller_harness":"openwebui","caller_origin":"interactive","caller_session_ref":"chat:1"}`
	event, ok := keiruntime.ParseAuditLine(line)
	if !ok {
		t.Fatal("ParseAuditLine rejected the line")
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"caller_harness":"openwebui"`, `"caller_origin":"interactive"`, `"caller_session_ref":"chat:1"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("flushed event lacks %s: %s", want, raw)
		}
	}
	bare, _ := json.Marshal(keiruntime.DecisionEvent{SpanID: "s2"})
	if strings.Contains(string(bare), "caller_") {
		t.Errorf("an event with no caller metadata carries caller fields: %s", bare)
	}
}
