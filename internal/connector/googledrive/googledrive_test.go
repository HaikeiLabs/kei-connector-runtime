package googledrive

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/connectortest"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

func docsRoutes(text string) *connectortest.Routes {
	r := connectortest.NewRoutes()
	r.Handle("www.googleapis.com", func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(w, `{"files":[{"id":"f-1","driveId":"0AFx","name":"Plan","mimeType":"application/vnd.google-apps.document","modifiedTime":"2026-09-01T00:00:00Z"}],"id":"f-1","driveId":"0AFx","name":"Plan","mimeType":"application/vnd.google-apps.document","modifiedTime":"2026-09-01T00:00:00Z"}`)
	})
	r.Handle("docs.googleapis.com", func(w http.ResponseWriter, req *http.Request) {
		body, _ := json.Marshal(map[string]any{"body": map[string]any{"content": []any{map[string]any{"paragraph": map[string]any{"elements": []any{map[string]any{"textRun": map[string]any{"content": text}}}}}}}})
		_, _ = w.Write(body)
	})
	return r
}

func TestSearchReturnsFileMetadataOnly(t *testing.T) {
	call := connectortest.Call(docsRoutes("secret doc text"), contract.ProviderGoogle, "drive.search", contract.ActionRead, "drive/0AFx", input.DriveSearch{Query: "plan"}, "fake-drive-token")
	got, err := Connector{}.Execute(context.Background(), call)
	raw, _ := json.Marshal(got)
	if err != nil || !strings.Contains(string(raw), `"name":"Plan"`) || strings.Contains(string(raw), "secret doc text") {
		t.Fatalf("search = %s, %v", raw, err)
	}
}

func TestDocsReadReturnsTextWithinTheCap(t *testing.T) {
	call := connectortest.Call(docsRoutes("hello"), contract.ProviderGoogle, "docs.read", contract.ActionRead, "drive/0AFx/files/f-1", input.Empty{}, "fake-drive-token")
	got, err := Connector{}.Execute(context.Background(), call)
	if err != nil || got != (Document{FileID: "f-1", Text: "hello"}) {
		t.Fatalf("docs.read = %+v, %v", got, err)
	}
	call = connectortest.Call(docsRoutes(strings.Repeat("x", MaxDocumentBytes+1)), contract.ProviderGoogle, "docs.read", contract.ActionRead, "drive/0AFx/files/f-1", input.Empty{}, "fake-drive-token")
	if _, err := (Connector{}).Execute(context.Background(), call); !errors.Is(err, connector.ErrTooLarge) {
		t.Fatalf("oversize docs.read err = %v", err)
	}
}
