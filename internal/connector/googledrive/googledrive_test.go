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
	"github.com/HaikeiLabs/kei-connector-contracts/providers"
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

func TestDriveListFilesAppliesScopedFiltersAndBoundedPage(t *testing.T) {
	routes := connectortest.NewRoutes()
	routes.Handle("www.googleapis.com", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != "/drive/v3/files" {
			t.Errorf("request = %s %s", req.Method, req.URL.Path)
		}
		q := req.URL.Query().Get("q")
		if !strings.Contains(q, "trashed = false") || !strings.Contains(q, "name contains 'plan\\'s'") || strings.Contains(q, "mimeType") {
			t.Errorf("q = %q", q)
		}
		if req.URL.Query().Get("driveId") != "0AFx" || req.URL.Query().Get("corpora") != "drive" || req.URL.Query().Get("supportsAllDrives") != "true" {
			t.Errorf("query = %v", req.URL.Query())
		}
		_, _ = io.WriteString(w, `{"files":[{"id":"f-1","driveId":"0AFx","name":"Plan","mimeType":"text/plain"},{"id":"f-2","driveId":"0AFx","name":"Plan doc","mimeType":"application/vnd.google-apps.document"},{"id":"f-3","driveId":"other-drive","name":"Plan other","mimeType":"text/plain"}]}`)
	})
	call := connectortest.Call(routes, contract.ProviderGoogle, "drive.search", contract.ActionRead, "drive/0AFx", input.DriveSearch{
		Query: "plan's", MimeType: "text/plain", Limit: 1,
	}, "fake-drive-token")
	got, err := (Connector{}).Execute(context.Background(), call)
	files, ok := got.([]providers.GoogleFile)
	if err != nil || !ok || len(files) != 1 || files[0].ID != "f-1" || files[0].DriveID != "0AFx" {
		t.Fatalf("drive.list_files normalized result = %#v, %v", got, err)
	}
	if routes.Count() != 1 {
		t.Fatalf("provider requests = %d, want one bounded list request", routes.Count())
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
