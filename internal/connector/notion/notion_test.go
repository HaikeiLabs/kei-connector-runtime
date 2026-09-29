package notion

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

const (
	token      = "fake-notion-integration-token-0001"
	pageID     = "1a2b3c4d5e6f47a8b9c0d1e2f3a4b5c6"
	databaseID = "9f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a"
	// Property values that must never leave the runtime.
	personEmail = "alice@example.com"
	bodyText    = "quarterly revenue is confidential"
)

// pageJSON is a Notion page object carrying a title property plus property
// values (a person, rich text) that redaction must drop.
func pageJSON(id, parent string) string {
	return `{"object":"page","id":"` + id + `","created_time":"2026-09-01T10:00:00.000Z","last_edited_time":"2026-09-02T11:30:00.000Z","archived":false,"url":"https://www.notion.so/Roadmap-` + id + `",` +
		`"parent":` + parent + `,` +
		`"properties":{"Name":{"id":"title","type":"title","title":[{"type":"text","plain_text":"Road"},{"type":"text","plain_text":"map"}]},` +
		`"Owner":{"id":"o","type":"people","people":[{"object":"user","person":{"email":"` + personEmail + `"}}]},` +
		`"Notes":{"id":"n","type":"rich_text","rich_text":[{"plain_text":"` + bodyText + `"}]}}}`
}

const databaseJSON = `{"object":"database","id":"` + databaseID + `","created_time":"2026-08-01T09:00:00.000Z","last_edited_time":"2026-08-02T09:00:00.000Z","archived":false,"url":"https://www.notion.so/db","title":[{"plain_text":"Engineering"},{"plain_text":" Wiki"}],"description":[{"plain_text":"` + bodyText + `"}],"properties":{"Owner":{"type":"people","people":{}}}}`

func routes(t *testing.T, handle func(w http.ResponseWriter, r *http.Request, body map[string]any)) *connectortest.Routes {
	r := connectortest.NewRoutes()
	r.Handle("api.notion.com", func(w http.ResponseWriter, req *http.Request) {
		if got := req.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("authorization = %q", got)
		}
		if got := req.Header.Get("Notion-Version"); got != notionVersion {
			t.Errorf("Notion-Version = %q", got)
		}
		var body map[string]any
		if req.Body != nil {
			raw, _ := io.ReadAll(req.Body)
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &body); err != nil {
					t.Errorf("request body is not JSON: %q", raw)
				}
			}
		}
		handle(w, req, body)
	})
	return r
}

func call(r *connectortest.Routes, capability, resource string, in any) connector.Call {
	return connectortest.Call(r, contract.ProviderNotion, capability, contract.ActionRead, resource, in, token)
}

func assertRedacted(t *testing.T, got any) {
	t.Helper()
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{personEmail, bodyText, `"properties"`} {
		if strings.Contains(string(raw), leaked) {
			t.Fatalf("result leaked %q: %s", leaked, raw)
		}
	}
}

func TestSearchReturnsTitlesAndMetadataOnly(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request, body map[string]any) {
		if req.Method != http.MethodPost || req.URL.Path != "/v1/search" {
			t.Errorf("request = %s %s", req.Method, req.URL.Path)
		}
		if body["query"] != "roadmap" || body["page_size"] != float64(5) {
			t.Errorf("search body = %v", body)
		}
		_, _ = io.WriteString(w, `{"object":"list","results":[`+pageJSON(pageID, `{"type":"database_id","database_id":"`+databaseID+`"}`)+`,`+databaseJSON+`],"has_more":true,"next_cursor":"cur-2"}`)
	})
	got, err := Connector{}.Execute(context.Background(), call(r, "search", "search", input.NotionSearch{Query: "roadmap", PageSize: 5}))
	if err != nil {
		t.Fatal(err)
	}
	res := got.(providers.NotionSearchResult)
	if len(res.Results) != 2 || !res.HasMore || res.NextCursor != "cur-2" {
		t.Fatalf("result = %+v", res)
	}
	page, db := res.Results[0].(Item), res.Results[1].(Item)
	if page.Object != "page" || page.ID != pageID || page.Title != "Roadmap" || page.ParentType != "database_id" || page.ParentID != databaseID || page.UpdatedAt.IsZero() {
		t.Fatalf("page item = %+v", page)
	}
	if db.Object != "database" || db.ID != databaseID || db.Title != "Engineering Wiki" || db.ParentType != "" {
		t.Fatalf("database item = %+v", db)
	}
	assertRedacted(t, got)
}

func TestSearchDefaultsAndCapsThePageSize(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, _ *http.Request, body map[string]any) {
		if body["page_size"] != float64(defaultPageSize) {
			t.Errorf("page_size = %v", body["page_size"])
		}
		if _, ok := body["query"]; ok {
			t.Errorf("empty query was sent: %v", body)
		}
		// A provider that ignores page_size still cannot widen the result.
		items := make([]string, defaultPageSize+3)
		for i := range items {
			items[i] = databaseJSON
		}
		_, _ = io.WriteString(w, `{"results":[`+strings.Join(items, ",")+`],"has_more":false}`)
	})
	got, err := Connector{}.Execute(context.Background(), call(r, "search", "search", input.NotionSearch{}))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(got.(providers.NotionSearchResult).Results); n != defaultPageSize {
		t.Fatalf("results = %d, want %d", n, defaultPageSize)
	}
}

func TestPageReadNeverReturnsPropertiesOrContent(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request, _ map[string]any) {
		if req.Method != http.MethodGet || req.URL.Path != "/v1/pages/"+pageID {
			t.Errorf("request = %s %s", req.Method, req.URL.Path)
		}
		_, _ = io.WriteString(w, pageJSON(pageID, `{"type":"workspace","workspace":true}`))
	})
	got, err := Connector{}.Execute(context.Background(), call(r, "page.read", "pages/"+pageID, input.Empty{}))
	if err != nil {
		t.Fatal(err)
	}
	page := got.(providers.NotionPage)
	if page.ID != pageID || page.Title != "Roadmap" || page.ParentType != "workspace" || page.ParentID != "" || page.Properties != nil {
		t.Fatalf("page = %+v", page)
	}
	if r.Count() != 1 {
		t.Fatalf("requests = %d; block content must never be fetched", r.Count())
	}
	assertRedacted(t, got)
}

func TestDatabaseQueryReturnsPagesWithoutProperties(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request, body map[string]any) {
		if req.Method != http.MethodPost || req.URL.Path != "/v1/databases/"+databaseID+"/query" {
			t.Errorf("request = %s %s", req.Method, req.URL.Path)
		}
		if len(body) != 1 || body["page_size"] != float64(3) {
			t.Errorf("query body = %v", body)
		}
		_, _ = io.WriteString(w, `{"object":"list","results":[`+pageJSON(pageID, `{"type":"database_id","database_id":"`+databaseID+`"}`)+`],"has_more":false}`)
	})
	got, err := Connector{}.Execute(context.Background(), call(r, "database.query", "databases/"+databaseID, input.NotionDatabaseQuery{PageSize: 3}))
	if err != nil {
		t.Fatal(err)
	}
	pages := got.([]providers.NotionPage)
	if len(pages) != 1 || pages[0].Title != "Roadmap" || pages[0].ParentID != databaseID {
		t.Fatalf("pages = %+v", pages)
	}
	assertRedacted(t, got)
}

// Every refusal happens before a provider request is made.
func TestFailsClosedWithoutCallingNotion(t *testing.T) {
	cases := []struct {
		name       string
		capability string
		resource   string
		in         any
		mutate     func(*connector.Call)
		want       error
	}{
		// The contract client accepts search/<query>, but that would put the
		// query in the resource, which the catalog and audit see.
		{"query in resource", "search", "search/secret-plans", input.NotionSearch{}, nil, connector.ErrInput},
		{"workspace resource", "search", "notion/workspace", input.NotionSearch{}, nil, connector.ErrInput},
		{"page id not a notion id", "page.read", "pages/not-an-id", input.Empty{}, nil, connector.ErrInput},
		{"page id with a path", "page.read", "pages/" + pageID + "/children", input.Empty{}, nil, connector.ErrInput},
		{"database id not a notion id", "database.query", "databases/x%2F..", input.NotionDatabaseQuery{}, nil, connector.ErrInput},
		{"input for another capability", "search", "search", input.DriveSearch{Query: "x"}, nil, connector.ErrInput},
		{"page input on search", "page.read", "pages/" + pageID, input.NotionSearch{}, nil, connector.ErrInput},
		{"oauth credential", "search", "search", input.NotionSearch{}, func(c *connector.Call) {
			c.Meta.CredentialSource = contract.CredentialSourceOAuth
		}, connector.ErrConfig},
		{"empty credential", "search", "search", input.NotionSearch{}, func(c *connector.Call) { c.Credential = "" }, connector.ErrConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := connectortest.NewRoutes()
			c := call(r, tc.capability, tc.resource, tc.in)
			if tc.mutate != nil {
				tc.mutate(&c)
			}
			if _, err := (Connector{}).Execute(context.Background(), c); !errors.Is(err, tc.want) || r.Count() != 0 {
				t.Fatalf("err = %v (want %v), requests = %d", err, tc.want, r.Count())
			}
		})
	}
}

func TestProviderFailureIsAnError(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"object":"error","message":"API token is invalid: `+token+`"}`)
	})
	_, err := Connector{}.Execute(context.Background(), call(r, "page.read", "pages/"+pageID, input.Empty{}))
	if err == nil || strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "invalid") {
		t.Fatalf("err = %v", err)
	}
}

// Only pages and databases are results; any other object is dropped rather
// than passed through with unknown fields.
func TestSearchDropsUnknownObjects(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
		_, _ = io.WriteString(w, `{"results":[{"object":"data_source","id":"`+pageID+`"},`+databaseJSON+`],"has_more":false}`)
	})
	got, err := Connector{}.Execute(context.Background(), call(r, "search", "search", input.NotionSearch{}))
	if err != nil {
		t.Fatal(err)
	}
	if res := got.(providers.NotionSearchResult).Results; len(res) != 1 || res[0].(Item).Object != "database" {
		t.Fatalf("results = %+v", res)
	}
}
