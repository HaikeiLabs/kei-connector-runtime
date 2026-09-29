// Package notion is the notion connector: search, page.read, and
// database.query through the kei-connector-contracts Notion client, using a
// shared-secret integration token (credential path 1). The contract module
// has only an in-memory Notion backend, so the HTTP backend lives here, behind
// the contract's providers.NotionBackend seam and its Guard.
//
// Redaction: results carry titles and metadata only. Property values (people,
// rich text, and so on) are discarded when the provider response is decoded,
// and page block content is never fetched. No policy attribute opts in to
// more yet.
package notion

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-contracts/providers"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

const (
	apiBase = "https://api.notion.com/v1"
	// notionVersion pins the API shape the decoder expects; later versions
	// move database queries to data sources.
	notionVersion   = "2022-06-28"
	defaultPageSize = 10
)

// notionID is a Notion object id: 32 hex digits, bare or as a dashed UUID.
var notionID = regexp.MustCompile(`^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$`)

// Item is one search result: a page or a database, without properties.
type Item struct {
	Object     string    `json:"object"`
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	URL        string    `json:"url"`
	ParentType string    `json:"parent_type,omitempty"`
	ParentID   string    `json:"parent_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Archived   bool      `json:"archived"`
}

// Connector executes notion reads.
type Connector struct{}

// Execute runs one notion read.
func (Connector) Execute(ctx context.Context, call connector.Call) (any, error) {
	if call.Meta.EffectiveCredentialSource() != contract.CredentialSourceOpaqueRef || call.Credential == "" {
		return nil, connector.ErrConfig
	}
	payload, err := payloadFor(call.Invocation, call.Input)
	if err != nil {
		return nil, err
	}
	b := &backend{client: call.HTTPClient, token: call.Credential}
	res, err := providers.NewNotion(b).Invoke(ctx, call.Meta, call.Invocation, payload)
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}

// payloadFor checks the input type and resource against the capability.
// Search takes its query from the input only: the contract's search/<query>
// resource would expose the query to the catalog and audit.
func payloadFor(inv contract.Invocation, in any) (providers.Payload, error) {
	switch inv.Capability {
	case "search":
		if s, ok := in.(input.NotionSearch); ok && inv.Resource == "search" {
			return providers.SearchPayload{Query: s.Query, PageSize: pageSize(s.PageSize)}, nil
		}
	case "page.read":
		if _, ok := in.(input.Empty); ok && idResource(inv.Resource, "pages/") {
			return providers.PageReadPayload{}, nil
		}
	case "database.query":
		if q, ok := in.(input.NotionDatabaseQuery); ok && idResource(inv.Resource, "databases/") {
			return providers.DatabaseQueryPayload{PageSize: pageSize(q.PageSize)}, nil
		}
	}
	return nil, connector.ErrInput
}

func idResource(resource, prefix string) bool {
	id, ok := strings.CutPrefix(resource, prefix)
	return ok && notionID.MatchString(id)
}

func pageSize(n int) int {
	if n <= 0 {
		return defaultPageSize
	}
	return n
}

// backend is the Notion REST API behind providers.NotionBackend. It is built
// per call with that call's credential.
type backend struct {
	client *http.Client
	token  string
}

var _ providers.NotionBackend = (*backend)(nil)

func (b *backend) Search(ctx context.Context, query string, size int) (providers.NotionSearchResult, error) {
	body := map[string]any{"page_size": size}
	if query != "" {
		body["query"] = query
	}
	var resp listResponse
	if err := b.do(ctx, http.MethodPost, "/search", body, &resp); err != nil {
		return providers.NotionSearchResult{}, err
	}
	results := []any{}
	for _, o := range resp.Results {
		if len(results) == size {
			break
		}
		if o.Object == "page" || o.Object == "database" {
			results = append(results, o.item())
		}
	}
	return providers.NotionSearchResult{Results: results, HasMore: resp.HasMore, NextCursor: resp.NextCursor}, nil
}

func (b *backend) Page(ctx context.Context, id string) (providers.NotionPage, error) {
	var o object
	if err := b.do(ctx, http.MethodGet, "/pages/"+url.PathEscape(id), nil, &o); err != nil {
		return providers.NotionPage{}, err
	}
	if o.Object != "page" {
		return providers.NotionPage{}, errors.New("provider response was invalid")
	}
	return o.page(), nil
}

// QueryDatabase sends only page_size; filters and sorts are not accepted
// from the input yet, so the contract passes none.
func (b *backend) QueryDatabase(ctx context.Context, id string, _ map[string]any, _ []map[string]any, size int) ([]providers.NotionPage, error) {
	var resp listResponse
	if err := b.do(ctx, http.MethodPost, "/databases/"+url.PathEscape(id)+"/query", map[string]any{"page_size": size}, &resp); err != nil {
		return nil, err
	}
	pages := []providers.NotionPage{}
	for _, o := range resp.Results {
		if len(pages) == size {
			break
		}
		if o.Object == "page" {
			pages = append(pages, o.page())
		}
	}
	return pages, nil
}

// do sends one request. Provider error bodies are never read, so their text
// cannot reach an error or a log.
func (b *backend) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return errors.New("provider request could not be created")
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, apiBase+path, reader)
	if err != nil {
		return errors.New("provider request could not be created")
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Notion-Version", notionVersion)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return errors.New("provider request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("provider request was rejected")
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return errors.New("provider response was invalid")
	}
	return nil
}

type listResponse struct {
	Results    []object `json:"results"`
	HasMore    bool     `json:"has_more"`
	NextCursor string   `json:"next_cursor"`
}

type richText []struct {
	PlainText string `json:"plain_text"`
}

func (r richText) String() string {
	var sb strings.Builder
	for _, t := range r {
		sb.WriteString(t.PlainText)
	}
	return sb.String()
}

// object is the part of a Notion page or database the connector keeps.
// Properties stay raw until titleProperty picks out the title; every other
// property value is dropped here.
type object struct {
	Object         string    `json:"object"`
	ID             string    `json:"id"`
	CreatedTime    time.Time `json:"created_time"`
	LastEditedTime time.Time `json:"last_edited_time"`
	Archived       bool      `json:"archived"`
	URL            string    `json:"url"`
	Parent         struct {
		Type       string `json:"type"`
		DatabaseID string `json:"database_id"`
		PageID     string `json:"page_id"`
		BlockID    string `json:"block_id"`
	} `json:"parent"`
	// Title is a database's title; a page's is its title property.
	Title      richText                   `json:"title"`
	Properties map[string]json.RawMessage `json:"properties"`
}

func (o object) title() string {
	if o.Object == "database" {
		return o.Title.String()
	}
	for _, raw := range o.Properties {
		var p struct {
			Type  string   `json:"type"`
			Title richText `json:"title"`
		}
		if json.Unmarshal(raw, &p) == nil && p.Type == "title" {
			return p.Title.String()
		}
	}
	return ""
}

func (o object) parentID() string {
	switch o.Parent.Type {
	case "database_id":
		return o.Parent.DatabaseID
	case "page_id":
		return o.Parent.PageID
	case "block_id":
		return o.Parent.BlockID
	}
	return ""
}

func (o object) item() Item {
	return Item{
		Object: o.Object, ID: o.ID, Title: o.title(), URL: o.URL,
		ParentType: o.Parent.Type, ParentID: o.parentID(),
		CreatedAt: o.CreatedTime, UpdatedAt: o.LastEditedTime, Archived: o.Archived,
	}
}

func (o object) page() providers.NotionPage {
	return providers.NotionPage{
		ID: o.ID, Title: o.title(), ParentID: o.parentID(), ParentType: o.Parent.Type, URL: o.URL,
		CreatedAt: o.CreatedTime, UpdatedAt: o.LastEditedTime, Archived: o.Archived,
	}
}
