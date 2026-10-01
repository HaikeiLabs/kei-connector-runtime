// Package grafana is the grafana connector: folder, dashboard, datasource,
// alert rule, and annotation reads, plus bounded datasource queries, against
// the connector's Grafana instance (Metadata.Grafana.BaseURL), using a service
// account token (credential path 1, opaque_ref only). The contract module
// defines the capabilities and the Guard; the HTTP client lives here.
//
// Host: base_url is an https origin (contract.GrafanaConfig.Validate checks
// its syntax). Self-hosted Grafana is usually
// internal, so private and loopback addresses are allowed, unlike http_api.
// Link-local addresses and the cloud metadata endpoints (by address and by
// name) are always refused: the contract refuses them as literals, and the
// runtime checks every resolved address before any request. Redirects are
// never followed.
//
// Redaction: results are re-encoded from the typed structs below.
// Datasources never carry their URL, user, database, or JSON settings;
// dashboards carry a panel summary (no templating values or links);
// annotations and folders drop user logins and emails.
//
// Queries: datasource.query runs one expression against a prometheus or loki
// datasource only, whose query languages cannot write. The range is at most
// 7 days (the last hour by default) and the result at most max_rows rows
// (default 100) across all frames.
package grafana

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-contracts/providers"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

const (
	defaultLimit   = 25
	defaultMaxRows = 100
	// maxAlertRules caps alert_rule.list; the provisioning API has no paging.
	maxAlertRules = 200
	// maxPanelQueries caps the query expressions kept per panel.
	maxPanelQueries = 10
)

// uid is a Grafana uid.
var uid = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)

// resources maps each capability to its resource pattern; "{uid}" is a uid.
var resources = map[string]string{
	"folder.list":      "folders",
	"folder.read":      "folders/{uid}",
	"dashboard.search": "search",
	"dashboard.read":   "dashboards/{uid}",
	"datasource.list":  "datasources",
	"datasource.read":  "datasources/{uid}",
	"datasource.query": "datasources/{uid}/query",
	"alert_rule.list":  "alert_rules",
	"annotation.list":  "annotations",
}

// queryable lists the datasource types datasource.query may run against.
var queryable = map[string]bool{"prometheus": true, "loki": true}

// metadataHosts are cloud metadata endpoints by name.
var metadataHosts = map[string]bool{
	"metadata": true, "metadata.google.internal": true, "metadata.goog": true,
	"instance-data": true, "instance-data.ec2.internal": true, "metadata.azure.com": true,
}

// Folder is one folder.
type Folder struct {
	UID       string `json:"uid"`
	Title     string `json:"title"`
	URL       string `json:"url,omitempty"`
	ParentUID string `json:"parent_uid,omitempty"`
}

// grafanaFolder is Folder as Grafana encodes it.
type grafanaFolder struct {
	UID       string `json:"uid"`
	Title     string `json:"title"`
	URL       string `json:"url"`
	ParentUID string `json:"parentUid"`
}

// FolderList is a page of folders. NextPage is set when the page is full.
type FolderList struct {
	Folders  []Folder `json:"folders"`
	NextPage int      `json:"next_page,omitempty"`
}

// DashboardSummary is one dashboard search hit.
type DashboardSummary struct {
	UID         string   `json:"uid"`
	Title       string   `json:"title"`
	URL         string   `json:"url"`
	Tags        []string `json:"tags"`
	FolderUID   string   `json:"folder_uid,omitempty"`
	FolderTitle string   `json:"folder_title,omitempty"`
}

// grafanaDashboardSummary is DashboardSummary as Grafana encodes it.
type grafanaDashboardSummary struct {
	UID         string   `json:"uid"`
	Title       string   `json:"title"`
	URL         string   `json:"url"`
	Tags        []string `json:"tags"`
	FolderUID   string   `json:"folderUid"`
	FolderTitle string   `json:"folderTitle"`
}

// DashboardList is a page of dashboards. NextPage is set when the page is
// full.
type DashboardList struct {
	Dashboards []DashboardSummary `json:"dashboards"`
	NextPage   int                `json:"next_page,omitempty"`
}

// Panel summarizes one panel: what it shows and from where.
type Panel struct {
	ID            int      `json:"id"`
	Title         string   `json:"title"`
	Type          string   `json:"type"`
	DatasourceUID string   `json:"datasource_uid,omitempty"`
	Queries       []string `json:"queries,omitempty"`
}

// Dashboard is a dashboard's metadata and panel summary.
type Dashboard struct {
	UID       string   `json:"uid"`
	Title     string   `json:"title"`
	Tags      []string `json:"tags"`
	FolderUID string   `json:"folder_uid,omitempty"`
	Version   int      `json:"version"`
	Panels    []Panel  `json:"panels"`
}

// Datasource is a datasource's identity, without connection details.
type Datasource struct {
	UID       string `json:"uid"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	IsDefault bool   `json:"is_default"`
}

// grafanaDatasource is Datasource as Grafana encodes it.
type grafanaDatasource struct {
	UID       string `json:"uid"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	IsDefault bool   `json:"isDefault"`
}

// AlertRule is one alert rule, without its queries or annotations.
type AlertRule struct {
	UID       string            `json:"uid"`
	Title     string            `json:"title"`
	FolderUID string            `json:"folder_uid"`
	RuleGroup string            `json:"rule_group"`
	Labels    map[string]string `json:"labels,omitempty"`
	Paused    bool              `json:"paused"`
}

// grafanaAlertRule is AlertRule as Grafana encodes it.
type grafanaAlertRule struct {
	UID       string            `json:"uid"`
	Title     string            `json:"title"`
	FolderUID string            `json:"folderUID"`
	RuleGroup string            `json:"ruleGroup"`
	Labels    map[string]string `json:"labels"`
	Paused    bool              `json:"isPaused"`
}

// AlertRuleList is the alert rules, capped at maxAlertRules.
type AlertRuleList struct {
	Rules     []AlertRule `json:"rules"`
	Truncated bool        `json:"truncated"`
}

// Annotation is one annotation, without who made it.
type Annotation struct {
	ID           int64    `json:"id"`
	DashboardUID string   `json:"dashboard_uid,omitempty"`
	PanelID      int      `json:"panel_id,omitempty"`
	Time         int64    `json:"time"`
	TimeEnd      int64    `json:"time_end,omitempty"`
	Text         string   `json:"text"`
	Tags         []string `json:"tags,omitempty"`
}

// grafanaAnnotation is Annotation as Grafana encodes it.
type grafanaAnnotation struct {
	ID           int64    `json:"id"`
	DashboardUID string   `json:"dashboardUID"`
	PanelID      int      `json:"panelId"`
	Time         int64    `json:"time"`
	TimeEnd      int64    `json:"timeEnd"`
	Text         string   `json:"text"`
	Tags         []string `json:"tags"`
}

// Field is one data frame column.
type Field struct {
	Name   string            `json:"name"`
	Type   string            `json:"type,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// Frame is one data frame, row-major.
type Frame struct {
	Name   string  `json:"name,omitempty"`
	Fields []Field `json:"fields"`
	Rows   [][]any `json:"rows"`
}

// QueryResult is a datasource query's frames. Truncated is set when rows
// were dropped to stay within max_rows.
type QueryResult struct {
	Frames    []Frame `json:"frames"`
	Truncated bool    `json:"truncated"`
}

// Connector executes grafana reads.
type Connector struct{}

// Execute runs one grafana read. The config, resource, input, and host are
// all checked before any request.
func (Connector) Execute(ctx context.Context, call connector.Call) (any, error) {
	if call.Meta.EffectiveCredentialSource() != contract.CredentialSourceOpaqueRef || call.Credential == "" {
		return nil, connector.ErrConfig
	}
	base, err := parseBaseURL(call.Meta.Grafana)
	if err != nil {
		return nil, err
	}
	capability := call.Invocation.Capability
	pattern, ok := resources[capability]
	if !ok {
		return nil, connector.ErrInput
	}
	uids, ok := match(pattern, call.Invocation.Resource)
	if !ok || !inputFits(capability, call.Input) {
		return nil, connector.ErrInput
	}
	if err := providers.Guard(call.Meta, call.Invocation); err != nil {
		return nil, err
	}
	if err := checkHost(ctx, call.LookupIP, base.Hostname()); err != nil {
		return nil, err
	}
	client := *call.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	b := &backend{client: &client, base: base, token: call.Credential, now: call.Now}
	switch capability {
	case "folder.list":
		return b.folders(ctx, call.Input.(input.GrafanaFolderList))
	case "folder.read":
		return b.folder(ctx, uids[0])
	case "dashboard.search":
		return b.search(ctx, call.Input.(input.GrafanaDashboardSearch))
	case "dashboard.read":
		return b.dashboard(ctx, uids[0])
	case "datasource.list":
		return b.datasources(ctx)
	case "datasource.read":
		return b.datasource(ctx, uids[0])
	case "datasource.query":
		return b.query(ctx, uids[0], call.Input.(input.GrafanaDatasourceQuery))
	case "alert_rule.list":
		return b.alertRules(ctx)
	default: // annotation.list
		return b.annotations(ctx, call.Input.(input.GrafanaAnnotationList))
	}
}

// parseBaseURL reads and checks the connector's Grafana base_url.
func parseBaseURL(g *contract.GrafanaConfig) (*url.URL, error) {
	if g == nil {
		return nil, connector.ErrConfig
	}
	// The contract checks the syntax: an https origin, with no path, query,
	// fragment, or userinfo, that is not a metadata address by name.
	if g.Validate() != nil {
		return nil, connector.ErrConfig
	}
	u, err := url.Parse(g.BaseURL)
	if err != nil {
		return nil, connector.ErrConfig
	}
	u.Path, u.RawPath = "", ""
	return u, nil
}

// checkHost refuses a host that is, or resolves to, a link-local or cloud
// metadata address. Private and loopback addresses are allowed.
func checkHost(ctx context.Context, lookup func(context.Context, string) ([]net.IP, error), host string) error {
	if metadataHosts[strings.TrimSuffix(strings.ToLower(host), ".")] {
		return connector.ErrConfig
	}
	ips := []net.IP{net.ParseIP(host)}
	if ips[0] == nil {
		if lookup == nil {
			lookup = func(ctx context.Context, host string) ([]net.IP, error) {
				return net.DefaultResolver.LookupIP(ctx, "ip", host)
			}
		}
		var err error
		if ips, err = lookup(ctx, host); err != nil || len(ips) == 0 {
			return connector.ErrConfig
		}
	}
	for _, ip := range ips {
		if blockedIP(ip) {
			return connector.ErrConfig
		}
	}
	return nil
}

// metadataIPs are cloud metadata addresses outside the link-local ranges:
// AWS over IPv6, and Alibaba Cloud.
var metadataIPs = []net.IP{net.ParseIP("fd00:ec2::254"), net.ParseIP("100.100.100.200")}

func blockedIP(ip net.IP) bool {
	if ip == nil || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	for _, m := range metadataIPs {
		if ip.Equal(m) {
			return true
		}
	}
	return false
}

// match returns the uids in resource if it fits pattern exactly.
func match(pattern, resource string) ([]string, bool) {
	want, got := strings.Split(pattern, "/"), strings.Split(resource, "/")
	if len(want) != len(got) {
		return nil, false
	}
	var uids []string
	for i, w := range want {
		switch {
		case w == "{uid}" && uid.MatchString(got[i]):
			uids = append(uids, got[i])
		case w != got[i]:
			return nil, false
		}
	}
	return uids, true
}

func inputFits(capability string, in any) bool {
	var ok bool
	switch capability {
	case "folder.list":
		_, ok = in.(input.GrafanaFolderList)
	case "dashboard.search":
		_, ok = in.(input.GrafanaDashboardSearch)
	case "annotation.list":
		_, ok = in.(input.GrafanaAnnotationList)
	case "datasource.query":
		_, ok = in.(input.GrafanaDatasourceQuery)
	default:
		_, ok = in.(input.Empty)
	}
	return ok
}

func orDefault(n, def int) int {
	if n <= 0 {
		return def
	}
	return n
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// backend is the Grafana HTTP API, built per call with that call's token.
type backend struct {
	client *http.Client
	base   *url.URL
	token  string
	now    func() time.Time
}

func (b *backend) clock() time.Time {
	if b.now != nil {
		return b.now()
	}
	return time.Now()
}

func (b *backend) folders(ctx context.Context, in input.GrafanaFolderList) (FolderList, error) {
	limit, page := orDefault(in.Limit, defaultLimit), orDefault(in.Page, 1)
	var raw []grafanaFolder
	if err := b.do(ctx, http.MethodGet, "/api/folders", url.Values{"limit": {strconv.Itoa(limit)}, "page": {strconv.Itoa(page)}}, nil, &raw); err != nil {
		return FolderList{}, err
	}
	out := FolderList{Folders: convert(capped(raw, limit), func(v grafanaFolder) Folder { return Folder(v) })}
	if len(raw) >= limit {
		out.NextPage = page + 1
	}
	return out, nil
}

func (b *backend) folder(ctx context.Context, id string) (Folder, error) {
	var f grafanaFolder
	err := b.do(ctx, http.MethodGet, "/api/folders/"+id, nil, nil, &f)
	return Folder(f), err
}

func (b *backend) search(ctx context.Context, in input.GrafanaDashboardSearch) (DashboardList, error) {
	limit, page := orDefault(in.Limit, defaultLimit), orDefault(in.Page, 1)
	q := url.Values{"type": {"dash-db"}, "limit": {strconv.Itoa(limit)}, "page": {strconv.Itoa(page)}}
	if in.Query != "" {
		q.Set("query", in.Query)
	}
	for _, t := range in.Tags {
		q.Add("tag", t)
	}
	var raw []grafanaDashboardSummary
	if err := b.do(ctx, http.MethodGet, "/api/search", q, nil, &raw); err != nil {
		return DashboardList{}, err
	}
	out := DashboardList{Dashboards: convert(capped(raw, limit), func(v grafanaDashboardSummary) DashboardSummary { return DashboardSummary(v) })}
	if len(raw) >= limit {
		out.NextPage = page + 1
	}
	return out, nil
}

// rawPanel is the part of a dashboard panel the connector decodes. Row
// panels nest their panels one level down.
type rawPanel struct {
	ID         int             `json:"id"`
	Title      string          `json:"title"`
	Type       string          `json:"type"`
	Datasource json.RawMessage `json:"datasource"`
	Targets    []struct {
		Expr string `json:"expr"`
	} `json:"targets"`
	Panels []rawPanel `json:"panels"`
}

func (p rawPanel) summary() Panel {
	out := Panel{ID: p.ID, Title: p.Title, Type: p.Type}
	// A datasource is an object with a uid, or a legacy name string.
	var ds struct {
		UID string `json:"uid"`
	}
	if json.Unmarshal(p.Datasource, &ds) == nil {
		out.DatasourceUID = ds.UID
	}
	for _, t := range p.Targets {
		if t.Expr != "" && len(out.Queries) < maxPanelQueries {
			out.Queries = append(out.Queries, t.Expr)
		}
	}
	return out
}

func (b *backend) dashboard(ctx context.Context, id string) (Dashboard, error) {
	var raw struct {
		Meta struct {
			FolderUID string `json:"folderUid"`
		} `json:"meta"`
		Dashboard struct {
			UID     string     `json:"uid"`
			Title   string     `json:"title"`
			Tags    []string   `json:"tags"`
			Version int        `json:"version"`
			Panels  []rawPanel `json:"panels"`
		} `json:"dashboard"`
	}
	if err := b.do(ctx, http.MethodGet, "/api/dashboards/uid/"+id, nil, nil, &raw); err != nil {
		return Dashboard{}, err
	}
	d := raw.Dashboard
	out := Dashboard{UID: d.UID, Title: d.Title, Tags: d.Tags, FolderUID: raw.Meta.FolderUID, Version: d.Version, Panels: []Panel{}}
	// A collapsed row nests its panels; they follow the row, flattened.
	for _, p := range d.Panels {
		out.Panels = append(out.Panels, p.summary())
		for _, nested := range p.Panels {
			out.Panels = append(out.Panels, nested.summary())
		}
	}
	return out, nil
}

func (b *backend) datasources(ctx context.Context) ([]Datasource, error) {
	var raw []grafanaDatasource
	err := b.do(ctx, http.MethodGet, "/api/datasources", nil, nil, &raw)
	return convert(raw, func(v grafanaDatasource) Datasource { return Datasource(v) }), err
}

func (b *backend) datasource(ctx context.Context, id string) (Datasource, error) {
	var d grafanaDatasource
	err := b.do(ctx, http.MethodGet, "/api/datasources/uid/"+id, nil, nil, &d)
	return Datasource(d), err
}

func (b *backend) alertRules(ctx context.Context) (AlertRuleList, error) {
	var raw []grafanaAlertRule
	if err := b.do(ctx, http.MethodGet, "/api/v1/provisioning/alert-rules", nil, nil, &raw); err != nil {
		return AlertRuleList{}, err
	}
	return AlertRuleList{Rules: convert(capped(raw, maxAlertRules), func(v grafanaAlertRule) AlertRule { return AlertRule(v) }), Truncated: len(raw) > maxAlertRules}, nil
}

func (b *backend) annotations(ctx context.Context, in input.GrafanaAnnotationList) ([]Annotation, error) {
	from, to := in.From, in.To
	if from == 0 && to == 0 {
		now := b.clock()
		from, to = now.Add(-24*time.Hour).UnixMilli(), now.UnixMilli()
	}
	limit := orDefault(in.Limit, defaultLimit)
	q := url.Values{"from": {itoa(from)}, "to": {itoa(to)}, "limit": {strconv.Itoa(limit)}}
	if in.DashboardUID != "" {
		q.Set("dashboardUID", in.DashboardUID)
	}
	for _, t := range in.Tags {
		q.Add("tags", t)
	}
	var raw []grafanaAnnotation
	if err := b.do(ctx, http.MethodGet, "/api/annotations", q, nil, &raw); err != nil {
		return nil, err
	}
	return convert(capped(raw, limit), func(v grafanaAnnotation) Annotation { return Annotation(v) }), nil
}

// query runs one bounded expression. The datasource is looked up first, and
// only a queryable type is sent a query.
func (b *backend) query(ctx context.Context, id string, in input.GrafanaDatasourceQuery) (QueryResult, error) {
	ds, err := b.datasource(ctx, id)
	if err != nil {
		return QueryResult{}, err
	}
	if !queryable[ds.Type] {
		return QueryResult{}, connector.ErrInput
	}
	from, to := in.From, in.To
	if from == 0 && to == 0 {
		now := b.clock()
		from, to = now.Add(-time.Hour).UnixMilli(), now.UnixMilli()
	}
	maxRows := orDefault(in.MaxRows, defaultMaxRows)
	q := map[string]any{
		"refId":         "A",
		"datasource":    map[string]string{"uid": id, "type": ds.Type},
		"expr":          in.Expr,
		"maxDataPoints": maxRows,
		"intervalMs":    max((to-from)/int64(maxRows), 1000),
	}
	if ds.Type == "loki" {
		q["queryType"] = "range"
		q["maxLines"] = maxRows
	} else {
		q["range"] = true
	}
	body := map[string]any{"from": itoa(from), "to": itoa(to), "queries": []any{q}}
	var resp struct {
		Results map[string]struct {
			Error  string     `json:"error"`
			Frames []rawFrame `json:"frames"`
		} `json:"results"`
	}
	if err := b.do(ctx, http.MethodPost, "/api/ds/query", nil, body, &resp); err != nil {
		return QueryResult{}, err
	}
	res, ok := resp.Results["A"]
	if !ok || res.Error != "" {
		return QueryResult{}, errors.New("provider query failed")
	}
	out := QueryResult{Frames: []Frame{}}
	remaining := maxRows
	for _, f := range res.Frames {
		frame, dropped := f.rows(remaining)
		remaining -= len(frame.Rows)
		out.Truncated = out.Truncated || dropped
		out.Frames = append(out.Frames, frame)
	}
	return out, nil
}

// rawFrame is a Grafana data frame: a schema and column-major values.
type rawFrame struct {
	Schema struct {
		Name   string  `json:"name"`
		Fields []Field `json:"fields"`
	} `json:"schema"`
	Data struct {
		Values [][]any `json:"values"`
	} `json:"data"`
}

// rows converts the frame to at most limit rows, reporting whether any were
// dropped.
func (f rawFrame) rows(limit int) (Frame, bool) {
	out := Frame{Name: f.Schema.Name, Fields: f.Schema.Fields, Rows: [][]any{}}
	if out.Fields == nil {
		out.Fields = []Field{}
	}
	n := 0
	for _, col := range f.Data.Values {
		n = max(n, len(col))
	}
	for i := 0; i < n && i < limit; i++ {
		row := make([]any, len(f.Data.Values))
		for c, col := range f.Data.Values {
			if i < len(col) {
				row[c] = col[i]
			}
		}
		out.Rows = append(out.Rows, row)
	}
	return out, n > limit
}

// do sends one request under base_url. Provider bodies are read only on
// success, so provider error text cannot reach an error or a log.
func (b *backend) do(ctx context.Context, method, path string, q url.Values, body any, out any) error {
	target := *b.base
	target.Path = b.base.Path + path
	target.RawQuery = q.Encode()
	var reader io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return errors.New("provider request could not be created")
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return errors.New("provider request could not be created")
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
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

// convert maps Grafana-encoded items to their result type.
func convert[From, To any](items []From, to func(From) To) []To {
	out := make([]To, len(items))
	for i, item := range items {
		out[i] = to(item)
	}
	return out
}

func capped[T any](items []T, n int) []T {
	if len(items) > n {
		return items[:n]
	}
	if items == nil {
		return []T{}
	}
	return items
}
