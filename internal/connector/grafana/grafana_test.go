package grafana

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/connectortest"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

const (
	token   = "glsa_fakeGrafanaServiceAccountToken_0001"
	host    = "grafana.internal.example"
	baseURL = "https://" + host
	dsUID   = "prom-main"
	// Values that must never leave the runtime.
	datasourceURL  = "http://prometheus.secret.svc:9090"
	datasourceUser = "prom-reader"
	userEmail      = "alice@example.com"
)

// now is connectortest.Call's clock, in epoch milliseconds.
var now = time.Unix(1_790_000_000, 0).UTC()

func routes(t *testing.T, handle func(w http.ResponseWriter, r *http.Request, body map[string]any)) *connectortest.Routes {
	r := connectortest.NewRoutes()
	r.Handle(host, func(w http.ResponseWriter, req *http.Request) {
		if got := req.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("authorization = %q", got)
		}
		var body map[string]any
		if raw, _ := io.ReadAll(req.Body); len(raw) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("request body is not JSON: %q", raw)
			}
		}
		handle(w, req, body)
	})
	return r
}

func call(r *connectortest.Routes, capability, resource string, in any) connector.Call {
	c := connectortest.Call(r, contract.ProviderGrafana, capability, contract.ActionRead, resource, in, token)
	c.Meta.Grafana = &contract.GrafanaConfig{BaseURL: baseURL}
	return c
}

func execute(t *testing.T, r *connectortest.Routes, capability, resource string, in any) any {
	t.Helper()
	got, err := Connector{}.Execute(context.Background(), call(r, capability, resource, in))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{token, datasourceURL, datasourceUser, userEmail} {
		if strings.Contains(string(raw), leaked) {
			t.Fatalf("result leaked %q: %s", leaked, raw)
		}
	}
	return got
}

func get(t *testing.T, req *http.Request, path string) {
	t.Helper()
	if req.Method != http.MethodGet || req.URL.Path != path {
		t.Errorf("request = %s %s, want GET %s", req.Method, req.URL.Path, path)
	}
}

func TestFolderListPagesAndReturnsNextPage(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request, _ map[string]any) {
		get(t, req, "/api/folders")
		if q := req.URL.Query(); q.Get("limit") != "2" || q.Get("page") != "3" {
			t.Errorf("query = %v", q)
		}
		_, _ = io.WriteString(w, `[{"id":1,"uid":"f1","title":"Prod"},{"id":2,"uid":"f2","title":"Staging","parentUid":"f1"}]`)
	})
	res := execute(t, r, "folder.list", "folders", input.GrafanaFolderList{Limit: 2, Page: 3}).(FolderList)
	if len(res.Folders) != 2 || res.Folders[1].UID != "f2" || res.Folders[1].ParentUID != "f1" || res.NextPage != 4 {
		t.Fatalf("result = %+v", res)
	}
}

func TestFolderListDefaults(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request, _ map[string]any) {
		if q := req.URL.Query(); q.Get("limit") != "25" || q.Get("page") != "1" {
			t.Errorf("query = %v", q)
		}
		_, _ = io.WriteString(w, `[{"uid":"f1","title":"Prod"}]`)
	})
	res := execute(t, r, "folder.list", "folders", input.GrafanaFolderList{}).(FolderList)
	if res.NextPage != 0 || len(res.Folders) != 1 {
		t.Fatalf("result = %+v", res)
	}
}

func TestFolderRead(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request, _ map[string]any) {
		get(t, req, "/api/folders/f1")
		_, _ = io.WriteString(w, `{"uid":"f1","title":"Prod","url":"/dashboards/f/f1/prod","createdBy":"`+userEmail+`","updatedBy":"admin"}`)
	})
	f := execute(t, r, "folder.read", "folders/f1", input.Empty{}).(Folder)
	if f.UID != "f1" || f.Title != "Prod" || f.URL != "/dashboards/f/f1/prod" {
		t.Fatalf("folder = %+v", f)
	}
}

func TestDashboardSearchSearchesDashboardsOnly(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request, _ map[string]any) {
		get(t, req, "/api/search")
		q := req.URL.Query()
		if q.Get("type") != "dash-db" || q.Get("query") != "cpu" || strings.Join(q["tag"], ",") != "prod,linux" || q.Get("limit") != "1" || q.Get("page") != "1" {
			t.Errorf("query = %v", q)
		}
		_, _ = io.WriteString(w, `[{"uid":"d1","title":"CPU","url":"/d/d1/cpu","type":"dash-db","tags":["prod"],"folderUid":"f1","folderTitle":"Prod"}]`)
	})
	res := execute(t, r, "dashboard.search", "search", input.GrafanaDashboardSearch{Query: "cpu", Tags: []string{"prod", "linux"}, Limit: 1}).(DashboardList)
	d := res.Dashboards[0]
	if len(res.Dashboards) != 1 || d.UID != "d1" || d.FolderUID != "f1" || d.FolderTitle != "Prod" || d.Tags[0] != "prod" || res.NextPage != 2 {
		t.Fatalf("result = %+v", res)
	}
}

func TestDashboardReadSummarizesPanels(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request, _ map[string]any) {
		get(t, req, "/api/dashboards/uid/d1")
		_, _ = io.WriteString(w, `{"meta":{"folderUid":"f1","createdBy":"`+userEmail+`"},"dashboard":{"uid":"d1","title":"CPU","tags":["prod"],"version":7,`+
			`"templating":{"list":[{"name":"password","current":{"value":"hunter2"}}]},`+
			`"panels":[{"id":1,"title":"Load","type":"timeseries","datasource":{"type":"prometheus","uid":"`+dsUID+`"},"targets":[{"refId":"A","expr":"node_load1"}]},`+
			`{"id":2,"title":"Row","type":"row","panels":[{"id":3,"title":"Legacy","type":"graph","datasource":"Prometheus","targets":[{"expr":"up"}]}]}]}}`)
	})
	d := execute(t, r, "dashboard.read", "dashboards/d1", input.Empty{}).(Dashboard)
	if d.UID != "d1" || d.Title != "CPU" || d.FolderUID != "f1" || d.Version != 7 || len(d.Panels) != 3 {
		t.Fatalf("dashboard = %+v", d)
	}
	if p := d.Panels[0]; p.ID != 1 || p.Type != "timeseries" || p.DatasourceUID != dsUID || len(p.Queries) != 1 || p.Queries[0] != "node_load1" {
		t.Fatalf("panel = %+v", p)
	}
	if p := d.Panels[2]; p.ID != 3 || p.DatasourceUID != "" || p.Queries[0] != "up" {
		t.Fatalf("nested panel = %+v", p)
	}
	raw, _ := json.Marshal(d)
	if strings.Contains(string(raw), "hunter2") || strings.Contains(string(raw), "templating") {
		t.Fatalf("dashboard leaked templating: %s", raw)
	}
}

const datasourceJSON = `{"id":1,"uid":"` + dsUID + `","name":"Prometheus","type":"prometheus","isDefault":true,"url":"` + datasourceURL + `","user":"` + datasourceUser + `","basicAuthUser":"` + datasourceUser + `","jsonData":{"httpMethod":"POST"},"secureJsonFields":{"basicAuthPassword":true}}`

func TestDatasourceListDropsConnectionDetails(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request, _ map[string]any) {
		get(t, req, "/api/datasources")
		_, _ = io.WriteString(w, `[`+datasourceJSON+`]`)
	})
	got := execute(t, r, "datasource.list", "datasources", input.Empty{}).([]Datasource)
	if len(got) != 1 || got[0].UID != dsUID || got[0].Name != "Prometheus" || got[0].Type != "prometheus" || !got[0].IsDefault {
		t.Fatalf("datasources = %+v", got)
	}
}

func TestDatasourceRead(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request, _ map[string]any) {
		get(t, req, "/api/datasources/uid/"+dsUID)
		_, _ = io.WriteString(w, datasourceJSON)
	})
	d := execute(t, r, "datasource.read", "datasources/"+dsUID, input.Empty{}).(Datasource)
	if d.UID != dsUID || d.Type != "prometheus" {
		t.Fatalf("datasource = %+v", d)
	}
}

func TestAlertRuleListIsCapped(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request, _ map[string]any) {
		get(t, req, "/api/v1/provisioning/alert-rules")
		rules := make([]string, maxAlertRules+1)
		for i := range rules {
			rules[i] = `{"uid":"r1","title":"High CPU","folderUID":"f1","ruleGroup":"node","labels":{"team":"sre"},"isPaused":false,"data":[{"model":{"expr":"x"}}],"annotations":{"runbook":"y"}}`
		}
		_, _ = io.WriteString(w, `[`+strings.Join(rules, ",")+`]`)
	})
	res := execute(t, r, "alert_rule.list", "alert_rules", input.Empty{}).(AlertRuleList)
	if len(res.Rules) != maxAlertRules || !res.Truncated {
		t.Fatalf("rules = %d, truncated = %v", len(res.Rules), res.Truncated)
	}
	if ru := res.Rules[0]; ru.UID != "r1" || ru.Title != "High CPU" || ru.FolderUID != "f1" || ru.RuleGroup != "node" || ru.Labels["team"] != "sre" {
		t.Fatalf("rule = %+v", ru)
	}
}

func TestAnnotationListDefaultsToTheLastDay(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request, _ map[string]any) {
		get(t, req, "/api/annotations")
		q := req.URL.Query()
		wantTo, wantFrom := now.UnixMilli(), now.Add(-24*time.Hour).UnixMilli()
		if q.Get("to") != itoa(wantTo) || q.Get("from") != itoa(wantFrom) || q.Get("limit") != "25" || q.Has("dashboardUID") {
			t.Errorf("query = %v", q)
		}
		_, _ = io.WriteString(w, `[{"id":9,"dashboardUID":"d1","panelId":1,"time":1,"timeEnd":2,"text":"deploy","tags":["release"],"login":"alice","email":"`+userEmail+`","avatarUrl":"/a"}]`)
	})
	got := execute(t, r, "annotation.list", "annotations", input.GrafanaAnnotationList{}).([]Annotation)
	if len(got) != 1 || got[0].ID != 9 || got[0].Text != "deploy" || got[0].DashboardUID != "d1" || got[0].Tags[0] != "release" {
		t.Fatalf("annotations = %+v", got)
	}
}

func TestAnnotationListPassesTheRangeAndFilters(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request, _ map[string]any) {
		q := req.URL.Query()
		if q.Get("from") != "1000" || q.Get("to") != "2000" || q.Get("dashboardUID") != "d1" || strings.Join(q["tags"], ",") != "a,b" || q.Get("limit") != "3" {
			t.Errorf("query = %v", q)
		}
		items := make([]string, 5)
		for i := range items {
			items[i] = `{"id":1,"text":"x"}`
		}
		_, _ = io.WriteString(w, `[`+strings.Join(items, ",")+`]`)
	})
	got := execute(t, r, "annotation.list", "annotations", input.GrafanaAnnotationList{From: 1000, To: 2000, DashboardUID: "d1", Tags: []string{"a", "b"}, Limit: 3}).([]Annotation)
	if len(got) != 3 {
		t.Fatalf("annotations = %d, want the limit 3", len(got))
	}
}

// queryRoutes serves the datasource lookup and /api/ds/query.
func queryRoutes(t *testing.T, dsType string, onQuery func(body map[string]any), frames string) *connectortest.Routes {
	return routes(t, func(w http.ResponseWriter, req *http.Request, body map[string]any) {
		switch req.URL.Path {
		case "/api/datasources/uid/" + dsUID:
			_, _ = io.WriteString(w, strings.Replace(datasourceJSON, `"type":"prometheus"`, `"type":"`+dsType+`"`, 1))
		case "/api/ds/query":
			if req.Method != http.MethodPost {
				t.Errorf("ds/query method = %s", req.Method)
			}
			onQuery(body)
			_, _ = io.WriteString(w, `{"results":{"A":{"status":200,"frames":`+frames+`}}}`)
		default:
			t.Errorf("unexpected path %s", req.URL.Path)
		}
	})
}

const twoFrames = `[` +
	`{"schema":{"name":"up","refId":"A","fields":[{"name":"Time","type":"time"},{"name":"Value","type":"number","labels":{"job":"node"}}]},"data":{"values":[[1000,2000,3000],[1,0,1]]}},` +
	`{"schema":{"name":"up","refId":"A","fields":[{"name":"Time","type":"time"},{"name":"Value","type":"number","labels":{"job":"api"}}]},"data":{"values":[[1000,2000],[1,1]]}}]`

func TestDatasourceQueryIsBoundedAndReturnsRows(t *testing.T) {
	r := queryRoutes(t, "prometheus", func(body map[string]any) {
		if body["from"] != "1000" || body["to"] != "3601000" {
			t.Errorf("range = %v..%v", body["from"], body["to"])
		}
		q := body["queries"].([]any)[0].(map[string]any)
		ds := q["datasource"].(map[string]any)
		if len(body["queries"].([]any)) != 1 || q["refId"] != "A" || q["expr"] != "up" || ds["uid"] != dsUID || ds["type"] != "prometheus" ||
			q["maxDataPoints"] != float64(4) || q["range"] != true {
			t.Errorf("query = %v", q)
		}
		if q["intervalMs"] != float64(900000) {
			t.Errorf("intervalMs = %v, want the window over max_rows", q["intervalMs"])
		}
	}, twoFrames)
	res := execute(t, r, "datasource.query", "datasources/"+dsUID+"/query", input.GrafanaDatasourceQuery{Expr: "up", From: 1000, To: 3601000, MaxRows: 4}).(QueryResult)
	if !res.Truncated || len(res.Frames) != 2 {
		t.Fatalf("result = %+v", res)
	}
	f0, f1 := res.Frames[0], res.Frames[1]
	if f0.Name != "up" || len(f0.Fields) != 2 || f0.Fields[1].Labels["job"] != "node" || len(f0.Rows) != 3 || f0.Rows[1][0] != float64(2000) || f0.Rows[1][1] != float64(0) {
		t.Fatalf("frame 0 = %+v", f0)
	}
	if len(f1.Rows) != 1 {
		t.Fatalf("frame 1 rows = %d, want 1 (4 rows in all)", len(f1.Rows))
	}
}

func TestDatasourceQueryDefaultsToTheLastHour(t *testing.T) {
	r := queryRoutes(t, "loki", func(body map[string]any) {
		if body["to"] != itoa(now.UnixMilli()) || body["from"] != itoa(now.Add(-time.Hour).UnixMilli()) {
			t.Errorf("range = %v..%v", body["from"], body["to"])
		}
		q := body["queries"].([]any)[0].(map[string]any)
		if q["queryType"] != "range" || q["maxLines"] != float64(defaultMaxRows) || q["maxDataPoints"] != float64(defaultMaxRows) {
			t.Errorf("loki query = %v", q)
		}
	}, `[]`)
	res := execute(t, r, "datasource.query", "datasources/"+dsUID+"/query", input.GrafanaDatasourceQuery{Expr: `{app="api"}`}).(QueryResult)
	if res.Truncated || len(res.Frames) != 0 {
		t.Fatalf("result = %+v", res)
	}
}

// Only datasources whose query language cannot write are queried: a SQL
// datasource is refused after the type lookup, before any query is sent.
func TestDatasourceQueryRefusesWritableDatasourceTypes(t *testing.T) {
	for _, dsType := range []string{"postgres", "mysql", "influxdb", "elasticsearch"} {
		queried := false
		r := queryRoutes(t, dsType, func(map[string]any) { queried = true }, `[]`)
		_, err := Connector{}.Execute(context.Background(), call(r, "datasource.query", "datasources/"+dsUID+"/query", input.GrafanaDatasourceQuery{Expr: "DELETE FROM users"}))
		if !errors.Is(err, connector.ErrInput) || queried || r.Count() != 1 {
			t.Fatalf("%s: err = %v, queried = %v, requests = %d", dsType, err, queried, r.Count())
		}
	}
}

func TestDatasourceQueryErrorDoesNotSurfaceProviderText(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, req *http.Request, _ map[string]any) {
		if strings.HasSuffix(req.URL.Path, "/ds/query") {
			_, _ = io.WriteString(w, `{"results":{"A":{"status":400,"error":"parse error near `+token+`"}}}`)
			return
		}
		_, _ = io.WriteString(w, datasourceJSON)
	})
	_, err := Connector{}.Execute(context.Background(), call(r, "datasource.query", "datasources/"+dsUID+"/query", input.GrafanaDatasourceQuery{Expr: "up("}))
	if err == nil || strings.Contains(err.Error(), "parse error") || strings.Contains(err.Error(), token) {
		t.Fatalf("err = %v", err)
	}
}

func lookup(ips ...string) func(context.Context, string) ([]net.IP, error) {
	return func(context.Context, string) ([]net.IP, error) {
		var out []net.IP
		for _, ip := range ips {
			out = append(out, net.ParseIP(ip))
		}
		return out, nil
	}
}

// Self-hosted Grafana is usually internal, so private and loopback addresses
// are allowed.
func TestPrivateGrafanaHostsAreAllowed(t *testing.T) {
	for _, ip := range []string{"10.0.0.5", "192.168.1.10", "172.16.0.2", "127.0.0.1", "fd12:3456::1", "100.64.0.1"} {
		r := routes(t, func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
			_, _ = io.WriteString(w, `[]`)
		})
		c := call(r, "datasource.list", "datasources", input.Empty{})
		c.LookupIP = lookup(ip)
		if _, err := (Connector{}).Execute(context.Background(), c); err != nil {
			t.Fatalf("%s: %v", ip, err)
		}
	}
}

// Every bad config, resource, input, or credential fails closed before any
// request.
func TestFailsClosedWithoutAProviderRequest(t *testing.T) {
	cases := []struct {
		name       string
		capability string
		resource   string
		in         any
		mutate     func(*connector.Call)
		want       error
	}{
		{"missing credential", "datasource.list", "datasources", input.Empty{}, func(c *connector.Call) { c.Credential = "" }, connector.ErrConfig},
		{"oauth descriptor", "datasource.list", "datasources", input.Empty{}, func(c *connector.Call) { c.Meta.CredentialSource = contract.CredentialSourceOAuth }, connector.ErrConfig},
		{"missing base_url", "datasource.list", "datasources", input.Empty{}, func(c *connector.Call) { c.Meta.Grafana = nil }, connector.ErrConfig},
		{"plain http base_url", "datasource.list", "datasources", input.Empty{}, func(c *connector.Call) { c.Meta.Grafana.BaseURL = "http://" + host }, connector.ErrConfig},
		{"userinfo in base_url", "datasource.list", "datasources", input.Empty{}, func(c *connector.Call) { c.Meta.Grafana.BaseURL = "https://admin:pw@" + host }, connector.ErrConfig},
		{"query in base_url", "datasource.list", "datasources", input.Empty{}, func(c *connector.Call) { c.Meta.Grafana.BaseURL = baseURL + "?orgId=2" }, connector.ErrConfig},
		{"path in base_url", "datasource.list", "datasources", input.Empty{}, func(c *connector.Call) { c.Meta.Grafana.BaseURL = baseURL + "/grafana" }, connector.ErrConfig},
		{"empty base_url", "datasource.list", "datasources", input.Empty{}, func(c *connector.Call) { c.Meta.Grafana.BaseURL = "" }, connector.ErrConfig},
		{"aws metadata address", "datasource.list", "datasources", input.Empty{}, func(c *connector.Call) { c.LookupIP = lookup("169.254.169.254") }, connector.ErrConfig},
		{"link-local address", "datasource.list", "datasources", input.Empty{}, func(c *connector.Call) { c.LookupIP = lookup("10.0.0.5", "169.254.10.1") }, connector.ErrConfig},
		{"ipv6 link-local", "datasource.list", "datasources", input.Empty{}, func(c *connector.Call) { c.LookupIP = lookup("fe80::1") }, connector.ErrConfig},
		{"aws ipv6 metadata", "datasource.list", "datasources", input.Empty{}, func(c *connector.Call) { c.LookupIP = lookup("fd00:ec2::254") }, connector.ErrConfig},
		{"alibaba metadata", "datasource.list", "datasources", input.Empty{}, func(c *connector.Call) { c.LookupIP = lookup("100.100.100.200") }, connector.ErrConfig},
		{"unspecified address", "datasource.list", "datasources", input.Empty{}, func(c *connector.Call) { c.LookupIP = lookup("0.0.0.0") }, connector.ErrConfig},
		{"metadata hostname", "datasource.list", "datasources", input.Empty{}, func(c *connector.Call) { c.Meta.Grafana.BaseURL = "https://metadata.google.internal" }, connector.ErrConfig},
		{"metadata ip literal", "datasource.list", "datasources", input.Empty{}, func(c *connector.Call) { c.Meta.Grafana.BaseURL = "https://169.254.169.254" }, connector.ErrConfig},
		{"unresolvable host", "datasource.list", "datasources", input.Empty{}, func(c *connector.Call) { c.LookupIP = lookup() }, connector.ErrConfig},
		{"bad uid", "folder.read", "folders/../admin", input.Empty{}, nil, connector.ErrInput},
		{"extra segment", "dashboard.read", "dashboards/d1/versions", input.Empty{}, nil, connector.ErrInput},
		{"wrong resource for capability", "datasource.list", "datasources/" + dsUID, input.Empty{}, nil, connector.ErrInput},
		{"wrong input type", "datasource.query", "datasources/" + dsUID + "/query", input.Empty{}, nil, connector.ErrInput},
		{"unknown capability", "dashboard.write", "dashboards/d1", input.Empty{}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := routes(t, func(http.ResponseWriter, *http.Request, map[string]any) {})
			c := call(r, tc.capability, tc.resource, tc.in)
			if tc.mutate != nil {
				tc.mutate(&c)
			}
			_, err := Connector{}.Execute(context.Background(), c)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), token) {
				t.Fatalf("error leaked the token: %v", err)
			}
			if r.Count() != 0 {
				t.Fatalf("provider requests = %d, want 0", r.Count())
			}
		})
	}
}

func TestProviderStatusesFailWithoutLeakingOrRetrying(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusTooManyRequests, http.StatusInternalServerError} {
		r := routes(t, func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"message":"invalid API key `+token+`"}`)
		})
		_, err := Connector{}.Execute(context.Background(), call(r, "folder.read", "folders/f1", input.Empty{}))
		if err == nil || strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "invalid API key") {
			t.Fatalf("status %d: err = %v", status, err)
		}
		if r.Count() != 1 {
			t.Fatalf("status %d: requests = %d, want 1", status, r.Count())
		}
	}
}

// A redirect is never followed: it could carry the token to a host the
// base_url check never saw.
func TestRedirectsAreNotFollowed(t *testing.T) {
	r := routes(t, func(w http.ResponseWriter, _ *http.Request, _ map[string]any) {
		w.Header().Set("Location", "https://169.254.169.254/latest/meta-data/")
		w.WriteHeader(http.StatusFound)
	})
	_, err := Connector{}.Execute(context.Background(), call(r, "folder.read", "folders/f1", input.Empty{}))
	if err == nil || r.Count() != 1 {
		t.Fatalf("err = %v, requests = %d", err, r.Count())
	}
}
