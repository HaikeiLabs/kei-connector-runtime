package input

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReadTakesLiteralFileOrStdin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "in.json")
	if err := os.WriteFile(path, []byte(`{"query":"from:file"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		arg, stdin, want string
	}{
		"default": {"", "", `{}`},
		"literal": {`{"query":"x"}`, "", `{"query":"x"}`},
		"file":    {"@" + path, "", `{"query":"from:file"}`},
		"stdin":   {"-", `{"query":"from:stdin"}`, `{"query":"from:stdin"}`},
	}
	for name, tc := range cases {
		got, err := Read(tc.arg, strings.NewReader(tc.stdin))
		if err != nil || string(got) != tc.want {
			t.Errorf("%s: Read = %q, %v; want %q", name, got, err, tc.want)
		}
	}
}

func TestReadRejectsOversizeAndMissingFile(t *testing.T) {
	if _, err := Read(`{"q":"`+strings.Repeat("a", MaxBytes)+`"}`, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("oversize literal: err = %v", err)
	}
	if _, err := Read("-", strings.NewReader(strings.Repeat("a", MaxBytes+1))); !errors.Is(err, ErrInvalid) {
		t.Errorf("oversize stdin: err = %v", err)
	}
	if _, err := Read("@/nonexistent/in.json", nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("missing file: err = %v", err)
	}
}

// The digest must not depend on key order or whitespace, and big numbers
// survive unchanged.
func TestCanonicalizeIsStableAndDigestsTheCanonicalForm(t *testing.T) {
	a, da, err := Canonicalize([]byte(`{"b":1, "a":"x", "n":12345678901234567890}`))
	if err != nil {
		t.Fatal(err)
	}
	b, db, err := Canonicalize([]byte("{\n\"n\":12345678901234567890,\"a\":\"x\",\"b\":1}"))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != `{"a":"x","b":1,"n":12345678901234567890}` || string(a) != string(b) || da != db {
		t.Fatalf("canonical = %s / %s, digests %s / %s", a, b, da, db)
	}
	if !strings.HasPrefix(da, "sha256:") || len(da) != len("sha256:")+64 {
		t.Fatalf("digest = %q", da)
	}
}

func TestCanonicalizeRejectsNonObjects(t *testing.T) {
	for _, raw := range []string{``, `[]`, `"s"`, `1`, `null`, `{"a":1}{"b":2}`, `{"a":`} {
		if _, _, err := Canonicalize([]byte(raw)); !errors.Is(err, ErrInvalid) {
			t.Errorf("Canonicalize(%q) err = %v", raw, err)
		}
	}
}

func TestDecodeReturnsTypedInputs(t *testing.T) {
	got, err := Decode("gmail", "message.search", []byte(`{"query":"from:alice","page_size":5,"page_token":"p-1"}`))
	if err != nil || got != (GmailMessageSearch{Query: "from:alice", PageSize: 5, PageToken: "p-1"}) {
		t.Fatalf("gmail search = %#v, %v", got, err)
	}
	if got, err := Decode("gmail", "message.get", []byte(`{"message_id":"m-1"}`)); err != nil || got != (GmailMessageGet{MessageID: "m-1"}) {
		t.Fatalf("gmail get = %#v, %v", got, err)
	}
	if got, err := Decode("google_drive", "drive.search", []byte(`{"query":"plan"}`)); err != nil || got != (DriveSearch{Query: "plan"}) {
		t.Fatalf("drive search = %#v, %v", got, err)
	}
	if got, err := Decode("tito", "event.list", []byte(`{"status":"past","page":2}`)); err != nil || got != (TitoEventList{Status: "past", Page: 2}) {
		t.Fatalf("tito list = %#v, %v", got, err)
	}
	h, err := Decode("http_api", "http.get", []byte(`{"path":"/leads","query":{"limit":["5"]}}`))
	if req, ok := h.(HTTPRequest); err != nil || !ok || req.Method != "GET" || req.Path != "/leads" || req.Query["limit"][0] != "5" {
		t.Fatalf("http_api get = %#v, %v", h, err)
	}
	if h, _ := Decode("http_api", "http.head", []byte(`{"path":"/leads"}`)); h.(HTTPRequest).Method != "HEAD" {
		t.Fatalf("http_api head method = %#v", h)
	}
	for _, key := range [][2]string{
		{"linear", "issue.read"}, {"linear", "team.read"}, {"github", "repository.read"}, {"github", "workflow.read"},
		{"google_drive", "docs.read"}, {"tito", "ticket.summary"}, {"crm", "lead.read"}, {"crm", "investor.read"},
	} {
		if got, err := Decode(key[0], key[1], []byte(`{}`)); err != nil || got != (Empty{}) {
			t.Errorf("%s/%s = %#v, %v", key[0], key[1], got, err)
		}
	}
}

func TestDecodeRejectsInvalidInput(t *testing.T) {
	cases := []struct{ provider, capability, input string }{
		{"gmail", "message.search", `{"query":"x","body":true}`},
		{"gmail", "message.search", `{"page_size":26}`},
		{"gmail", "message.search", `{"page_size":-1}`},
		{"gmail", "message.search", `{"query":"` + strings.Repeat("q", 513) + `"}`},
		{"gmail", "message.search", `{"page_size":"5"}`},
		{"gmail", "message.get", `{"message_id":"` + strings.Repeat("m", 257) + `"}`},
		{"google_drive", "drive.search", `{}`},
		{"tito", "event.list", `{"status":"all"}`},
		{"tito", "event.list", `{"page":-1}`},
		{"http_api", "http.get", `{}`},
		{"http_api", "http.get", `{"path":"/x","method":"POST"}`},
		{"linear", "issue.read", `{"id":"ENG-1"}`},
		{"crm", "lead.create", `{"data":{}}`},
		{"crm", "investor.read", `{"investor_id":"7"}`},
		{"crm", "investor.list", `{"stage":"won"}`},
		{"crm", "investor.list", `{"q":"` + strings.Repeat("q", 201) + `"}`},
		{"crm", "investor.list", `{"limit":101}`},
		{"crm", "investor.list", `{"limit":-1}`},
		{"crm", "investor.list", `{"limit":"5"}`},
		{"crm", "investor.list", `{"cursor":"` + strings.Repeat("c", 129) + `"}`},
		{"crm", "investor.list", `{"data":{"stage":"meeting"}}`},
		{"crm", "investor.list", `{"tenant_id":"t-2"}`},
		{"s3", "object.read", `{}`},
	}
	for _, tc := range cases {
		if _, err := Decode(tc.provider, tc.capability, []byte(tc.input)); !errors.Is(err, ErrInvalid) {
			t.Errorf("Decode(%s, %s, %s) err = %v", tc.provider, tc.capability, tc.input, err)
		}
	}
}

func TestDecodeCRMInvestorList(t *testing.T) {
	got, err := Decode("crm", "investor.list", []byte(`{"stage":"diligence","q":"north","limit":5,"cursor":"eyJpZCI6N30"}`))
	want := CRMInvestorList{Stage: "diligence", Query: "north", Limit: 5, Cursor: "eyJpZCI6N30"}
	if err != nil || got != want {
		t.Fatalf("investor.list = %#v, %v", got, err)
	}
	if got, err := Decode("crm", "investor.list", []byte(`{}`)); err != nil || got != (CRMInvestorList{}) {
		t.Fatalf("empty investor.list = %#v, %v", got, err)
	}
}

func TestDecodeNotion(t *testing.T) {
	if got, err := Decode("notion", "search", []byte(`{"query":"roadmap","page_size":5}`)); err != nil || got != (NotionSearch{Query: "roadmap", PageSize: 5}) {
		t.Fatalf("notion search = %#v, %v", got, err)
	}
	// An empty query lists what the integration can see, like Notion's own search.
	if got, err := Decode("notion", "search", []byte(`{}`)); err != nil || got != (NotionSearch{}) {
		t.Fatalf("empty notion search = %#v, %v", got, err)
	}
	if got, err := Decode("notion", "database.query", []byte(`{"page_size":25}`)); err != nil || got != (NotionDatabaseQuery{PageSize: 25}) {
		t.Fatalf("notion database.query = %#v, %v", got, err)
	}
	if got, err := Decode("notion", "page.read", []byte(`{}`)); err != nil || got != (Empty{}) {
		t.Fatalf("notion page.read = %#v, %v", got, err)
	}
}

func TestDecodeRejectsInvalidNotionInput(t *testing.T) {
	cases := []struct{ capability, input string }{
		{"search", `{"query":"` + strings.Repeat("q", 513) + `"}`},
		{"search", `{"page_size":26}`},
		{"search", `{"page_size":-1}`},
		{"search", `{"query":1}`},
		{"search", `{"filter":{"property":"object","value":"page"}}`},
		{"database.query", `{"page_size":26}`},
		{"database.query", `{"filter":{"property":"Status"}}`},
		{"database.query", `{"sorts":[]}`},
		{"page.read", `{"page_id":"p-1"}`},
		{"page.write", `{}`},
	}
	for _, tc := range cases {
		if _, err := Decode("notion", tc.capability, []byte(tc.input)); !errors.Is(err, ErrInvalid) {
			t.Errorf("Decode(notion, %s, %s) err = %v", tc.capability, tc.input, err)
		}
	}
}

func TestDecodeDiscord(t *testing.T) {
	if got, err := Decode("discord", "guild.list", []byte(`{"limit":100,"after":"223456789012345678"}`)); err != nil || got != (DiscordGuildList{Limit: 100, After: "223456789012345678"}) {
		t.Fatalf("discord guild.list = %#v, %v", got, err)
	}
	if got, err := Decode("discord", "message.list", []byte(`{"limit":50,"before":"523456789012345678"}`)); err != nil || got != (DiscordMessageList{Limit: 50, Before: "523456789012345678"}) {
		t.Fatalf("discord message.list = %#v, %v", got, err)
	}
	if got, err := Decode("discord", "message.list", []byte(`{"after":"523456789012345678"}`)); err != nil || got != (DiscordMessageList{After: "523456789012345678"}) {
		t.Fatalf("discord message.list after = %#v, %v", got, err)
	}
	for _, capability := range []string{"guild.read", "channel.list", "channel.read", "thread.list", "message.read", "role.list"} {
		if got, err := Decode("discord", capability, []byte(`{}`)); err != nil || got != (Empty{}) {
			t.Fatalf("discord %s = %#v, %v", capability, got, err)
		}
	}
}

func TestDecodeRejectsInvalidDiscordInput(t *testing.T) {
	cases := []struct{ capability, input string }{
		{"guild.list", `{"limit":101}`},
		{"guild.list", `{"limit":-1}`},
		{"guild.list", `{"after":"abc"}`},
		{"guild.list", `{"after":"1234"}`},
		{"guild.list", `{"before":"223456789012345678"}`},
		{"message.list", `{"limit":101}`},
		{"message.list", `{"before":"x"}`},
		{"message.list", `{"before":"523456789012345678","after":"523456789012345679"}`},
		{"message.list", `{"around":"523456789012345678"}`},
		{"message.read", `{"message_id":"523456789012345678"}`},
		{"member.list", `{}`},
		{"message.write", `{}`},
	}
	for _, tc := range cases {
		if _, err := Decode("discord", tc.capability, []byte(tc.input)); !errors.Is(err, ErrInvalid) {
			t.Errorf("Decode(discord, %s, %s) err = %v", tc.capability, tc.input, err)
		}
	}
}

func TestDecodeGrafana(t *testing.T) {
	const day = int64(24 * 60 * 60 * 1000)
	from := int64(1_790_000_000_000)
	cases := []struct {
		capability, input string
		want              any
	}{
		{"folder.list", `{"limit":50,"page":2}`, GrafanaFolderList{Limit: 50, Page: 2}},
		{"dashboard.search", `{"query":"cpu","tags":["prod"],"limit":10}`, GrafanaDashboardSearch{Query: "cpu", Tags: []string{"prod"}, Limit: 10}},
		{"dashboard.search", `{}`, GrafanaDashboardSearch{}},
		{"annotation.list", fmt.Sprintf(`{"from":%d,"to":%d,"dashboard_uid":"abc-123","limit":5}`, from, from+30*day), GrafanaAnnotationList{From: from, To: from + 30*day, DashboardUID: "abc-123", Limit: 5}},
		{"annotation.list", `{}`, GrafanaAnnotationList{}},
		{"datasource.query", fmt.Sprintf(`{"expr":"up","from":%d,"to":%d,"max_rows":1000}`, from, from+7*day), GrafanaDatasourceQuery{Expr: "up", From: from, To: from + 7*day, MaxRows: 1000}},
		{"datasource.query", `{"expr":"rate(http_requests_total[5m])"}`, GrafanaDatasourceQuery{Expr: "rate(http_requests_total[5m])"}},
	}
	for _, tc := range cases {
		got, err := Decode("grafana", tc.capability, []byte(tc.input))
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Decode(grafana, %s, %s) = %#v, %v; want %#v", tc.capability, tc.input, got, err, tc.want)
		}
	}
	for _, capability := range []string{"folder.read", "dashboard.read", "datasource.list", "datasource.read", "alert_rule.list"} {
		if got, err := Decode("grafana", capability, []byte(`{}`)); err != nil || got != (Empty{}) {
			t.Fatalf("grafana %s = %#v, %v", capability, got, err)
		}
	}
}

func TestDecodeRejectsInvalidGrafanaInput(t *testing.T) {
	const day = int64(24 * 60 * 60 * 1000)
	from := int64(1_790_000_000_000)
	cases := []struct{ capability, input string }{
		{"folder.list", `{"limit":101}`},
		{"folder.list", `{"page":-1}`},
		{"dashboard.search", `{"query":"` + strings.Repeat("q", 257) + `"}`},
		{"dashboard.search", `{"tags":["a","b","c","d","e","f","g","h","i","j","k"]}`},
		{"dashboard.search", `{"tags":[""]}`},
		{"dashboard.search", `{"type":"dash-folder"}`},
		{"annotation.list", fmt.Sprintf(`{"from":%d}`, from)},
		{"annotation.list", fmt.Sprintf(`{"from":%d,"to":%d}`, from, from)},
		{"annotation.list", fmt.Sprintf(`{"from":%d,"to":%d}`, from, from+31*day)},
		{"annotation.list", `{"dashboard_uid":"../x"}`},
		{"annotation.list", `{"limit":101}`},
		{"datasource.query", `{}`},
		{"datasource.query", `{"expr":"` + strings.Repeat("x", 4097) + `"}`},
		{"datasource.query", fmt.Sprintf(`{"expr":"up","from":%d,"to":%d}`, from, from+7*day+1)},
		{"datasource.query", fmt.Sprintf(`{"expr":"up","from":%d,"to":%d}`, from+1, from)},
		{"datasource.query", `{"expr":"up","from":-5,"to":10}`},
		{"datasource.query", `{"expr":"up","max_rows":1001}`},
		{"datasource.query", `{"expr":"up","rawSql":"DELETE FROM users"}`},
		{"datasource.read", `{"uid":"x"}`},
		{"dashboard.write", `{}`},
	}
	for _, tc := range cases {
		if _, err := Decode("grafana", tc.capability, []byte(tc.input)); !errors.Is(err, ErrInvalid) {
			t.Errorf("Decode(grafana, %s, %s) err = %v", tc.capability, tc.input, err)
		}
	}
}
