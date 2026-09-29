package input

import (
	"errors"
	"os"
	"path/filepath"
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
