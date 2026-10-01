// Package input reads and validates the capability input of `kei-proxy
// connector invoke` (docs/connector-execution-contract.md, section 5). The
// input never leaves the runtime: the catalog sees only its digest.
// Validation is fail-closed and runs in two phases: Canonicalize checks the
// shape before the catalog is asked anything, and Decode applies the strict
// per-capability schema once the catalog's descriptor names the provider.
package input

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/HaikeiLabs/kei-connector-contracts/providers"
)

// MaxBytes is the largest input accepted.
const MaxBytes = 16 << 10

// ErrInvalid is returned for every input the contract does not accept.
var ErrInvalid = errors.New("connector input is invalid")

// Read returns the raw input named by --input: a literal JSON object,
// "@<file>", or "-" for stdin. An empty argument means an empty object.
func Read(arg string, stdin io.Reader) ([]byte, error) {
	var r io.Reader
	switch {
	case arg == "":
		return []byte("{}"), nil
	case arg == "-":
		r = stdin
	case strings.HasPrefix(arg, "@"):
		f, err := os.Open(strings.TrimPrefix(arg, "@"))
		if err != nil {
			return nil, ErrInvalid
		}
		defer f.Close()
		r = f
	default:
		r = strings.NewReader(arg)
	}
	if r == nil {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil || len(raw) > MaxBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}

// Canonicalize checks that raw is exactly one JSON object and returns its
// canonical encoding (sorted keys, numbers as written) and "sha256:<hex>" of
// that encoding.
func Canonicalize(raw []byte) (json.RawMessage, string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, "", ErrInvalid
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, "", ErrInvalid
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, "", ErrInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, "", ErrInvalid
	}
	sum := sha256.Sum256(canonical)
	return canonical, "sha256:" + hex.EncodeToString(sum[:]), nil
}

// GmailMessageSearch is the gmail/message.search input.
type GmailMessageSearch struct {
	Query     string `json:"query,omitempty"`
	PageSize  int    `json:"page_size,omitempty"`
	PageToken string `json:"page_token,omitempty"`
}

// GmailMessageGet is the gmail/message.get input.
type GmailMessageGet struct {
	MessageID string `json:"message_id,omitempty"`
}

// DriveSearch is the google_drive/drive.search input.
type DriveSearch struct {
	Query string `json:"query"`
}

// TitoEventList is the tito/event.list input.
type TitoEventList struct {
	Status string `json:"status,omitempty"`
	Page   int    `json:"page,omitempty"`
}

// NotionSearch is the notion/search input. An empty query lists what the
// integration can see.
type NotionSearch struct {
	Query    string `json:"query,omitempty"`
	PageSize int    `json:"page_size,omitempty"`
}

// NotionDatabaseQuery is the notion/database.query input. Filters and sorts
// are not accepted yet.
type NotionDatabaseQuery struct {
	PageSize int `json:"page_size,omitempty"`
}

// DiscordGuildList is the discord/guild.list input. After is the guild-id
// cursor from a previous page's next_after.
type DiscordGuildList struct {
	Limit int    `json:"limit,omitempty"`
	After string `json:"after,omitempty"`
}

// DiscordMessageList is the discord/message.list input. Before and After are
// message-id cursors; at most one may be set (newest first when neither is).
type DiscordMessageList struct {
	Limit  int    `json:"limit,omitempty"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// snowflake is a Discord id: 17 to 20 decimal digits.
var snowflake = regexp.MustCompile(`^[0-9]{17,20}$`)

// optionalSnowflake reports whether s is empty or a Discord id.
func optionalSnowflake(s string) bool { return s == "" || snowflake.MatchString(s) }

// GrafanaFolderList is the grafana/folder.list input. Page is 1-based.
type GrafanaFolderList struct {
	Limit int `json:"limit,omitempty"`
	Page  int `json:"page,omitempty"`
}

// GrafanaDashboardSearch is the grafana/dashboard.search input. It searches
// dashboards only; folders are listed by folder.list.
type GrafanaDashboardSearch struct {
	Query string   `json:"query,omitempty"`
	Tags  []string `json:"tags,omitempty"`
	Limit int      `json:"limit,omitempty"`
	Page  int      `json:"page,omitempty"`
}

// GrafanaAnnotationList is the grafana/annotation.list input. From and To are
// epoch milliseconds, set together, at most 30 days apart; when neither is
// set the connector reads the last 24 hours.
type GrafanaAnnotationList struct {
	From         int64    `json:"from,omitempty"`
	To           int64    `json:"to,omitempty"`
	DashboardUID string   `json:"dashboard_uid,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Limit        int      `json:"limit,omitempty"`
}

// GrafanaDatasourceQuery is the grafana/datasource.query input: one query
// expression (PromQL or LogQL), a time range in epoch milliseconds at most 7
// days long (the last hour when neither is set), and a row cap.
type GrafanaDatasourceQuery struct {
	Expr    string `json:"expr"`
	From    int64  `json:"from,omitempty"`
	To      int64  `json:"to,omitempty"`
	MaxRows int    `json:"max_rows,omitempty"`
}

const day = int64(24 * 60 * 60 * 1000)

// grafanaUID is a Grafana uid.
var grafanaUID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)

// timeRange reports whether from and to are both unset, or both set with
// from < to and a window of at most maxWindow milliseconds.
func timeRange(from, to, maxWindow int64) bool {
	if from == 0 && to == 0 {
		return true
	}
	return from > 0 && to > from && to-from <= maxWindow
}

// tags reports whether ts has at most 10 tags of 1..64 characters.
func tags(ts []string) bool {
	if len(ts) > 10 {
		return false
	}
	for _, t := range ts {
		if t == "" || len(t) > 64 {
			return false
		}
	}
	return true
}

// CRMInvestorList is the crm/investor.list input. Its bounds are the
// contract's (providers.InvestorListPayload.Validate).
type CRMInvestorList = providers.InvestorListPayload

// CRMInvestorUpdate is the crm/investor.update input. Its bounds are the
// contract's (providers.InvestorUpdatePayload.Validate).
type CRMInvestorUpdate = providers.InvestorUpdatePayload

// HTTPRequest is the http_api/http.get and http.head input. Method comes from
// the capability, never from the input.
type HTTPRequest struct {
	Method string              `json:"-"`
	Path   string              `json:"path"`
	Query  map[string][]string `json:"query,omitempty"`
}

// Empty is the input of every read capability whose resource names
// everything it needs.
type Empty struct{}

// emptyInput lists the read capabilities that take no input.
var emptyInput = map[string]bool{
	"google_drive/drive.metadata.read": true, "google_drive/docs.read": true,
	"linear/team.read": true, "linear/project.read": true, "linear/cycle.read": true, "linear/issue.read": true,
	"github/repository.read": true, "github/issue.read": true, "github/pull_request.read": true,
	"github/check.read": true, "github/workflow.read": true,
	"tito/event.get": true, "tito/release.list": true, "tito/ticket.summary": true,
	"crm/lead.read": true, "crm/investor.read": true,
	"notion/page.read":   true,
	"discord/guild.read": true, "discord/channel.list": true, "discord/channel.read": true,
	"discord/thread.list": true, "discord/message.read": true, "discord/role.list": true,
	"grafana/folder.read": true, "grafana/dashboard.read": true, "grafana/datasource.list": true,
	"grafana/datasource.read": true, "grafana/alert_rule.list": true,
}

// Decode strictly decodes a canonical input for one provider capability.
// Unknown fields, wrong types, out-of-range values, and capabilities without
// a read schema are all ErrInvalid.
func Decode(provider, capability string, raw json.RawMessage) (any, error) {
	switch key := provider + "/" + capability; key {
	case "gmail/message.search":
		var in GmailMessageSearch
		if strict(raw, &in) != nil || len(in.Query) > 512 || in.PageSize < 0 || in.PageSize > 25 || len(in.PageToken) > 256 {
			return nil, ErrInvalid
		}
		return in, nil
	case "gmail/message.get":
		var in GmailMessageGet
		if strict(raw, &in) != nil || len(in.MessageID) > 256 {
			return nil, ErrInvalid
		}
		return in, nil
	case "google_drive/drive.search":
		var in DriveSearch
		if strict(raw, &in) != nil || in.Query == "" || len(in.Query) > 512 {
			return nil, ErrInvalid
		}
		return in, nil
	case "tito/event.list":
		var in TitoEventList
		if strict(raw, &in) != nil || in.Page < 0 {
			return nil, ErrInvalid
		}
		switch in.Status {
		case "", "upcoming", "past", "archived":
			return in, nil
		}
		return nil, ErrInvalid
	case "notion/search":
		var in NotionSearch
		if strict(raw, &in) != nil || len(in.Query) > 512 || in.PageSize < 0 || in.PageSize > 25 {
			return nil, ErrInvalid
		}
		return in, nil
	case "notion/database.query":
		var in NotionDatabaseQuery
		if strict(raw, &in) != nil || in.PageSize < 0 || in.PageSize > 25 {
			return nil, ErrInvalid
		}
		return in, nil
	case "discord/guild.list":
		var in DiscordGuildList
		if strict(raw, &in) != nil || in.Limit < 0 || in.Limit > 100 || !optionalSnowflake(in.After) {
			return nil, ErrInvalid
		}
		return in, nil
	case "discord/message.list":
		var in DiscordMessageList
		if strict(raw, &in) != nil || in.Limit < 0 || in.Limit > 100 || !optionalSnowflake(in.Before) || !optionalSnowflake(in.After) ||
			(in.Before != "" && in.After != "") {
			return nil, ErrInvalid
		}
		return in, nil
	case "grafana/folder.list":
		var in GrafanaFolderList
		if strict(raw, &in) != nil || in.Limit < 0 || in.Limit > 100 || in.Page < 0 {
			return nil, ErrInvalid
		}
		return in, nil
	case "grafana/dashboard.search":
		var in GrafanaDashboardSearch
		if strict(raw, &in) != nil || len(in.Query) > 256 || !tags(in.Tags) || in.Limit < 0 || in.Limit > 100 || in.Page < 0 {
			return nil, ErrInvalid
		}
		return in, nil
	case "grafana/annotation.list":
		var in GrafanaAnnotationList
		if strict(raw, &in) != nil || !timeRange(in.From, in.To, 30*day) || !tags(in.Tags) || in.Limit < 0 || in.Limit > 100 ||
			(in.DashboardUID != "" && !grafanaUID.MatchString(in.DashboardUID)) {
			return nil, ErrInvalid
		}
		return in, nil
	case "grafana/datasource.query":
		var in GrafanaDatasourceQuery
		if strict(raw, &in) != nil || in.Expr == "" || len(in.Expr) > 4096 || !timeRange(in.From, in.To, 7*day) || in.MaxRows < 0 || in.MaxRows > 1000 {
			return nil, ErrInvalid
		}
		return in, nil
	case "crm/investor.list":
		var in CRMInvestorList
		if strict(raw, &in) != nil || in.Validate() != nil {
			return nil, ErrInvalid
		}
		return in, nil
	case "crm/investor.update":
		var in CRMInvestorUpdate
		if strict(raw, &in) != nil || in.Validate() != nil {
			return nil, ErrInvalid
		}
		return in, nil
	case "http_api/http.get", "http_api/http.head":
		var in HTTPRequest
		if strict(raw, &in) != nil || in.Path == "" {
			return nil, ErrInvalid
		}
		in.Method = "GET"
		if capability == "http.head" {
			in.Method = "HEAD"
		}
		return in, nil
	default:
		if !emptyInput[key] {
			return nil, fmt.Errorf("%w: no read input schema for %s", ErrInvalid, key)
		}
		if strict(raw, &Empty{}) != nil {
			return nil, ErrInvalid
		}
		return Empty{}, nil
	}
}

func strict(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}
