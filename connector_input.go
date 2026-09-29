package connectorruntime

// Capability input for `kei-proxy connector invoke` (connector execution
// contract, section 5). The input never leaves the runtime: the catalog sees
// only its digest. Validation happens twice, both fail-closed: a shape check
// before the catalog is asked anything, and a strict per-capability decode
// once the catalog's descriptor names the provider.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/HaikeiLabs/kei-connector-contracts"
	"github.com/HaikeiLabs/kei-connector-contracts/providers"
)

const maxConnectorInputBytes = 16 << 10

var errConnectorInputInvalid = errors.New("connector input is invalid")

// readConnectorInput returns the raw input named by --input: a literal JSON
// object, "@<file>", or "-" for stdin. No flag means an empty object.
func readConnectorInput(arg string, stdin io.Reader) ([]byte, error) {
	var r io.Reader
	switch {
	case arg == "":
		return []byte("{}"), nil
	case arg == "-":
		r = stdin
	case strings.HasPrefix(arg, "@"):
		f, err := os.Open(strings.TrimPrefix(arg, "@"))
		if err != nil {
			return nil, errConnectorInputInvalid
		}
		defer f.Close()
		r = f
	default:
		r = strings.NewReader(arg)
	}
	if r == nil {
		return nil, errConnectorInputInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxConnectorInputBytes+1))
	if err != nil || len(raw) > maxConnectorInputBytes {
		return nil, errConnectorInputInvalid
	}
	return raw, nil
}

// canonicalizeConnectorInput checks that raw is exactly one JSON object and
// returns its canonical encoding (sorted keys, numbers preserved) and
// "sha256:<hex>" of that encoding.
func canonicalizeConnectorInput(raw []byte) (json.RawMessage, string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, "", errConnectorInputInvalid
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, "", errConnectorInputInvalid
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, "", errConnectorInputInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, "", errConnectorInputInvalid
	}
	sum := sha256.Sum256(canonical)
	return canonical, "sha256:" + hex.EncodeToString(sum[:]), nil
}

// decodedInput is a capability input after the strict decode.
type decodedInput struct {
	payload providers.Payload
	http    *connectors.HTTPInvocation
}

type empty struct{}

// decodeConnectorInput decodes input strictly for one provider capability:
// unknown fields, wrong types, and out-of-range values are rejected.
func decodeConnectorInput(provider connectors.Provider, capability string, input json.RawMessage) (decodedInput, error) {
	key := string(provider) + "/" + capability
	switch key {
	case "gmail/message.search":
		var p providers.MessageSearchPayload
		if err := strictDecode(input, &p); err != nil || len(p.Query) > 512 || p.PageSize < 0 || p.PageSize > 25 || len(p.PageToken) > 256 {
			return decodedInput{}, errConnectorInputInvalid
		}
		return decodedInput{payload: p}, nil
	case "gmail/message.get":
		var p providers.MessageGetPayload
		if err := strictDecode(input, &p); err != nil || len(p.MessageID) > 256 {
			return decodedInput{}, errConnectorInputInvalid
		}
		return decodedInput{payload: p}, nil
	case "google_drive/drive.search":
		var p providers.DriveSearchPayload
		if err := strictDecode(input, &p); err != nil || p.Query == "" || len(p.Query) > 512 {
			return decodedInput{}, errConnectorInputInvalid
		}
		return decodedInput{payload: p}, nil
	case "tito/event.list":
		var p providers.EventListPayload
		if err := strictDecode(input, &p); err != nil || p.Page < 0 {
			return decodedInput{}, errConnectorInputInvalid
		}
		switch p.Status {
		case "", "upcoming", "past", "archived":
		default:
			return decodedInput{}, errConnectorInputInvalid
		}
		return decodedInput{payload: p}, nil
	case "http_api/http.get", "http_api/http.head":
		var p struct {
			Path  string              `json:"path"`
			Query map[string][]string `json:"query,omitempty"`
		}
		if err := strictDecode(input, &p); err != nil || p.Path == "" {
			return decodedInput{}, errConnectorInputInvalid
		}
		method := connectors.HTTPMethod("GET")
		if capability == "http.head" {
			method = connectors.HTTPMethod("HEAD")
		}
		return decodedInput{http: &connectors.HTTPInvocation{Method: method, Path: p.Path, Query: p.Query}}, nil
	}
	payload, ok := emptyInputPayloads[key]
	if !ok {
		return decodedInput{}, fmt.Errorf("%w: no input schema for %s", errConnectorInputInvalid, key)
	}
	if err := strictDecode(input, &empty{}); err != nil {
		return decodedInput{}, errConnectorInputInvalid
	}
	return decodedInput{payload: payload}, nil
}

// emptyInputPayloads are the read capabilities that take no input: the
// resource names everything. crm/lead.read has no provider payload; its
// client is the runtime's own.
var emptyInputPayloads = map[string]providers.Payload{
	"google_drive/drive.metadata.read": providers.DriveMetadataPayload{},
	"google_drive/docs.read":           providers.DocsReadPayload{},
	"linear/team.read":                 providers.TeamReadPayload{},
	"linear/project.read":              providers.ProjectReadPayload{},
	"linear/cycle.read":                providers.CycleReadPayload{},
	"linear/issue.read":                providers.LinearIssueReadPayload{},
	"github/repository.read":           providers.RepositoryReadPayload{},
	"github/issue.read":                providers.GitHubIssueReadPayload{},
	"github/pull_request.read":         providers.PullRequestReadPayload{},
	"github/check.read":                providers.CheckReadPayload{},
	"github/workflow.read":             providers.WorkflowReadPayload{},
	"tito/event.get":                   providers.EventGetPayload{},
	"tito/release.list":                providers.ReleaseListPayload{},
	"tito/ticket.summary":              providers.TicketSummaryPayload{},
	"crm/lead.read":                    nil,
}

func strictDecode(input json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errConnectorInputInvalid
	}
	return nil
}
