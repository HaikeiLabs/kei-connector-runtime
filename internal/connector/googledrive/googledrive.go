// Package googledrive is the google_drive connector: drive.search,
// drive.metadata.read, and docs.read through the kei-connector-contracts
// Google client. Search and metadata never carry file content; docs.read
// returns the document text, capped at MaxDocumentBytes.
package googledrive

import (
	"context"
	"strings"

	"github.com/HaikeiLabs/kei-connector-contracts/providers"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

// MaxDocumentBytes caps docs.read text; a larger document is refused rather
// than truncated.
const MaxDocumentBytes = 256 << 10

// Document is the docs.read result.
type Document struct {
	FileID string `json:"file_id"`
	Text   string `json:"text"`
}

// Connector executes google_drive reads.
type Connector struct{}

// Execute runs one google_drive read.
func (Connector) Execute(ctx context.Context, call connector.Call) (any, error) {
	var payload providers.Payload
	switch in := call.Input.(type) {
	case input.DriveSearch:
		payload = providers.DriveSearchPayload{Query: in.Query}
	case input.Empty:
		switch call.Invocation.Capability {
		case "drive.metadata.read":
			payload = providers.DriveMetadataPayload{}
		case "docs.read":
			payload = providers.DocsReadPayload{}
		default:
			return nil, connector.ErrInput
		}
	default:
		return nil, connector.ErrInput
	}
	res, err := providers.NewAuthenticatedGoogle(call.RuntimeConfig()).Invoke(ctx, call.Meta, call.Invocation, payload)
	if err != nil {
		return nil, err
	}
	if text, ok := res.Data.(string); ok {
		if len(text) > MaxDocumentBytes {
			return nil, connector.ErrTooLarge
		}
		return Document{FileID: call.Invocation.Resource[strings.LastIndex(call.Invocation.Resource, "/")+1:], Text: text}, nil
	}
	return res.Data, nil
}
