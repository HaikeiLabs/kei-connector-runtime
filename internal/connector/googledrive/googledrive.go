// Package googledrive is the google_drive connector: bounded drive.search,
// drive.metadata.read, and docs.read through the kei-connector-contracts
// Google client, plus drive.doc.create and drive.doc.update for document
// writes. Search and metadata never carry file content; docs.read returns the
// document text, capped at MaxDocumentBytes. Write results return the created
// or updated document id.
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

// Connector executes google_drive capabilities.
type Connector struct{}

func driveIDFromResource(resource string) string {
	parts := strings.Split(resource, "/")
	if len(parts) != 2 || parts[0] != "drive" {
		return ""
	}
	return parts[1]
}

// Execute runs one google_drive capability.
func (Connector) Execute(ctx context.Context, call connector.Call) (any, error) {
	var payload providers.Payload
	switch in := call.Input.(type) {
	case input.DriveSearch:
		payload = providers.DriveSearchPayload{Query: in.Query}
	case input.DriveDocCreate:
		payload = in
	case input.DriveDocUpdate:
		payload = in
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
	if in, ok := call.Input.(input.DriveSearch); ok {
		files, ok := res.Data.([]providers.GoogleFile)
		if !ok {
			return nil, connector.ErrInput
		}
		driveID := driveIDFromResource(call.Invocation.Resource)
		limit := in.Limit
		if limit == 0 {
			limit = 50
		}
		filtered := make([]providers.GoogleFile, 0, min(limit, len(files)))
		for _, file := range files {
			if file.DriveID != driveID || (in.MimeType != "" && file.MimeType != in.MimeType) {
				continue
			}
			filtered = append(filtered, file)
			if len(filtered) == limit {
				break
			}
		}
		return filtered, nil
	}
	if text, ok := res.Data.(string); ok {
		if len(text) > MaxDocumentBytes {
			return nil, connector.ErrTooLarge
		}
		return Document{FileID: call.Invocation.Resource[strings.LastIndex(call.Invocation.Resource, "/")+1:], Text: text}, nil
	}
	return res.Data, nil
}
