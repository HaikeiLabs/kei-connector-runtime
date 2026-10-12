// Package skillsrepo is the skills_repo connector: skills.list and
// skills.fetch through the kei-connector-contracts skills repository client
// and its GitHub backend. The token is the invoking user's GitHub OAuth token
// (per_user, path 2) or the connector's opaque_ref secret (path 1); the
// contract module owns the reads, the source config, and the skill-name and
// path checks.
//
// skills.fetch returns one skill folder as an inline tar+gzip archive. Before
// the result leaves the connector, the archive must be within the contract's
// archive bound and match its declared format, size, and sha256 digest;
// anything else fails closed. The archive bytes are never logged.
package skillsrepo

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/HaikeiLabs/kei-connector-contracts/providers"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

// maxFetchResultBytes bounds a skills.fetch result: the largest archive the
// contract allows, base64 encoded in the JSON result, plus its listing entry
// and fields.
var maxFetchResultBytes = base64.StdEncoding.EncodedLen(providers.SkillsRepoMaxArchiveBytes) + 64<<10

var errInvalidArchive = errors.New("skill archive does not match its digest")

// Connector executes skills_repo reads.
type Connector struct{}

var payloads = map[string]providers.Payload{
	"skills.list":  providers.SkillsListPayload{},
	"skills.fetch": providers.SkillsFetchPayload{},
}

// Execute runs one skills_repo read.
func (Connector) Execute(ctx context.Context, call connector.Call) (any, error) {
	payload, ok := payloads[call.Invocation.Capability]
	if _, empty := call.Input.(input.Empty); !ok || !empty {
		return nil, connector.ErrInput
	}
	res, err := providers.NewAuthenticatedSkillsRepo(call.RuntimeConfig()).Invoke(ctx, call.Meta, call.Invocation, payload)
	if err != nil {
		return nil, err
	}
	if archive, ok := res.Data.(providers.SkillsRepoArchive); ok {
		if err := verifyArchive(archive); err != nil {
			return nil, err
		}
	}
	return res.Data, nil
}

// MaxResultBytes lets a skills.fetch result carry a full-size archive; other
// capabilities keep the runtime's default limit.
func (Connector) MaxResultBytes(capability string) int {
	if capability == "skills.fetch" {
		return maxFetchResultBytes
	}
	return 0
}

func verifyArchive(a providers.SkillsRepoArchive) error {
	if len(a.Archive) > providers.SkillsRepoMaxArchiveBytes {
		return connector.ErrTooLarge
	}
	sum := sha256.Sum256(a.Archive)
	if a.Format != providers.SkillsRepoArchiveFormat || a.Size != len(a.Archive) || a.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
		return errInvalidArchive
	}
	return nil
}
