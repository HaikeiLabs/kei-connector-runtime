package mcproute

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/manifest"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

// Manifest and cache limits (ADR-036 §4.7 step 1, §5.3).
const (
	maxManifestTools = 512
	maxManifestBytes = 4 * 1024 * 1024
	listingTTL       = 300 * time.Second
)

// errManifestDrift marks a listing that cannot be verified against the
// approval (ADR-036 §5.3).
var errManifestDrift = errors.New(reasonManifestDrift)

// verifiedListing is an upstream tools/list result whose every tool is
// approved with an equal tool_hash.
type verifiedListing struct {
	hash      string // the observed manifest_hash
	tools     []json.RawMessage
	toolNames map[string]bool
	// schemas holds each tool's verified inputSchema; compiled caches them.
	schemas  map[string]json.RawMessage
	schemaMu sync.Mutex
	compiled map[string]*jsonschema.Schema
}

// newVerifiedListing indexes a listing that has been verified.
func newVerifiedListing(hash string, tools []json.RawMessage) (*verifiedListing, error) {
	toolNames := make(map[string]bool, len(tools))
	schemas := make(map[string]json.RawMessage, len(tools))
	for _, t := range tools {
		var info struct {
			Name        string          `json:"name"`
			InputSchema json.RawMessage `json:"inputSchema"`
		}
		if err := json.Unmarshal(t, &info); err != nil {
			continue
		}
		toolNames[info.Name] = true
		schemas[info.Name] = info.InputSchema
	}
	return &verifiedListing{hash: hash, tools: tools, toolNames: toolNames, schemas: schemas}, nil
}

// listingKey caches verified listings per (session, connector) (§5.3).
type listingKey struct {
	session   string
	connector string
}

type cachedListing struct {
	listing      *verifiedListing
	bundleDigest string
	approvedHash string
	verifiedAt   time.Time
}

func manifestDenial(reason string, err error) *routeError {
	return &routeError{code: codeManifest, reason: reason, err: err}
}

// verifiedListingFor returns the session's verified listing for connector d,
// fetching and verifying one when none is cached (ADR-036 §5.3). A cached
// listing lasts 300 s and only while the bundle and approval are unchanged.
// After drift the connector stays blocked for the session, without another
// upstream request, until a bundle carries a different approval.
func (h *Handler) verifiedListingFor(ctx context.Context, sess *Session, d policybundle.Connector) (*verifiedListing, error) {
	approved := d.MCP.ApprovedManifestHash
	if approved == "" {
		return nil, manifestDenial(reasonManifestUnapproved, nil)
	}
	key := listingKey{session: sess.SessionID, connector: d.ID}
	digest := h.config.Catalog.BundleDigest()

	h.mu.Lock()
	if blockedFor, ok := h.blocked[key]; ok {
		if blockedFor == approved {
			h.mu.Unlock()
			return nil, manifestDenial(reasonManifestDrift, errors.New("connector blocked for this session after drift"))
		}
		delete(h.blocked, key)
	}
	if c, ok := h.listings[key]; ok && c.bundleDigest == digest && c.approvedHash == approved && h.now().Sub(c.verifiedAt) <= listingTTL {
		h.mu.Unlock()
		return c.listing, nil
	}
	h.mu.Unlock()

	tools, err := h.fetchListing(ctx, d, sess)
	var listing *verifiedListing
	if err == nil {
		listing, err = verifyListing(tools, d.MCP.ApprovedTools)
	}
	if errors.Is(err, errManifestDrift) {
		if tools != nil {
			h.submitCandidate(d, tools)
		}
		h.mu.Lock()
		h.blocked[key] = approved
		delete(h.listings, key)
		h.mu.Unlock()
		return nil, manifestDenial(reasonManifestDrift, err)
	}
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.listings[key] = &cachedListing{listing: listing, bundleDigest: digest, approvedHash: approved, verifiedAt: h.now()}
	h.mu.Unlock()
	return listing, nil
}

// EndSession drops what the route cached for a session that has ended.
func (h *Handler) EndSession(sessionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for key := range h.listings {
		if key.session == sessionID {
			delete(h.listings, key)
		}
	}
	for key := range h.blocked {
		if key.session == sessionID {
			delete(h.blocked, key)
		}
	}
}

// verifyListing applies ADR-036 §5.3: the listing is verified when it is a
// valid manifest (§5.2 rule 6) and every tool is approved with an equal
// tool_hash. A subset of the approved tools is verified.
func verifyListing(tools []json.RawMessage, approved []policybundle.MCPApprovedTool) (*verifiedListing, error) {
	if _, err := manifest.Canonicalize(tools); err != nil {
		return nil, fmt.Errorf("%w: invalid manifest: %v", errManifestDrift, err)
	}
	approvedHash := make(map[string]string, len(approved))
	for _, a := range approved {
		approvedHash[a.Name] = a.ToolHash
	}
	drift := &driftError{}
	for _, raw := range tools {
		var info struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &info); err != nil {
			drift.add("unreadable tool")
			continue
		}
		got, err := manifest.ToolHash(raw)
		want, ok := approvedHash[info.Name]
		switch {
		case err != nil:
			drift.add(fmt.Sprintf("tool %q: %v", info.Name, err))
		case !ok:
			drift.add(fmt.Sprintf("tool %q is not approved", info.Name))
		case got != want:
			drift.add(fmt.Sprintf("tool %q changed", info.Name))
		}
	}
	if drift.unapproved > 0 {
		return nil, drift
	}
	observed, err := manifest.Hash(tools)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid manifest: %v", errManifestDrift, err)
	}
	return newVerifiedListing(observed, tools)
}

// driftError is a listing with tools that are not approved, or whose hash
// differs; unapproved counts them for audit (§4.9).
type driftError struct {
	unapproved int
	first      string
}

func (e *driftError) add(why string) {
	if e.unapproved == 0 {
		e.first = why
	}
	e.unapproved++
}

func (e *driftError) Error() string {
	return fmt.Sprintf("%s: %d tool(s) not approved, first: %s", reasonManifestDrift, e.unapproved, e.first)
}

func (e *driftError) Is(target error) bool { return target == errManifestDrift }

// unapprovedCount is the number of unapproved tools behind a drift error.
func unapprovedCount(err error) int {
	var d *driftError
	if errors.As(err, &d) {
		return d.unapproved
	}
	return 0
}

// fetchListing pages through the upstream tools/list (§4.7 step 1). More
// than 512 tools or 4 MiB is drift.
func (h *Handler) fetchListing(ctx context.Context, d policybundle.Connector, sess *Session) ([]json.RawMessage, error) {
	var allTools []json.RawMessage
	totalBytes := 0
	cursor := ""
	for {
		var params json.RawMessage
		if cursor != "" {
			b, err := json.Marshal(map[string]string{"cursor": cursor})
			if err != nil {
				return nil, fmt.Errorf("cannot marshal cursor params: %w", err)
			}
			params = b
		}
		body, err := json.Marshal(jsonrpcRequest{
			JSONRPC: "2.0",
			ID:      json.RawMessage("1"),
			Method:  "tools/list",
			Params:  params,
		})
		if err != nil {
			return nil, fmt.Errorf("cannot marshal tools/list request: %w", err)
		}
		respBody, err := h.exchange(ctx, d, sess, body)
		var re *routeError
		if errors.As(err, &re) && re.reason == reasonResponseTooLarge {
			// §4.7 step 1: a listing above 4 MiB is drift, not an upstream error.
			return nil, fmt.Errorf("%w: manifest exceeds %d bytes", errManifestDrift, maxManifestBytes)
		}
		if err != nil {
			return nil, err
		}
		var rpcResp struct {
			Result *struct {
				Tools      []json.RawMessage `json:"tools"`
				NextCursor string            `json:"nextCursor,omitempty"`
			} `json:"result"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(respBody, &rpcResp); err != nil {
			return nil, upstreamFailure(reasonUpstreamProtocolError, fmt.Errorf("cannot parse tools/list response: %w", err))
		}
		if rpcResp.Error != nil {
			return nil, upstreamFailure(reasonUpstreamProtocolError, errors.New("upstream answered tools/list with a JSON-RPC error"))
		}
		if rpcResp.Result == nil {
			return nil, upstreamFailure(reasonUpstreamProtocolError, errors.New("tools/list response has no result"))
		}
		allTools = append(allTools, rpcResp.Result.Tools...)
		for _, t := range rpcResp.Result.Tools {
			totalBytes += len(t)
		}
		if len(allTools) > maxManifestTools {
			return nil, fmt.Errorf("%w: manifest exceeds %d tools", errManifestDrift, maxManifestTools)
		}
		if totalBytes > maxManifestBytes {
			return nil, fmt.Errorf("%w: manifest exceeds %d bytes", errManifestDrift, maxManifestBytes)
		}
		if rpcResp.Result.NextCursor == "" {
			break
		}
		cursor = rpcResp.Result.NextCursor
	}
	if allTools == nil {
		allTools = []json.RawMessage{}
	}
	return allTools, nil
}
