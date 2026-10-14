package mcproute

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

// AuditRecord is the route's view of one tools/list or tools/call decision
// (ADR-036 §4.9). Args are the call's arguments: an Auditor turns them into a
// digest, and into ciphertext only for a customer-held key; it never writes
// them in the clear. The record holds no token, route key, response body or
// tool description.
type AuditRecord struct {
	Event                string          `json:"event"`
	DecisionID           string          `json:"decision_id"`
	Decision             string          `json:"decision"`
	ReasonCode           string          `json:"reason_code,omitempty"`
	PolicyID             string          `json:"policy_id,omitempty"`
	BundleVersion        int64           `json:"bundle_version,omitempty"`
	BundleDigest         string          `json:"bundle_digest,omitempty"`
	DenySource           string          `json:"deny_source,omitempty"`
	SessionID            string          `json:"session_id,omitempty"`
	AgentID              string          `json:"agent_id,omitempty"`
	HarnessKind          string          `json:"harness_kind,omitempty"`
	UserID               string          `json:"user_id,omitempty"`
	Groups               []string        `json:"groups,omitempty"`
	ConnectorID          string          `json:"connector_id,omitempty"`
	ConnectorSlug        string          `json:"connector_slug,omitempty"`
	Template             string          `json:"template,omitempty"`
	Tool                 string          `json:"tool,omitempty"`
	ToolHash             string          `json:"tool_hash,omitempty"`
	ApprovedManifestHash string          `json:"approved_manifest_hash,omitempty"`
	Args                 json.RawMessage `json:"-"`
	Forwarded            bool            `json:"forwarded,omitempty"`
	UpstreamHost         string          `json:"upstream_host,omitempty"`
	UpstreamStatus       int             `json:"upstream_status,omitempty"`
	JSONRPCErrorCode     int             `json:"jsonrpc_error_code,omitempty"`
	IsError              bool            `json:"is_error,omitempty"`
	ResponseBytes        int             `json:"response_bytes,omitempty"`
	DurationMS           int64           `json:"duration_ms,omitempty"`
	ChallengedScope      string          `json:"challenged_scope,omitempty"`
	Listed               int             `json:"listed,omitempty"`
	HiddenByPolicy       int             `json:"hidden_by_policy,omitempty"`
	Unapproved           int             `json:"unapproved,omitempty"`
}

// describe adds the connector descriptor's fields to the record.
func (r *AuditRecord) describe(d policybundle.Connector) {
	r.ConnectorID, r.Template = d.ID, d.Provider
	if d.MCP == nil {
		return
	}
	r.ApprovedManifestHash = d.MCP.ApprovedManifestHash
	for _, t := range d.MCP.ApprovedTools {
		if r.Tool != "" && t.Name == r.Tool {
			r.ToolHash = t.ToolHash
		}
	}
}

// Auditor writes audit records. An error is logged by the route and never
// changes the decision.
type Auditor interface {
	Record(ctx context.Context, rec AuditRecord) error
}

// ArgsSealer is the audit-arguments encryption of ADR-030
// (auditcrypto.Provider): a Kei-keyed digest, and age encryption to the
// customer's registered keys, empty when none is registered.
type ArgsSealer interface {
	Digest(canonicalJSON []byte) (digest, keyID string)
	Encrypt(canonicalJSON []byte) (ciphertext string, keyIDs []string)
}

// SpoolAuditor writes records to the runtime's local audit spool (ADR-022)
// as decision events. Each line is a superset of runtime.DecisionEvent, so
// the existing collector ships the decision; the §4.9 fields stay in the
// spool record beside it.
type SpoolAuditor struct {
	// Append adds one record of an event class to the spool.
	Append func(class string, record []byte) error
	// Sealer digests and, with a customer key, encrypts the arguments. When
	// nil, the digest is a plain SHA-256 and nothing is encrypted.
	Sealer ArgsSealer
	// Scope returns the installation's org, workspace and installation ids.
	Scope func() (orgID, workspaceID, installationID string)
}

type spoolSubject struct {
	UserID string   `json:"user_id,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

type spoolRecord struct {
	// runtime.DecisionEvent fields.
	SpanID              string    `json:"span_id"`
	InvokedAt           time.Time `json:"invoked_at"`
	InvokingSubject     string    `json:"invoking_subject"`
	DelegationDepth     int       `json:"delegation_depth"`
	AgentID             string    `json:"agent_id"`
	Framework           string    `json:"framework"`
	ToolName            string    `json:"tool_name"`
	ToolArgsDigest      string    `json:"tool_args_digest,omitempty"`
	ResourcesTouched    []string  `json:"resources_touched"`
	Decision            string    `json:"decision"`
	PolicyID            string    `json:"policy_id,omitempty"`
	OrgID               string    `json:"org_id,omitempty"`
	WorkspaceID         string    `json:"workspace_id,omitempty"`
	PolicyBundleVersion int64     `json:"policy_bundle_version,omitempty"`
	PolicyBundleDigest  string    `json:"policy_bundle_digest,omitempty"`
	DenySource          string    `json:"deny_source,omitempty"`
	ReasonCode          string    `json:"reason_code,omitempty"`

	// ADR-036 §4.9 fields.
	Event                string       `json:"event"`
	DecisionID           string       `json:"decision_id"`
	InstallationID       string       `json:"installation_id,omitempty"`
	HarnessKind          string       `json:"harness_kind,omitempty"`
	SessionID            string       `json:"session_id,omitempty"`
	Subject              spoolSubject `json:"subject"`
	ConnectorID          string       `json:"connector_id,omitempty"`
	ConnectorSlug        string       `json:"connector_slug"`
	Template             string       `json:"template,omitempty"`
	Tool                 string       `json:"tool,omitempty"`
	ToolHash             string       `json:"tool_hash,omitempty"`
	ApprovedManifestHash string       `json:"approved_manifest_hash,omitempty"`
	ArgsDigest           string       `json:"args_digest,omitempty"`
	DigestKeyID          string       `json:"digest_key_id,omitempty"`
	ArgsCiphertext       string       `json:"args_ciphertext,omitempty"`
	RecipientKeyIDs      []string     `json:"recipient_key_ids,omitempty"`
	UpstreamHost         string       `json:"upstream_host,omitempty"`
	UpstreamStatus       int          `json:"upstream_status,omitempty"`
	JSONRPCErrorCode     int          `json:"jsonrpc_error_code,omitempty"`
	IsError              *bool        `json:"is_error,omitempty"`
	ResponseBytes        *int         `json:"response_bytes,omitempty"`
	DurationMS           *int64       `json:"duration_ms,omitempty"`
	ChallengedScope      string       `json:"challenged_scope,omitempty"`
	Listed               *int         `json:"listed,omitempty"`
	HiddenByPolicy       *int         `json:"hidden_by_policy,omitempty"`
	Unapproved           *int         `json:"unapproved,omitempty"`
}

// Record writes rec as one decision-class spool line.
func (a SpoolAuditor) Record(_ context.Context, rec AuditRecord) error {
	if a.Append == nil {
		return errors.New("mcp audit: no spool")
	}
	out := spoolRecord{
		SpanID: rec.DecisionID, InvokedAt: time.Now().UTC(), InvokingSubject: rec.UserID,
		AgentID: rec.AgentID, Framework: rec.HarnessKind, ToolName: "mcp:" + rec.ConnectorSlug,
		ResourcesTouched: []string{}, Decision: rec.Decision, PolicyID: rec.PolicyID,
		PolicyBundleVersion: rec.BundleVersion, PolicyBundleDigest: rec.BundleDigest,
		DenySource: rec.DenySource, ReasonCode: rec.ReasonCode,

		Event: rec.Event, DecisionID: rec.DecisionID, HarnessKind: rec.HarnessKind, SessionID: rec.SessionID,
		Subject:     spoolSubject{UserID: rec.UserID, Groups: rec.Groups},
		ConnectorID: rec.ConnectorID, ConnectorSlug: rec.ConnectorSlug, Template: rec.Template,
		ApprovedManifestHash: rec.ApprovedManifestHash, ChallengedScope: rec.ChallengedScope,
	}
	if a.Scope != nil {
		out.OrgID, out.WorkspaceID, out.InstallationID = a.Scope()
	}
	switch rec.Event {
	case "mcp.tools_call":
		out.ToolName += "." + rec.Tool
		out.Tool, out.ToolHash = rec.Tool, rec.ToolHash
		if canonical, ok := canonicalArgs(rec.Args); ok {
			out.ArgsDigest, out.DigestKeyID = a.digest(canonical)
			out.ToolArgsDigest = out.ArgsDigest
			if a.Sealer != nil {
				out.ArgsCiphertext, out.RecipientKeyIDs = a.Sealer.Encrypt(canonical)
			}
		}
	case "mcp.tools_list":
		listed, hidden, unapproved := rec.Listed, rec.HiddenByPolicy, rec.Unapproved
		out.Listed, out.HiddenByPolicy, out.Unapproved = &listed, &hidden, &unapproved
	}
	if rec.Forwarded {
		isError, bytes, ms := rec.IsError, rec.ResponseBytes, rec.DurationMS
		out.UpstreamHost, out.UpstreamStatus, out.JSONRPCErrorCode = rec.UpstreamHost, rec.UpstreamStatus, rec.JSONRPCErrorCode
		out.IsError, out.ResponseBytes, out.DurationMS = &isError, &bytes, &ms
	}
	line, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return a.Append("decision", line)
}

func (a SpoolAuditor) digest(canonical []byte) (string, string) {
	if a.Sealer != nil {
		return a.Sealer.Digest(canonical)
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), ""
}

// canonicalArgs is the deterministic serialization of a call's arguments
// that is digested and encrypted: object keys sorted, numbers as received,
// and absent arguments as {}. It is not byte-for-byte RFC 8785 for every
// number form.
func canonicalArgs(raw json.RawMessage) ([]byte, bool) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		raw = json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	b, err := json.Marshal(v)
	return b, err == nil
}
