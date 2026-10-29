package connectorruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// daemonAuthorizeCall is the part of an authorize invocation the serve daemon
// decides. The subject is the daemon session's, never the caller's.
type daemonAuthorizeCall struct {
	Tool            string
	Action          string
	Resource        string
	AgentID         string
	SpanID          string
	ParentSpan      string
	DelegationDepth int
	Framework       string
	ToolArgsDigest  string
}

// authorizeViaDaemon asks the serve daemon on socketPath to decide call in
// the named session (POST /v1/authorize). A v2 bundle has no one-shot
// decision: the subject lives in a daemon session. The daemon audits the
// decision. The error is non-nil when no decision was obtained.
func authorizeViaDaemon(ctx context.Context, socketPath, runtimeToken, sessionID string, call daemonAuthorizeCall) (keiruntime.AuthorizeOutput, error) {
	body := map[string]any{
		"schema": "kei.authorize-request/v1", "tool": call.Tool, "action": call.Action, "resource": call.Resource,
		"agent_id": call.AgentID, "span_id": call.SpanID, "parent_span": call.ParentSpan,
		"delegation_depth": call.DelegationDepth, "framework": call.Framework, "tool_args_digest": call.ToolArgsDigest,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return keiruntime.AuthorizeOutput{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/authorize", bytes.NewReader(raw))
	if err != nil {
		return keiruntime.AuthorizeOutput{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+runtimeToken)
	session.SetHeader(req, sessionID)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.DialTimeout("unix", socketPath, 3*time.Second)
		},
	}}
	resp, err := client.Do(req)
	if err != nil {
		return keiruntime.AuthorizeOutput{}, fmt.Errorf("kei-proxy daemon unreachable at %s: %w", socketPath, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return keiruntime.AuthorizeOutput{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return keiruntime.AuthorizeOutput{}, fmt.Errorf("kei-proxy daemon returned status %d", resp.StatusCode)
	}
	var decided struct {
		Decision   string           `json:"decision"`
		ReasonCode string           `json:"reason_code"`
		Hint       string           `json:"hint"`
		DenySource string           `json:"deny_source"`
		Reason     string           `json:"reason"`
		Enrollment *json.RawMessage `json:"enrollment"`
	}
	if err := json.Unmarshal(data, &decided); err != nil {
		return keiruntime.AuthorizeOutput{}, fmt.Errorf("decode daemon decision: %w", err)
	}
	out := keiruntime.AuthorizeOutput{Decision: "deny", ReasonCode: decided.ReasonCode, Hint: decided.Hint, DenySource: decided.DenySource, Reason: decided.Reason, Enrollment: decided.Enrollment}
	switch decided.Decision {
	// The shared decision word, not a literal: the ADR-026 static guard bans a
	// bare permit string in non-test Go.
	case policybundle.DecisionPermit:
		out.Decision = "allow"
	case "deny", "unmatched":
	default:
		return keiruntime.AuthorizeOutput{}, fmt.Errorf("unexpected daemon decision %q", decided.Decision)
	}
	return out, nil
}
