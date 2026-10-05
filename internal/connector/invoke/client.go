package invoke

// `kei-proxy connector invoke` as a thin client of the serve daemon's
// POST /v1/connectors:invoke (KEI_CREDENTIAL_RELEASE=identity, HAI-346 L3b).
// The command validates its input, sends the call over the Unix socket with
// the runtime token, and prints the daemon's result. It holds no credential
// and asks no control plane; the daemon decides with its local PDP and the
// session subject. With no daemon or no session it fails closed.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

// maxDaemonResponseBytes bounds the daemon's answer; a result is at most
// maxResultBytes plus its envelope.
const maxDaemonResponseBytes = maxResultBytes + 64<<10

func runViaDaemon(plan connectorInvokePlan, env Env, stdout, stderr io.Writer) int {
	out := output{TraceID: plan.req.TraceID, ConnectorID: plan.req.ConnectorID, Capability: plan.req.Capability}
	fail := func(code, reason, message string) int {
		fmt.Fprintf(stderr, "Error: %s\n", message)
		out.Decision, out.ReasonCode, out.Reason = "deny", code, reason
		if err := writeJSON(stdout, out); err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
		}
		return 1
	}
	if plan.explicitSubject {
		return fail("invalid_request", "the subject comes from the daemon session",
			"--user-id, --user and --provider-user are not accepted: the daemon acts for its session subject")
	}
	raw, err := input.Read(plan.input, env.Stdin)
	var canonical json.RawMessage
	if err == nil {
		canonical, _, err = input.Canonicalize(raw)
	}
	if err != nil {
		return fail("input_invalid", "input must be one JSON object of at most 16 KiB", "--input must be one JSON object of at most 16 KiB")
	}

	body, err := json.Marshal(daemonRequest{
		Schema: daemonRequestSchema, ConnectorID: plan.req.ConnectorID, Capability: plan.req.Capability,
		Action: plan.req.Action, Resource: plan.req.Resource, Input: canonical, TraceID: plan.req.TraceID,
		IdempotencyKey: plan.req.IdempotencyKey, AgentID: plan.req.AgentID, Framework: plan.req.Framework,
	})
	if err != nil {
		return fail("invalid_request", "request could not be encoded", "connector invoke request could not be encoded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), plan.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+DaemonInvokePath, bytes.NewReader(body))
	if err != nil {
		return fail("daemon_unavailable", "the kei-proxy serve daemon is not reachable", "connector invoke request could not be built")
	}
	req.Header.Set("Authorization", "Bearer "+env.RuntimeToken)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", env.DaemonSocket)
		},
	}}
	resp, err := client.Do(req)
	if err != nil {
		return fail("daemon_unavailable", "the kei-proxy serve daemon is not reachable",
			fmt.Sprintf("kei-proxy serve daemon is not reachable at %s; start `kei-proxy serve` (fail closed)", env.DaemonSocket))
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return fail("daemon_unavailable", "the daemon does not serve connector calls",
			"the kei-proxy serve daemon does not serve connector calls; run it with KEI_CREDENTIAL_RELEASE=identity (fail closed)")
	case http.StatusUnauthorized:
		return fail("daemon_unauthorized", "the daemon rejected the runtime token",
			"the kei-proxy serve daemon rejected KEI_RUNTIME_TOKEN (fail closed)")
	default:
		return fail("daemon_unavailable", "the daemon did not return a decision",
			fmt.Sprintf("the kei-proxy serve daemon returned status %d (fail closed)", resp.StatusCode))
	}
	var got daemonResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDaemonResponseBytes)).Decode(&got); err != nil ||
		got.Schema != daemonResponseSchema || (got.Decision != "allow" && got.Decision != "deny") {
		return fail("daemon_unavailable", "the daemon did not return a decision", "the kei-proxy serve daemon returned a malformed answer (fail closed)")
	}
	switch got.ReasonCode {
	case "no_session":
		fmt.Fprintln(stderr, "Error: no active kei-proxy session; the harness must start one with PUT /v1/session (fail closed)")
	case "connector_not_connected", "connector_reconnect_required":
		fmt.Fprintln(stderr, "Error: the session subject must (re)connect this provider")
	}
	if err := writeJSON(stdout, got.output); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if got.Decision != "allow" {
		return 1
	}
	return 0
}
