package run

// `kei-proxy run` as a thin client of the serve daemon's POST /v1/commands:run
// (KEI_CREDENTIAL_RELEASE=identity, HAI-346 L3c). It sends argv, its
// environment (kei://connectors references unresolved) and working directory,
// relays the child's streamed output, and exits with the child's exit code.
// This process never holds a connector credential. With no daemon, no session
// or a denied reference it fails closed.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// maxRunFrameBytes bounds one streamed frame (a base64 output chunk).
const maxRunFrameBytes = 4 << 20

func runViaDaemon(args []string, stdout, stderr io.Writer, cfg Config, parentEnv []string) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	connectorID := flags.String("connector", "", "connector id for resolved credentials")
	sep := -1
	for i, arg := range args {
		if arg == "--" {
			sep = i
			break
		}
	}
	if sep < 0 || flags.Parse(args[:sep]) != nil || flags.NArg() != 0 || sep+1 >= len(args) || args[sep+1] == "" {
		fmt.Fprintln(stderr, "run requires [--connector id] -- <command> [args...]")
		return 2
	}
	dir, err := os.Getwd()
	if err != nil {
		dir = ""
	}
	body, err := json.Marshal(daemonRunRequest{
		Schema: daemonRunSchema, Argv: args[sep+1:], Env: parentEnv, Dir: dir,
		Connector: *connectorID, AgentID: os.Getenv("KEI_PROXY_AGENT_ID"),
	})
	if err != nil {
		fmt.Fprintln(stderr, "Error: run request could not be encoded")
		return 1
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://unix"+DaemonRunPath, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintln(stderr, "Error: run request could not be built")
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+cfg.RuntimeToken)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", cfg.DaemonSocket)
		},
	}}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "Error: kei-proxy serve daemon is not reachable at %s; start `kei-proxy serve` (fail closed)\n", cfg.DaemonSocket)
		return 1
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		fmt.Fprintln(stderr, "Error: the kei-proxy serve daemon does not run commands; run it with KEI_CREDENTIAL_RELEASE=identity (fail closed)")
		return 1
	case http.StatusUnauthorized:
		fmt.Fprintln(stderr, "Error: the kei-proxy serve daemon rejected KEI_RUNTIME_TOKEN (fail closed)")
		return 1
	default:
		fmt.Fprintf(stderr, "Error: the kei-proxy serve daemon returned status %d (fail closed)\n", resp.StatusCode)
		return 1
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64<<10), maxRunFrameBytes)
	for scanner.Scan() {
		var frame runFrame
		if err := json.Unmarshal(scanner.Bytes(), &frame); err != nil {
			break
		}
		switch {
		case frame.Done != nil:
			return finishRun(*frame.Done, stderr)
		case frame.Stream == "stdout":
			_, _ = stdout.Write(frame.Data)
		case frame.Stream == "stderr":
			_, _ = stderr.Write(frame.Data)
		}
	}
	fmt.Fprintln(stderr, "Error: the kei-proxy serve daemon ended the run without an exit code (fail closed)")
	return 1
}

func finishRun(done runDone, stderr io.Writer) int {
	if done.Schema != daemonStreamSchema {
		fmt.Fprintln(stderr, "Error: the kei-proxy serve daemon returned a malformed answer (fail closed)")
		return 1
	}
	if done.Decision == "allow" {
		return done.ExitCode
	}
	switch done.ReasonCode {
	case "no_session":
		fmt.Fprintln(stderr, "Error: no active kei-proxy session; the harness must start one with PUT /v1/session (fail closed)")
	case "connector_not_connected", "connector_reconnect_required":
		fmt.Fprintf(stderr, "Error: run denied (%s): the session subject must (re)connect this provider\n", done.ReasonCode)
	default:
		fmt.Fprintf(stderr, "Error: run denied (%s): %s\n", done.ReasonCode, done.Reason)
	}
	if done.ExitCode == 0 {
		return 1
	}
	return done.ExitCode
}
