package hooks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

type permissionEvent struct {
	Schema            string    `json:"schema"`
	EventClass        string    `json:"event_class"`
	HarnessID         string    `json:"harness_id"`
	HarnessKind       string    `json:"harness_kind"`
	HarnessRegistered bool      `json:"harness_registered"`
	HarnessSessionID  string    `json:"harness_session_id,omitempty"`
	ToolUseID         string    `json:"tool_use_id,omitempty"`
	Phase             string    `json:"phase"`
	Tool              string    `json:"tool"`
	ArgsDigest        string    `json:"args_digest"`
	NativeDecision    string    `json:"native_decision"`
	Argv0             string    `json:"argv0,omitempty"`
	ObservedAt        time.Time `json:"observed_at"`
}

// Run dispatches the report-only permission hook CLI. Every harness-facing
// invocation returns zero, including malformed input and spool failures.
func Run(args []string, stdin io.Reader, stdout io.Writer, cfg Config) int {
	if len(args) == 0 || args[0] != "report" {
		return 2
	}
	return ReportPermissions(args[1:], stdin, stdout, cfg)
}

// ReportPermissions records the harness's native tool decision without
// making or changing that decision. It always exits zero for a harness.
func ReportPermissions(args []string, stdin io.Reader, stdout io.Writer, cfg Config) int {
	if len(args) == 0 || !validHarnessKind(args[0]) {
		return 0
	}
	kind := args[0]
	flags := flag.NewFlagSet("hook report", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	harnessID := flags.String("harness", "", "registered harness id")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *harnessID == "" {
		return 0
	}
	in, err := ReadInput(stdin)
	if err != nil {
		return 0
	}
	canonical := CanonicalJSON(in.ToolInput)
	digest := sha256.Sum256(canonical)
	phase := in.Phase
	if phase == "" {
		phase = "pre"
		if strings.EqualFold(in.EventName, "PostToolUse") {
			phase = "post"
		}
	}
	decision := in.NativeDecision
	if phase == "post" {
		decision = "executed"
	}
	if !validNativeDecision(phase, decision) {
		decision = "unknown"
	}
	tool, argv0 := reportedTool(in.ToolName, in.ToolInput)
	event := permissionEvent{Schema: "kei.harness-tool-event/v1", EventClass: "harness_tool", HarnessID: *harnessID, HarnessKind: kind, HarnessRegistered: false, HarnessSessionID: in.SessionID, ToolUseID: in.ToolUseID, Phase: phase, Tool: tool, ArgsDigest: "sha256:" + hex.EncodeToString(digest[:]), NativeDecision: decision, Argv0: argv0, ObservedAt: time.Now().UTC()}
	data, err := json.Marshal(event)
	if err == nil {
		WriteAudit(cfg, data)
	}
	if cfg.RuntimeStateDir != "" {
		if store, openErr := policybundle.OpenStore(cfg.RuntimeStateDir); openErr == nil && store.State() == policybundle.Expired && phase == "pre" {
			event.Phase, event.NativeDecision, event.ObservedAt = "entries_expired", "unknown", time.Now().UTC()
			if expiredEvent, marshalErr := json.Marshal(event); marshalErr == nil {
				WriteAudit(cfg, expiredEvent)
			}
			if kind == "claude" {
				_, _ = io.WriteString(stdout, "{\"systemMessage\":\"Kei harness permissions have expired. Run `kei harness sync` to renew them.\"}\n")
			}
		}
	}
	return 0
}

func reportedTool(name string, raw json.RawMessage) (string, string) {
	tool, argv0 := name, ""
	if strings.EqualFold(name, "bash") || strings.EqualFold(name, "exec_command") {
		var args struct {
			Command string `json:"command"`
			Cmd     string `json:"cmd"`
		}
		_ = json.Unmarshal(raw, &args)
		command := args.Command
		if command == "" {
			command = args.Cmd
		}
		if fields := strings.Fields(command); len(fields) > 0 {
			argv0 = fields[0]
		}
		tool = "shell"
	}
	return tool, argv0
}
