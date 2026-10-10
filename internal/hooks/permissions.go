package hooks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
)

type permissionEvent struct {
	Schema            string `json:"schema"`
	EventClass        string `json:"event_class"`
	HarnessID         string `json:"harness_id"`
	HarnessKind       string `json:"harness_kind"`
	HarnessRegistered bool   `json:"harness_registered"`
	HarnessSessionID  string `json:"harness_session_id,omitempty"`
	// SessionID is the kei-proxy daemon session the harness runs in
	// (--session or $KEI_SESSION_ID), not the harness's own session.
	SessionID       string    `json:"session_id,omitempty"`
	ToolUseID       string    `json:"tool_use_id,omitempty"`
	Phase           string    `json:"phase"`
	Tool            string    `json:"tool"`
	Skill           string    `json:"skill,omitempty"`
	ArgsDigest      string    `json:"args_digest"`
	DigestKeyID     string    `json:"digest_key_id,omitempty"`
	ArgsCiphertext  string    `json:"args_ciphertext,omitempty"`
	RecipientKeyIDs []string  `json:"recipient_key_ids,omitempty"`
	NativeDecision  string    `json:"native_decision"`
	Argv0           string    `json:"argv0,omitempty"`
	Failed          bool      `json:"failed,omitempty"`
	ObservedAt      time.Time `json:"observed_at"`
}

// Run dispatches the report-only permission hook CLI. Every harness-facing
// invocation returns zero, including malformed input and spool failures.
//
// It accepts two forms:
//   - hook report <kind> --harness <id>   (kept for backward compat)
//   - hook <kind> --harness <id>          (rendered hook contract, see HookSpec)
//
// For unrecognised subcommands, it writes a one-line diagnostic to stderr
// and still returns zero so the harness never blocks on a hook invocation.
func Run(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, cfg Config) int {
	if len(args) == 0 {
		return 0
	}
	if args[0] == "report" {
		return ReportPermissions(args[1:], stdin, stdout, cfg)
	}
	if validHarnessKind(args[0]) {
		return ReportPermissions(args, stdin, stdout, cfg)
	}
	fmt.Fprintf(stderr, "kei-proxy hook: unknown subcommand %q\n", args[0])
	return 0
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
	sessionID := flags.String("session", session.IDFromEnv(), "kei-proxy daemon session id (default $KEI_SESSION_ID)")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return 0
	}
	in, err := ReadInput(stdin)
	if err != nil {
		return 0
	}
	if in.SessionID == "" {
		in.SessionID = strconv.Itoa(os.Getppid())
	}
	canonical := CanonicalJSON(in.ToolInput)
	var argsDigest, digestKeyID string
	var argsCiphertext string
	var recipientKeyIDs []string
	if cfg.AuditCrypto != nil {
		argsDigest, digestKeyID = cfg.AuditCrypto.Digest(canonical)
		argsCiphertext, recipientKeyIDs = cfg.AuditCrypto.Encrypt(canonical)
	} else {
		digest := sha256.Sum256(canonical)
		argsDigest = "sha256:" + hex.EncodeToString(digest[:])
	}
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
	skill := activeSkillFor(kind, in.SessionID, in.ToolName, in.ToolInput, cfg.RuntimeStateDir)
	registered := harnessRegisteredFor(cfg.RuntimeStateDir, *harnessID, kind)
	if kind == "claude" && in.EventName != "" {
		ctx := newClaudeEventContext(in, kind, harnessID, sessionID, tool, argv0, skill, registered, argsDigest, digestKeyID, argsCiphertext, recipientKeyIDs)
		return handleClaudeEvent(in, ctx, stdout, cfg)
	}
	event := permissionEvent{Schema: "kei.harness-tool-event/v1", EventClass: "harness_tool", HarnessID: *harnessID, HarnessKind: kind, HarnessRegistered: registered, HarnessSessionID: in.SessionID, SessionID: *sessionID, ToolUseID: in.ToolUseID, Phase: phase, Tool: tool, Skill: skill, ArgsDigest: argsDigest, DigestKeyID: digestKeyID, ArgsCiphertext: argsCiphertext, RecipientKeyIDs: recipientKeyIDs, NativeDecision: decision, Argv0: argv0, ObservedAt: time.Now().UTC()}
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
			_ = writeNotice(stdout, kind, "Kei harness permissions have expired. Run `kei harness sync` to renew them.")
		}
	}
	if phase == "pre" && cfg.SubjectSource != nil && *sessionID != "" {
		ctx := session.WithID(context.Background(), *sessionID)
		if subject, subErr := cfg.SubjectSource.Subject(ctx); subErr == nil && subject == "" && !recentlyNudged(cfg.RuntimeStateDir, *sessionID) {
			_ = writeNotice(stdout, kind, "Kei: you're not signed in — run `kei login` so your calls are attributed and your user/group policies apply.")
			_ = markNudged(cfg.RuntimeStateDir, *sessionID)
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

// activeSkillFor returns the invoking skill to tag a reported tool call with.
// Attribution is opencode-only: when an opencode skill tool call is observed it
// sets the session's active skill, and every opencode tool call in that session
// (including the skill call itself) is tagged with it. Claude and codex have no
// discrete skill tool, so their skill is always empty.
func activeSkillFor(kind, sessionID, toolName string, toolInput json.RawMessage, stateDir string) string {
	if kind != "opencode" || sessionID == "" || stateDir == "" {
		return ""
	}
	store, err := OpenActiveSkillStore(stateDir)
	if err != nil {
		return ""
	}
	if skillName, ok := skillToolName(toolName, toolInput); ok {
		_ = store.Set(sessionID, skillName)
	}
	skill, _ := store.Get(sessionID)
	return skill
}

// skillToolName reports whether a tool call is an opencode skill invocation and
// returns the skill name from its input.
func skillToolName(name string, raw json.RawMessage) (string, bool) {
	if !strings.EqualFold(name, "skill") {
		return "", false
	}
	var input struct {
		Skill string `json:"skill"`
	}
	if json.Unmarshal(raw, &input) != nil || input.Skill == "" {
		return "", false
	}
	return input.Skill, true
}

// bundleKind maps a hook's short harness kind to the kind recorded in the
// policy bundle's harnesses[] (ADR-029). The rendered hook CLI uses short
// kinds (claude, codex, opencode); the bundle records claude_code, codex and
// opencode. This is the single place that translates between the two.
var bundleKind = map[string]string{
	"claude":   "claude_code",
	"codex":    "codex",
	"opencode": "opencode",
}

// harnessRegistered reports whether the bundle's registered harnesses include
// harnessID under the bundle kind for the hook's short kind.
func harnessRegistered(harnesses []policybundle.Harness, harnessID, kind string) bool {
	want, ok := bundleKind[kind]
	if !ok || harnessID == "" {
		return false
	}
	for _, h := range harnesses {
		if h.AgentID == harnessID && h.Kind == want {
			return true
		}
	}
	return false
}

// harnessRegisteredFor reports whether the persisted policy bundle lists
// harnessID as a registered harness of the given short kind. It is
// report-only: a missing, unreadable, invalid, or expired bundle yields false,
// and it never fails the hook.
func harnessRegisteredFor(stateDir, harnessID, kind string) bool {
	if stateDir == "" || harnessID == "" {
		return false
	}
	store, err := policybundle.OpenStore(stateDir)
	if err != nil {
		return false
	}
	harnesses, err := store.Harnesses(time.Now())
	if err != nil {
		return false
	}
	return harnessRegistered(harnesses, harnessID, kind)
}
