package hooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

type pendingCall struct {
	ToolUseID  string `json:"tool_use_id"`
	ToolName   string `json:"tool_name"`
	ArgsDigest string `json:"args_digest"`
	// DigestKeyID is the key ArgsDigest was computed under; empty for a
	// plain sha256 digest and for calls stored before it was recorded.
	DigestKeyID string    `json:"digest_key_id,omitempty"`
	Asked       bool      `json:"asked"`
	Executed    bool      `json:"executed"`
	Decided     bool      `json:"decided"`
	CreatedAt   time.Time `json:"created_at"`
}

type claudeSessionCalls struct {
	Calls []pendingCall `json:"calls"`
}

type claudeDecisionState struct {
	Sessions map[string]*claudeSessionCalls `json:"sessions"`
	version  int
}

const claudeDecisionFile = "claude-decisions.json"
const claudeDecisionLock = "claude-decisions.lock"

type ClaudeDecisionStore struct {
	dir      string
	path     string
	lockPath string
	mu       sync.Mutex
}

func OpenClaudeDecisionStore(dir string) (*ClaudeDecisionStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("runtime state directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create runtime state directory: %w", err)
	}
	return &ClaudeDecisionStore{
		dir:      dir,
		path:     filepath.Join(dir, claudeDecisionFile),
		lockPath: filepath.Join(dir, claudeDecisionLock),
	}, nil
}

func (s *ClaudeDecisionStore) load() (claudeDecisionState, error) {
	st := claudeDecisionState{Sessions: map[string]*claudeSessionCalls{}}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return st, fmt.Errorf("read claude decision state: %w", err)
	}
	if len(data) == 0 {
		return st, nil
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("parse claude decision state: %w", err)
	}
	if st.Sessions == nil {
		st.Sessions = map[string]*claudeSessionCalls{}
	}
	for k, v := range st.Sessions {
		if v == nil {
			st.Sessions[k] = &claudeSessionCalls{}
		}
	}
	return st, nil
}

func (s *ClaudeDecisionStore) save(st claudeDecisionState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("marshal claude decision state: %w", err)
	}
	tmp, err := os.CreateTemp(s.dir, "claude-decisions.tmp-")
	if err != nil {
		return fmt.Errorf("create temp claude decision state: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}

func (s *ClaudeDecisionStore) withLock(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open claude decision lock: %w", err)
	}
	defer func() { _ = f.Close() }()
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("lock claude decision state: %w", err)
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	return fn()
}

func (s *ClaudeDecisionStore) withLockReadonly(fn func(claudeDecisionState) error) error {
	return s.withLock(func() error {
		st, err := s.load()
		if err != nil {
			return err
		}
		return fn(st)
	})
}

func (s *ClaudeDecisionStore) withLockReadWrite(fn func(*claudeDecisionState) error) error {
	return s.withLock(func() error {
		st, err := s.load()
		if err != nil {
			return err
		}
		if err := fn(&st); err != nil {
			return err
		}
		return s.save(st)
	})
}

func (s *ClaudeDecisionStore) Add(sessionID string, call pendingCall) error {
	return s.withLockReadWrite(func(st *claudeDecisionState) error {
		sess, ok := st.Sessions[sessionID]
		if !ok {
			sess = &claudeSessionCalls{}
			st.Sessions[sessionID] = sess
		}
		sess.Calls = append(sess.Calls, call)
		return nil
	})
}

func (s *ClaudeDecisionStore) FindOldestPending(sessionID, toolName, argsDigest string) (int, *pendingCall, error) {
	var foundIdx int = -1
	var found *pendingCall
	err := s.withLockReadonly(func(st claudeDecisionState) error {
		sess, ok := st.Sessions[sessionID]
		if !ok {
			return nil
		}
		for i := range sess.Calls {
			pc := &sess.Calls[i]
			if !pc.Asked && !pc.Decided && pc.ToolName == toolName && pc.ArgsDigest == argsDigest {
				foundIdx = i
				found = pc
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return -1, nil, err
	}
	if foundIdx < 0 {
		return -1, nil, nil
	}
	return foundIdx, found, nil
}

func (s *ClaudeDecisionStore) MarkAsked(sessionID string, idx int) error {
	return s.withLockReadWrite(func(st *claudeDecisionState) error {
		sess, ok := st.Sessions[sessionID]
		if !ok {
			return fmt.Errorf("session %q not found", sessionID)
		}
		if idx < 0 || idx >= len(sess.Calls) {
			return fmt.Errorf("call index %d out of range", idx)
		}
		sess.Calls[idx].Asked = true
		return nil
	})
}

func (s *ClaudeDecisionStore) MarkDenied(sessionID string, idx int) error {
	return s.withLockReadWrite(func(st *claudeDecisionState) error {
		sess, ok := st.Sessions[sessionID]
		if !ok {
			return fmt.Errorf("session %q not found", sessionID)
		}
		if idx < 0 || idx >= len(sess.Calls) {
			return fmt.Errorf("call index %d out of range", idx)
		}
		sess.Calls[idx].Asked = true
		sess.Calls[idx].Decided = true
		return nil
	})
}

func (s *ClaudeDecisionStore) MarkDecided(sessionID string, idx int) error {
	return s.withLockReadWrite(func(st *claudeDecisionState) error {
		sess, ok := st.Sessions[sessionID]
		if !ok {
			return fmt.Errorf("session %q not found", sessionID)
		}
		if idx < 0 || idx >= len(sess.Calls) {
			return fmt.Errorf("call index %d out of range", idx)
		}
		sess.Calls[idx].Decided = true
		return nil
	})
}

func (s *ClaudeDecisionStore) FindByToolUseID(sessionID, toolUseID string) (int, *pendingCall, error) {
	var foundIdx int = -1
	var found *pendingCall
	err := s.withLockReadonly(func(st claudeDecisionState) error {
		sess, ok := st.Sessions[sessionID]
		if !ok {
			return nil
		}
		for i := range sess.Calls {
			pc := &sess.Calls[i]
			if pc.ToolUseID == toolUseID {
				foundIdx = i
				found = pc
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return -1, nil, err
	}
	if foundIdx < 0 {
		return -1, nil, nil
	}
	return foundIdx, found, nil
}

func (s *ClaudeDecisionStore) MarkExecuted(sessionID string, idx int) error {
	return s.withLockReadWrite(func(st *claudeDecisionState) error {
		sess, ok := st.Sessions[sessionID]
		if !ok {
			return fmt.Errorf("session %q not found", sessionID)
		}
		if idx < 0 || idx >= len(sess.Calls) {
			return fmt.Errorf("call index %d out of range", idx)
		}
		sess.Calls[idx].Executed = true
		return nil
	})
}

func (s *ClaudeDecisionStore) UndecidedCalls(sessionID string) ([]pendingCall, error) {
	var calls []pendingCall
	err := s.withLockReadonly(func(st claudeDecisionState) error {
		sess, ok := st.Sessions[sessionID]
		if !ok {
			return nil
		}
		for _, pc := range sess.Calls {
			if !pc.Decided {
				calls = append(calls, pc)
			}
		}
		return nil
	})
	return calls, err
}

func (s *ClaudeDecisionStore) DeleteSession(sessionID string) error {
	return s.withLockReadWrite(func(st *claudeDecisionState) error {
		delete(st.Sessions, sessionID)
		return nil
	})
}

// StaleSessionIDs returns session IDs where every call is older than the
// given duration, or sessions with no calls at all.
func (s *ClaudeDecisionStore) StaleSessionIDs(olderThan time.Duration) ([]string, error) {
	cutoff := time.Now().UTC().Add(-olderThan)
	var ids []string
	err := s.withLockReadonly(func(st claudeDecisionState) error {
		for sid, sess := range st.Sessions {
			if sess == nil || len(sess.Calls) == 0 {
				ids = append(ids, sid)
				continue
			}
			allBefore := true
			for _, pc := range sess.Calls {
				if pc.CreatedAt.IsZero() || pc.CreatedAt.After(cutoff) {
					allBefore = false
					break
				}
			}
			if allBefore {
				ids = append(ids, sid)
			}
		}
		return nil
	})
	return ids, err
}

func (s *ClaudeDecisionStore) AllSessionIDs() ([]string, error) {
	var ids []string
	err := s.withLockReadonly(func(st claudeDecisionState) error {
		for sid := range st.Sessions {
			ids = append(ids, sid)
		}
		return nil
	})
	return ids, err
}

type claudeEventContext struct {
	kind             string
	harnessID        string
	harnessSessionID string
	sessionID        string
	tool             string
	argv0            string
	skill            string
	registered       bool
	argsDigest       string
	digestKeyID      string
	argsCiphertext   string
	recipientKeyIDs  []string
}

func newClaudeEventContext(in ToolInput, kind string, harnessID, sessionID *string, tool, argv0, skill string, registered bool, argsDigest, digestKeyID, argsCiphertext string, recipientKeyIDs []string) claudeEventContext {
	return claudeEventContext{
		kind:             kind,
		harnessID:        *harnessID,
		harnessSessionID: in.SessionID,
		sessionID:        *sessionID,
		tool:             tool,
		argv0:            argv0,
		skill:            skill,
		registered:       registered,
		argsDigest:       argsDigest,
		digestKeyID:      digestKeyID,
		argsCiphertext:   argsCiphertext,
		recipientKeyIDs:  recipientKeyIDs,
	}
}

func writeEvent(ctx claudeEventContext, phase, nativeDecision string, toolUseID string, failed bool, cfg Config) {
	ev := permissionEvent{
		Schema:            "kei.harness-tool-event/v1",
		EventClass:        "harness_tool",
		HarnessID:         ctx.harnessID,
		HarnessKind:       ctx.kind,
		HarnessRegistered: ctx.registered,
		HarnessSessionID:  ctx.harnessSessionID,
		SessionID:         ctx.sessionID,
		ToolUseID:         toolUseID,
		Phase:             phase,
		Tool:              ctx.tool,
		Skill:             ctx.skill,
		ArgsDigest:        ctx.argsDigest,
		DigestKeyID:       ctx.digestKeyID,
		ArgsCiphertext:    ctx.argsCiphertext,
		RecipientKeyIDs:   ctx.recipientKeyIDs,
		NativeDecision:    nativeDecision,
		Argv0:             ctx.argv0,
		ObservedAt:        time.Now().UTC(),
	}
	if failed {
		ev.Failed = true
	}
	data, err := json.Marshal(ev)
	if err == nil {
		WriteAudit(cfg, data)
	}
}

func handleClaudeEvent(in ToolInput, ctx claudeEventContext, stdout io.Writer, cfg Config) int {
	eventName := strings.ToLower(in.EventName)
	switch eventName {
	case "pretooluse":
		return handleClaudePreToolUse(in, ctx, stdout, cfg)
	case "posttooluse", "posttoolusefailure":
		return handleClaudePostToolUse(in, ctx, cfg)
	case "permissionrequest":
		return handleClaudePermissionRequest(in, ctx, cfg)
	case "permissiondenied":
		return handleClaudePermissionDenied(in, ctx, cfg)
	case "stop":
		return handleClaudeStop(in, ctx, cfg)
	case "sessionend":
		return handleClaudeSessionEnd(in, ctx, cfg)
	default:
		return 0
	}
}

func handleClaudePreToolUse(in ToolInput, ctx claudeEventContext, stdout io.Writer, cfg Config) int {
	if store, err := OpenClaudeDecisionStore(cfg.RuntimeStateDir); err == nil {
		closeStaleSessions(store, ctx, cfg)
		_ = store.Add(in.SessionID, pendingCall{
			ToolUseID:   in.ToolUseID,
			ToolName:    ctx.tool,
			ArgsDigest:  ctx.argsDigest,
			DigestKeyID: ctx.digestKeyID,
			CreatedAt:   time.Now().UTC(),
		})
	}
	writeEvent(ctx, "pre", "unknown", in.ToolUseID, false, cfg)
	if cfg.RuntimeStateDir != "" {
		if bundleStore, openErr := policybundle.OpenStore(cfg.RuntimeStateDir); openErr == nil && bundleStore.State() == policybundle.Expired {
			writeEvent(ctx, "entries_expired", "unknown", in.ToolUseID, false, cfg)
			_ = writeNotice(stdout, ctx.kind, "Kei harness permissions have expired. Run `kei harness sync` to renew them.")
		}
	}
	if ctx.sessionID != "" && cfg.SubjectSource != nil {
		if subject, subErr := cfg.SubjectSource.Subject(session.WithID(context.Background(), ctx.sessionID)); subErr == nil && subject == "" && !recentlyNudged(cfg.RuntimeStateDir, ctx.sessionID) {
			_ = writeNotice(stdout, ctx.kind, "Kei: you're not signed in — run `kei login` so your calls are attributed and your user/group policies apply.")
			_ = markNudged(cfg.RuntimeStateDir, ctx.sessionID)
		}
	}
	return 0
}

func handleClaudePostToolUse(in ToolInput, ctx claudeEventContext, cfg Config) int {
	failed := strings.EqualFold(in.EventName, "PostToolUseFailure")
	store, err := OpenClaudeDecisionStore(cfg.RuntimeStateDir)
	if err != nil {
		writeEvent(ctx, "post", "executed", in.ToolUseID, failed, cfg)
		return 0
	}
	closeStaleSessions(store, ctx, cfg)

	idx, pc, findErr := store.FindByToolUseID(in.SessionID, in.ToolUseID)
	if findErr != nil || pc == nil {
		writeEvent(ctx, "post", "executed", in.ToolUseID, failed, cfg)
		return 0
	}
	if !pc.Decided {
		if pc.Asked {
			writeEvent(ctx, "permission_reply", "approved", in.ToolUseID, false, cfg)
		} else {
			writeEvent(ctx, "decision", "allow", in.ToolUseID, false, cfg)
		}
		_ = store.MarkDecided(in.SessionID, idx)
	}
	_ = store.MarkExecuted(in.SessionID, idx)
	writeEvent(ctx, "post", "executed", in.ToolUseID, failed, cfg)
	return 0
}

func handleClaudePermissionRequest(in ToolInput, ctx claudeEventContext, cfg Config) int {
	store, err := OpenClaudeDecisionStore(cfg.RuntimeStateDir)
	if err != nil {
		return 0
	}
	closeStaleSessions(store, ctx, cfg)
	idx, pc, findErr := store.FindOldestPending(in.SessionID, ctx.tool, ctx.argsDigest)
	if findErr != nil || pc == nil {
		return 0
	}
	_ = store.MarkAsked(in.SessionID, idx)
	writeEvent(ctx, "decision", "ask", pc.ToolUseID, false, cfg)
	return 0
}

func handleClaudePermissionDenied(in ToolInput, ctx claudeEventContext, cfg Config) int {
	store, err := OpenClaudeDecisionStore(cfg.RuntimeStateDir)
	if err != nil {
		return 0
	}
	closeStaleSessions(store, ctx, cfg)
	idx, pc, findErr := store.FindOldestPending(in.SessionID, ctx.tool, ctx.argsDigest)
	if findErr != nil || pc == nil {
		return 0
	}
	_ = store.MarkDenied(in.SessionID, idx)
	writeEvent(ctx, "decision", "deny", pc.ToolUseID, false, cfg)
	return 0
}

func handleClaudeStop(in ToolInput, ctx claudeEventContext, cfg Config) int {
	store, err := OpenClaudeDecisionStore(cfg.RuntimeStateDir)
	if err != nil {
		return 0
	}
	closeStaleSessions(store, ctx, cfg)
	closeRemainingCalls(store, in.SessionID, ctx, cfg)
	return 0
}

func handleClaudeSessionEnd(in ToolInput, ctx claudeEventContext, cfg Config) int {
	store, err := OpenClaudeDecisionStore(cfg.RuntimeStateDir)
	if err != nil {
		return 0
	}
	closeStaleSessions(store, ctx, cfg)
	closeRemainingCalls(store, in.SessionID, ctx, cfg)
	_ = store.DeleteSession(in.SessionID)
	return 0
}

// closeStaleSessions closes and deletes all stale (older than 24 h) sessions,
// reusing closeRemainingCalls so the emit logic is identical to Stop/SessionEnd.
func closeStaleSessions(store *ClaudeDecisionStore, ctx claudeEventContext, cfg Config) {
	staleIDs, err := store.StaleSessionIDs(24 * time.Hour)
	if err != nil {
		return
	}
	for _, sid := range staleIDs {
		closeRemainingCalls(store, sid, ctx, cfg)
		_ = store.DeleteSession(sid)
	}
}

func closeRemainingCalls(store *ClaudeDecisionStore, sessionID string, ctx claudeEventContext, cfg Config) {
	undecided, err := store.UndecidedCalls(sessionID)
	if err != nil {
		return
	}
	for _, pc := range undecided {
		idx, current, findErr := store.FindByToolUseID(sessionID, pc.ToolUseID)
		if findErr != nil || current == nil {
			continue
		}
		if current.Decided {
			continue
		}
		callCtx := pendingCallContext(ctx, *current)
		if current.Asked {
			writeEvent(callCtx, "permission_reply", "denied", pc.ToolUseID, false, cfg)
		} else {
			writeEvent(callCtx, "decision", "deny", pc.ToolUseID, false, cfg)
		}
		_ = store.MarkDecided(sessionID, idx)
	}
}

// pendingCallContext describes a call closed by a later event (Stop,
// SessionEnd, or a stale-session sweep). That event carries no tool_name or
// tool_input of its own, so the tool and args digest come from the stored
// call; the closing event's argv0 and ciphertext describe nothing and are
// dropped.
func pendingCallContext(ctx claudeEventContext, pc pendingCall) claudeEventContext {
	ctx.tool = pc.ToolName
	ctx.argsDigest = pc.ArgsDigest
	ctx.digestKeyID = pc.DigestKeyID
	ctx.argv0 = ""
	ctx.argsCiphertext = ""
	ctx.recipientKeyIDs = nil
	return ctx
}
