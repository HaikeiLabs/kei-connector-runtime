package hooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// activeSkillState is the on-disk shape of the per-session active-skill store.
type activeSkillState struct {
	Sessions map[string]string `json:"sessions"`
}

// ActiveSkillStore keeps the invoking skill for each opencode session in a
// small state file under the runtime state directory. It is written when an
// opencode skill tool call is observed and read to tag subsequent tool calls
// in the same session. OpenCode is the only harness with a discrete,
// observable skill tool, so attribution is opencode-only; other harnesses
// leave the skill empty.
type ActiveSkillStore struct {
	dir      string
	path     string
	lockPath string
}

// OpenActiveSkillStore opens (creating if needed) the active-skill store under
// dir. A blank dir is an error so callers fail closed rather than silently
// dropping attribution.
func OpenActiveSkillStore(dir string) (*ActiveSkillStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("runtime state directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create runtime state directory: %w", err)
	}
	return &ActiveSkillStore{
		dir:      dir,
		path:     filepath.Join(dir, "active-skills.json"),
		lockPath: filepath.Join(dir, "active-skills.lock"),
	}, nil
}

func (s *ActiveSkillStore) load() (activeSkillState, error) {
	st := activeSkillState{Sessions: map[string]string{}}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return st, fmt.Errorf("read active skill state: %w", err)
	}
	if len(data) == 0 {
		return st, nil
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("parse active skill state: %w", err)
	}
	if st.Sessions == nil {
		st.Sessions = map[string]string{}
	}
	return st, nil
}

func (s *ActiveSkillStore) save(st activeSkillState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("marshal active skill state: %w", err)
	}
	tmp, err := os.CreateTemp(s.dir, "active-skills.tmp-")
	if err != nil {
		return fmt.Errorf("create temp active skill state: %w", err)
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

// withLock runs fn while holding an exclusive advisory lock, serializing the
// concurrent hook processes that share the state file.
func (s *ActiveSkillStore) withLock(fn func() error) error {
	f, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open active skill lock: %w", err)
	}
	defer func() { _ = f.Close() }()
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("lock active skill state: %w", err)
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	return fn()
}

// Set records skill as the active skill for sessionID. Blank arguments are a
// no-op so a malformed skill call never clears an existing attribution.
func (s *ActiveSkillStore) Set(sessionID, skill string) error {
	if sessionID == "" || skill == "" {
		return nil
	}
	return s.withLock(func() error {
		st, err := s.load()
		if err != nil {
			return err
		}
		st.Sessions[sessionID] = skill
		return s.save(st)
	})
}

// Get returns the active skill for sessionID, or "" when none is set.
func (s *ActiveSkillStore) Get(sessionID string) (string, error) {
	if sessionID == "" {
		return "", nil
	}
	skill := ""
	err := s.withLock(func() error {
		st, err := s.load()
		if err != nil {
			return err
		}
		skill = st.Sessions[sessionID]
		return nil
	})
	return skill, err
}

// Clear drops the active skill for sessionID when the session ends.
func (s *ActiveSkillStore) Clear(sessionID string) error {
	if sessionID == "" {
		return nil
	}
	return s.withLock(func() error {
		st, err := s.load()
		if err != nil {
			return err
		}
		if _, ok := st.Sessions[sessionID]; !ok {
			return nil
		}
		delete(st.Sessions, sessionID)
		return s.save(st)
	})
}
