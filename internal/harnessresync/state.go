package harnessresync

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// StateFile is the resync status file in the runtime state directory, read by
// `kei-proxy policy show`.
const StateFile = "harness-resync.json"

// Resync states shown by `kei-proxy policy show`.
const (
	StateActive  = "active"
	StateBackoff = "harness resync backoff"
)

// Status is the persisted resync state. It holds counts and harness kinds
// only.
type Status struct {
	State           string    `json:"state"`
	IntervalSeconds int       `json:"interval_seconds"`
	BackoffKinds    []string  `json:"backoff_harnesses,omitempty"`
	LastCheck       time.Time `json:"last_check,omitzero"`
	LastDrifted     int       `json:"last_drifted"`
	LastSync        time.Time `json:"last_sync,omitzero"`
	LastError       string    `json:"last_error,omitempty"`
}

// SaveStatus writes s to dir atomically with mode 0600.
func SaveStatus(dir string, s Status) error {
	if dir == "" {
		return nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".harness-resync-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, StateFile))
}

// LoadStatus reads the status in dir. It returns nil, nil when the resync
// loop never ran there (a server installation, or no `kei` binary).
func LoadStatus(dir string) (*Status, error) {
	if dir == "" {
		return nil, nil
	}
	b, err := os.ReadFile(filepath.Join(dir, StateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Status
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, errors.New("decode harness resync state: invalid JSON")
	}
	return &s, nil
}
