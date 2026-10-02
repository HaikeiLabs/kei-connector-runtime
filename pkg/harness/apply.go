package harness

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/harnessmatch"
)

// SyncLedger records exact native values managed by Kei for one harness.
type SyncLedger struct {
	Schema       string         `json:"schema"`
	HarnessID    string         `json:"harness_id"`
	HarnessKind  Kind           `json:"harness_kind"`
	BundleID     string         `json:"bundle_id"`
	BundleDigest string         `json:"bundle_digest"`
	ExpiresAt    time.Time      `json:"expires_at"`
	ConfigPath   string         `json:"config_path"`
	HookPath     string         `json:"hook_path,omitempty"`
	Entries      []ManagedEntry `json:"entries"`
}

// ApplyPlan makes timestamped backups before atomically replacing plan files.
func ApplyPlan(plan RenderPlan, h Harness, b VerifiedBundle, ledgerPath string, now time.Time) error {
	if plan.ConfigPath == "" || ledgerPath == "" {
		return errors.New("config and ledger paths are required")
	}
	if old, err := readLedger(ledgerPath); err == nil {
		current := map[string]bool{}
		for _, e := range plan.Managed {
			current[entryKey(e)] = true
		}
		var stale []ManagedEntry
		for _, e := range old.Entries {
			if !current[entryKey(e)] {
				stale = append(stale, e)
			}
		}
		if plan.Config != nil {
			plan.Config, err = removeManaged(h.Kind, plan.Config, stale)
			if err != nil {
				return err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	files := append([]ManagedFile(nil), plan.Files...)
	for _, entry := range plan.Managed {
		if entry.Decision != "baseline" || !strings.HasSuffix(entry.Path, ":approval_policy") {
			continue
		}
		path := strings.TrimSuffix(entry.Path, ":approval_policy")
		old, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		files = append(files, ManagedFile{Path: path, Data: setTOMLApprovalPolicy(old, entry.Value), Replace: true})
	}
	if plan.Config != nil {
		files = append(files, ManagedFile{Path: plan.ConfigPath, Data: plan.Config, Replace: true})
	}
	if plan.HookPath != "" && plan.Hook != nil {
		files = append(files, ManagedFile{Path: plan.HookPath, Data: plan.Hook, Replace: true})
	}
	for _, f := range files {
		if f.Path == "" {
			return errors.New("render plan contains empty file path")
		}
	}
	for _, f := range files {
		if _, err := os.Stat(f.Path); err == nil {
			if err = backupFile(f.Path, now); err != nil {
				return fmt.Errorf("backup %s: %w", filepath.Base(f.Path), err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if _, err := os.Stat(ledgerPath); err == nil {
		if err = backupFile(ledgerPath, now); err != nil {
			return fmt.Errorf("backup harness ledger: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, f := range files {
		mode := os.FileMode(0600)
		if info, err := os.Stat(f.Path); err == nil {
			mode = info.Mode().Perm()
		}
		if err := atomicWrite(f.Path, f.Data, mode); err != nil {
			return fmt.Errorf("write %s: %w", filepath.Base(f.Path), err)
		}
	}
	ledger := SyncLedger{Schema: "kei.harness-sync-ledger/v1", HarnessID: h.ID, HarnessKind: h.Kind, BundleID: b.ID, BundleDigest: b.Digest, ExpiresAt: b.ExpiresAt, ConfigPath: plan.ConfigPath, HookPath: plan.HookPath, Entries: append([]ManagedEntry(nil), plan.Managed...)}
	encoded, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(ledgerPath, append(encoded, '\n'), 0600)
}

// ExpireLedger withdraws only expired Kei allow values. Denies and user edits
// remain in place. The exact current value must still match the ledger.
func ExpireLedger(ledgerPath string, now time.Time) error {
	ledger, err := readLedger(ledgerPath)
	if err != nil {
		return err
	}
	expired := ExpiredEntries(ledger.Entries, now)
	if len(expired) == 0 {
		return nil
	}
	config, err := os.ReadFile(ledger.ConfigPath)
	if err != nil {
		return err
	}
	updated, err := removeManaged(ledger.HarnessKind, config, expired)
	if err != nil {
		return err
	}
	if err = backupFile(ledger.ConfigPath, now); err != nil {
		return err
	}
	if err = atomicWrite(ledger.ConfigPath, updated, 0600); err != nil {
		return err
	}
	removed := map[string]bool{}
	for _, e := range expired {
		removed[entryKey(e)] = true
	}
	kept := ledger.Entries[:0]
	for _, e := range ledger.Entries {
		if !removed[entryKey(e)] {
			kept = append(kept, e)
		}
	}
	ledger.Entries = kept
	encoded, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return err
	}
	if err = backupFile(ledgerPath, now); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicWrite(ledgerPath, append(encoded, '\n'), 0600)
}

func readLedger(path string) (SyncLedger, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return SyncLedger{}, err
	}
	var l SyncLedger
	if err = json.Unmarshal(b, &l); err != nil {
		return SyncLedger{}, err
	}
	if l.Schema != "kei.harness-sync-ledger/v1" || l.ConfigPath == "" {
		return SyncLedger{}, errors.New("invalid harness sync ledger")
	}
	return l, nil
}
func entryKey(e ManagedEntry) string {
	return e.Path + "\x00" + e.Value + "\x00" + e.Decision + "\x00" + e.PolicyID
}

func setTOMLApprovalPolicy(raw []byte, value string) []byte {
	lines := strings.Split(string(raw), "\n")
	found := false
	sectionSeen := false
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "[") {
			sectionSeen = true
		}
		if strings.HasPrefix(trim, "approval_policy") && strings.Contains(trim, "=") {
			if sectionSeen {
				continue
			}
			lines[i] = "approval_policy = " + strconv.Quote(value)
			found = true
			break
		}
	}
	if !found {
		if len(lines) == 1 && lines[0] == "" {
			lines = nil
		}
		setting := "approval_policy = " + strconv.Quote(value)
		if sectionSeen {
			lines = append([]string{setting}, lines...)
		} else {
			lines = append(lines, setting)
		}
	}
	return []byte(strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n")
}

func removeManaged(kind Kind, config []byte, entries []ManagedEntry) ([]byte, error) {
	if kind == Codex {
		remove := map[string]bool{}
		for _, e := range entries {
			if e.Decision == string(harnessmatch.OutcomePermit) && e.Path == "codex.rules" {
				remove[e.Value] = true
			}
		}
		lines := strings.Split(string(config), "\n")
		out := lines[:0]
		for _, line := range lines {
			if !remove[line] {
				out = append(out, line)
			}
		}
		return []byte(strings.Join(out, "\n")), nil
	}
	var doc map[string]any
	if err := json.Unmarshal(config, &doc); err != nil {
		return nil, err
	}
	key := "permissions"
	if kind == OpenCode {
		key = "permission"
	}
	permissions, _ := doc[key].(map[string]any)
	if permissions == nil {
		return config, nil
	}
	for _, e := range entries {
		if kind == ClaudeCode {
			category := strings.TrimPrefix(e.Path, "permissions.")
			items, _ := permissions[category].([]any)
			out := items[:0]
			for _, v := range items {
				if s, ok := v.(string); !ok || s != e.Value {
					out = append(out, v)
				}
			}
			permissions[category] = out
			continue
		}
		if e.Path == "permission.bash" {
			items, _ := permissions["bash"].(map[string]any)
			if items[e.Value] == decisionKey(e.Decision) {
				delete(items, e.Value)
			}
			continue
		}
		if strings.HasPrefix(e.Path, "permission.") {
			parts := strings.SplitN(e.Value, "=", 2)
			if len(parts) != 2 {
				continue
			}
			category := strings.TrimPrefix(e.Path, "permission.")
			items, _ := permissions[category].(map[string]any)
			if items[parts[0]] == decisionKey(e.Decision) {
				delete(items, parts[0])
			}
		}
	}
	return json.MarshalIndent(doc, "", "  ")
}

func backupFile(path string, now time.Time) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	backup := fmt.Sprintf("%s.kei-backup-%s", path, now.UTC().Format("20060102T150405.000000000Z"))
	return atomicWrite(backup, data, info.Mode().Perm())
}
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".kei-harness-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(data)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
