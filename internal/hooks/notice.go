package hooks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"
)

const nudgeRateLimit = 30 * time.Minute

// writeNotice writes a non-blocking harness notice to w. All supported
// harnesses (claude, codex, opencode, cursor) display a systemMessage JSON line.
func writeNotice(w io.Writer, harness, msg string) error {
	if w == nil {
		return nil
	}
	b, err := json.Marshal(map[string]string{"systemMessage": msg})
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	_ = harness // all harnesses use the same systemMessage shape
	return err
}

// nudgeKeyFile returns the path to the rate-limit file for sessionKey. A
// blank key maps to a global fallback so the nudge is still rate-limited
// when no session id is available.
func nudgeKeyFile(stateDir, sessionKey string) string {
	key := ".nobody"
	if sessionKey != "" {
		h := sha256.Sum256([]byte(sessionKey))
		key = hex.EncodeToString(h[:])
	}
	return filepath.Join(stateDir, "nudge", key)
}

// recentlyNudged reports whether the nudge has been shown within the
// rate-limit window for sessionKey.
func recentlyNudged(stateDir, sessionKey string) bool {
	if stateDir == "" {
		return false
	}
	fi, err := os.Stat(nudgeKeyFile(stateDir, sessionKey))
	if err != nil {
		return false
	}
	return time.Since(fi.ModTime()) < nudgeRateLimit
}

// markNudged records a nudge timestamp for sessionKey.
func markNudged(stateDir, sessionKey string) error {
	if stateDir == "" {
		return nil
	}
	dir := filepath.Join(stateDir, "nudge")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.Create(nudgeKeyFile(stateDir, sessionKey))
	if err != nil {
		return err
	}
	return f.Close()
}
