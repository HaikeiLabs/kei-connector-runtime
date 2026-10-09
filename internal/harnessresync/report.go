// Package harnessresync keeps desktop harness native config (Claude Code,
// Codex, OpenCode) in line with the policy bundle from inside the kei-proxy
// policy refresher. It runs `kei harness sync --check --json` after a bundle
// change and on a timer, and runs `kei harness sync` when the check reports
// drift (HAI-432). Long-running harness sessions rewrite their settings from
// a stale in-memory copy and drop Kei entries; this puts them back.
//
// The package only ever keeps counts from a drift report. Rendered entries,
// file paths, config contents and tokens never leave the decoder.
package harnessresync

import (
	"encoding/json"
	"fmt"
)

// DriftSchema is the `kei harness sync --check --json` report schema this
// package understands (kei-cli #105).
const DriftSchema = "kei.harness-drift/v1"

// statusDrift is the per-harness status `kei` reports when a sync would
// change the native store.
const statusDrift = "drift"

// Report is the count-only summary of one drift check.
type Report struct {
	// Drift is true when `kei harness sync` would change a native store.
	Drift bool
	// BundleExpired is true when the check compared against an expired
	// bundle; sync then removes Kei-written allows.
	BundleExpired bool
	Harnesses     []HarnessDrift
}

// HarnessDrift counts one harness's differences. Missing and AlteredFiles
// mean another writer changed the native store; Pending and Stale mean the
// bundle changed since the last sync.
type HarnessDrift struct {
	Kind         string
	Drifted      bool
	Missing      int
	AlteredFiles int
	Pending      int
	Stale        int
}

// Rewritten reports whether another writer removed Kei entries or edited a
// Kei-owned file: the drift backoff counts only this, not a bundle change.
func (h HarnessDrift) Rewritten() bool {
	return h.Drifted && (h.Missing > 0 || h.AlteredFiles > 0)
}

// DriftedCount is the number of harnesses whose native store would change.
func (r Report) DriftedCount() int {
	n := 0
	for _, h := range r.Harnesses {
		if h.Drifted {
			n++
		}
	}
	return n
}

// counted decodes a JSON array to its length; the elements are discarded.
type counted int

func (c *counted) UnmarshalJSON(b []byte) error {
	var items []json.RawMessage
	if err := json.Unmarshal(b, &items); err != nil {
		return err
	}
	*c = counted(len(items))
	return nil
}

type wireReport struct {
	Schema string `json:"schema"`
	Drift  bool   `json:"drift"`
	Bundle struct {
		Expired bool `json:"expired"`
	} `json:"bundle"`
	Harnesses []struct {
		Kind         string  `json:"kind"`
		Status       string  `json:"status"`
		Missing      counted `json:"missing"`
		AlteredFiles counted `json:"altered_files"`
		Pending      counted `json:"pending"`
		Stale        counted `json:"stale"`
	} `json:"harnesses"`
}

// ParseReport decodes a kei.harness-drift/v1 report into counts. Errors
// never quote the input.
func ParseReport(b []byte) (Report, error) {
	var w wireReport
	if err := json.Unmarshal(b, &w); err != nil {
		return Report{}, fmt.Errorf("decode drift report: invalid JSON")
	}
	if w.Schema != DriftSchema {
		return Report{}, fmt.Errorf("decode drift report: unsupported schema")
	}
	r := Report{Drift: w.Drift, BundleExpired: w.Bundle.Expired, Harnesses: make([]HarnessDrift, 0, len(w.Harnesses))}
	for _, h := range w.Harnesses {
		r.Harnesses = append(r.Harnesses, HarnessDrift{
			Kind:         safeKind(h.Kind),
			Drifted:      h.Status == statusDrift,
			Missing:      int(h.Missing),
			AlteredFiles: int(h.AlteredFiles),
			Pending:      int(h.Pending),
			Stale:        int(h.Stale),
		})
	}
	return r, nil
}

// safeKind keeps a harness kind only when it looks like one (claude_code,
// codex, opencode, ...), so nothing else from the report reaches a log.
func safeKind(kind string) string {
	if kind == "" || len(kind) > 32 {
		return "unknown"
	}
	for _, c := range kind {
		if (c < 'a' || c > 'z') && c != '_' && (c < '0' || c > '9') {
			return "unknown"
		}
	}
	return kind
}
