package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// The local audit spool is the KEI_PROXY_AUDIT file plus sealed segments
// beside it. Writers append to the active file at <path>; once it would grow
// past a tenth of the cap it is renamed to an immutable <path>.<seq> segment
// and a new active file starts. The spool's total size never exceeds its cap:
// when a decision would cross it, the oldest segments are evicted, sent or
// not, so the newest records survive, and the loss is counted in <path>.meta.
//
// Every append, rotation, and eviction happens under an flock on <path>.lock,
// which serializes one-shot authorize processes, in-process writers, and the
// collector. Release targets are linux and darwin, both of which provide
// flock with per-open-file semantics.
const (
	// defaultAuditMaxBytes is the spool cap when KEI_PROXY_AUDIT_MAX_BYTES is
	// unset: 100 MiB across the active file and every segment.
	defaultAuditMaxBytes int64 = 100 << 20
	// auditSegmentsPerCap sets the rotation size to cap/10, so an eviction
	// drops at most about a tenth of the spool.
	auditSegmentsPerCap = 10
	// lifecycleCeilingPercent reserves the spool for decisions: a lifecycle
	// append is refused if the spool would reach this share of the cap, so a
	// lifecycle record can never be the reason a decision is evicted.
	lifecycleCeilingPercent = 90
	// auditSegmentSeqDigits zero-pads segment numbers so names sort in order.
	auditSegmentSeqDigits = 10
)

var (
	errLifecycleBudget = errors.New("audit spool: lifecycle record refused; spool space is reserved for decisions")
	errRecordTooLarge  = errors.New("audit spool: record exceeds the spool cap")
)

// spoolLoss counts records the spool dropped to stay within its cap. It is
// cumulative for the life of the spool directory; the collector logs the
// increase since it last looked.
type spoolLoss struct {
	EvictedSegments  int64 `json:"evicted_segments"`
	EvictedRecords   int64 `json:"evicted_records"`
	EvictedBytes     int64 `json:"evicted_bytes"`
	LifecycleRefused int64 `json:"lifecycle_refused"`
	OversizeRefused  int64 `json:"oversize_refused"`
}

// spoolMeta is the <path>.meta sidecar: the next segment number and the loss
// counters. It is only read and written under the spool lock.
type spoolMeta struct {
	NextSeq uint64    `json:"next_seq"`
	Loss    spoolLoss `json:"loss"`
}

type spoolSegment struct {
	seq  uint64
	path string
	size int64
}

type auditSpool struct {
	path     string
	maxBytes int64
}

// newAuditSpool opens the spool rooted at path. A non-positive maxBytes uses
// the default cap.
func newAuditSpool(path string, maxBytes int64) *auditSpool {
	if maxBytes <= 0 {
		maxBytes = defaultAuditMaxBytes
	}
	return &auditSpool{path: path, maxBytes: maxBytes}
}

func (s *auditSpool) segmentBytes() int64 {
	if n := s.maxBytes / auditSegmentsPerCap; n > 0 {
		return n
	}
	return 1
}

func (s *auditSpool) lockPath() string      { return s.path + ".lock" }
func (s *auditSpool) metaPath() string      { return s.path + ".meta" }
func (s *auditSpool) collectorPath() string { return s.path + ".state" }
func (s *auditSpool) segmentPath(seq uint64) string {
	return fmt.Sprintf("%s.%0*d", s.path, auditSegmentSeqDigits, seq)
}

// withLock runs fn while holding the spool's exclusive flock.
func (s *auditSpool) withLock(fn func() error) error {
	f, err := os.OpenFile(s.lockPath(), os.O_CREATE|os.O_RDONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open spool lock: %w", err)
	}
	defer func() { _ = f.Close() }()
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("lock spool: %w", err)
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	return fn()
}

// Append writes one record of the given class as a single line. Decisions
// may evict the oldest segments to fit under the cap; lifecycle records are
// refused instead once the spool nears it. A lifecycle record must carry
// event_class "lifecycle" so the collector can never read it as a decision.
func (s *auditSpool) Append(class string, record []byte) error {
	if s.path == "" {
		return nil
	}
	switch class {
	case eventClassDecision:
	case eventClassLifecycle:
		if got := recordEventClass(record); got != eventClassLifecycle {
			return fmt.Errorf("audit spool: lifecycle record has event_class %q", got)
		}
	default:
		return fmt.Errorf("audit spool: unknown event class %q", class)
	}
	if bytes.IndexByte(record, '\n') >= 0 {
		return errors.New("audit spool: record contains a newline")
	}
	// The spool is normally written under a mounted volume (e.g.
	// /data/kei-proxy on the bot's PVC); create the parent directory so a
	// fresh volume mount doesn't fail the first authorized call.
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	line := make([]byte, 0, len(record)+1)
	line = append(append(line, record...), '\n')
	return s.withLock(func() error { return s.appendLocked(class, line) })
}

func (s *auditSpool) appendLocked(class string, line []byte) error {
	meta := s.readMeta()
	segs, err := s.segments()
	if err != nil {
		return err
	}
	activeSize, err := fileSize(s.path)
	if err != nil {
		return err
	}
	total := activeSize
	for _, seg := range segs {
		total += seg.size
	}
	n := int64(len(line))

	if class == eventClassLifecycle && total+n > s.maxBytes*lifecycleCeilingPercent/100 {
		meta.Loss.LifecycleRefused++
		if err := s.writeMeta(meta); err != nil {
			return err
		}
		return errLifecycleBudget
	}
	if n > s.maxBytes {
		meta.Loss.OversizeRefused++
		if err := s.writeMeta(meta); err != nil {
			return err
		}
		return errRecordTooLarge
	}

	changed := false
	if activeSize > 0 && activeSize+n > s.segmentBytes() {
		seg, err := s.rotateLocked(&meta, segs, activeSize)
		if err != nil {
			return err
		}
		segs = append(segs, seg)
		changed = true
	}
	// Overwrite the oldest unsent data: evict whole segments, oldest first,
	// until the new line fits. A lifecycle append never evicts: it was
	// refused above unless it fits under the lifecycle ceiling.
	for total+n > s.maxBytes && len(segs) > 0 {
		s.evictLocked(&meta, segs[0])
		total -= segs[0].size
		segs = segs[1:]
		changed = true
	}
	if changed {
		if err := syncDir(filepath.Dir(s.path)); err != nil {
			return err
		}
		// Record the loss before the new line lands, so a crash never leaves
		// an eviction uncounted.
		if err := s.writeMeta(meta); err != nil {
			return err
		}
	}

	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(line); err != nil {
		return err
	}
	// The JSONL file is the fail-open durability boundary. Do not report the
	// authorization decision as auditable until the appended line has reached
	// stable storage according to the filesystem's sync semantics.
	return f.Sync()
}

// rotateLocked seals the active file as the next segment. The caller holds
// the lock and syncs the directory.
func (s *auditSpool) rotateLocked(meta *spoolMeta, segs []spoolSegment, activeSize int64) (spoolSegment, error) {
	seq := meta.NextSeq
	if seq == 0 {
		seq = 1
	}
	// Never reuse a number: a lost or stale meta file must not hand out a
	// segment name that sorts before data already on disk.
	if n := len(segs); n > 0 && segs[n-1].seq >= seq {
		seq = segs[n-1].seq + 1
	}
	seg := spoolSegment{seq: seq, path: s.segmentPath(seq), size: activeSize}
	if err := os.Rename(s.path, seg.path); err != nil {
		return spoolSegment{}, fmt.Errorf("rotate audit spool: %w", err)
	}
	meta.NextSeq = seq + 1
	return seg, nil
}

// evictLocked deletes a segment and counts what was lost. If the collector
// had already acknowledged part of it, only the unsent lines count as lost.
func (s *auditSpool) evictLocked(meta *spoolMeta, seg spoolSegment) {
	lines, _ := countSpoolLines(seg.path)
	if st, err := readCollectorState(s.collectorPath()); err == nil && st.Segment == seg.seq {
		lines -= int64(st.LinesSent)
		if lines < 0 {
			lines = 0
		}
	}
	if err := os.Remove(seg.path); err != nil && !os.IsNotExist(err) {
		return
	}
	meta.Loss.EvictedSegments++
	meta.Loss.EvictedRecords += lines
	meta.Loss.EvictedBytes += seg.size
}

// sealActiveLocked rotates a non-empty active file into a segment and returns
// its number, or 0 when the active file is empty. The collector calls it
// under the lock so it only ever reads immutable segments. floorSeq keeps new
// segment numbers ahead of the collector's own position.
func (s *auditSpool) sealActiveLocked(meta *spoolMeta, floorSeq uint64) (uint64, error) {
	if meta.NextSeq < floorSeq {
		meta.NextSeq = floorSeq
	}
	activeSize, err := fileSize(s.path)
	if err != nil || activeSize == 0 {
		return 0, err
	}
	segs, err := s.segments()
	if err != nil {
		return 0, err
	}
	seg, err := s.rotateLocked(meta, segs, activeSize)
	if err != nil {
		return 0, err
	}
	if err := syncDir(filepath.Dir(s.path)); err != nil {
		return 0, err
	}
	return seg.seq, s.writeMeta(*meta)
}

// segments lists sealed segments in sequence order.
func (s *auditSpool) segments() ([]spoolSegment, error) {
	dir := filepath.Dir(s.path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list audit spool: %w", err)
	}
	prefix := filepath.Base(s.path) + "."
	var segs []spoolSegment
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, prefix) || e.IsDir() {
			continue
		}
		suffix := name[len(prefix):]
		if len(suffix) != auditSegmentSeqDigits {
			continue
		}
		seq, err := strconv.ParseUint(suffix, 10, 64)
		if err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			// Evicted or shipped between the listing and the stat.
			continue
		}
		segs = append(segs, spoolSegment{seq: seq, path: filepath.Join(dir, name), size: info.Size()})
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].seq < segs[j].seq })
	return segs, nil
}

// readMeta returns the sidecar, or a zero value when it is missing or
// unreadable. Losing the sidecar resets the counters but never blocks an
// append, and segment numbering recovers from the names on disk.
func (s *auditSpool) readMeta() spoolMeta {
	var meta spoolMeta
	data, err := os.ReadFile(s.metaPath())
	if err != nil {
		return meta
	}
	_ = json.Unmarshal(data, &meta)
	return meta
}

func (s *auditSpool) writeMeta(meta spoolMeta) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.metaPath(), data)
}

// recordEventClass returns a record's event_class, or "" when it has none.
func recordEventClass(record []byte) string {
	var probe struct {
		EventClass string `json:"event_class"`
	}
	_ = json.Unmarshal(record, &probe)
	return probe.EventClass
}

// nextSpoolLine returns the next non-blank line with surrounding whitespace
// trimmed, or io.EOF. A final line without a newline (a write cut short by a
// crash) is still returned; the parser counts it as malformed.
func nextSpoolLine(r *bufio.Reader) ([]byte, error) {
	for {
		line, err := r.ReadBytes('\n')
		if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
			return trimmed, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// countSpoolLines counts the non-blank lines in a file, matching the line
// numbering the collector uses for its position.
func countSpoolLines(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(f)
	var n int64
	for {
		if _, err := nextSpoolLine(r); err != nil {
			if errors.Is(err, io.EOF) {
				return n, nil
			}
			return n, err
		}
		n++
	}
}

func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return info.Size(), nil
}

// writeFileAtomic replaces path with data through a synced temp file and
// rename, then syncs the directory so the rename survives a power loss.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0o644); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", filepath.Base(path), err)
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open directory: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}
