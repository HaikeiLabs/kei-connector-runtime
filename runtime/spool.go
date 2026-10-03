package runtime

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

const (
	defaultAuditMaxBytes    int64 = 100 << 20
	auditSegmentsPerCap           = 10
	lifecycleCeilingPercent       = 90
	auditSegmentSeqDigits         = 10
)

const (
	EventClassDecision    = "decision"
	EventClassLifecycle   = "lifecycle"
	EventClassHarnessTool = "harness_tool"
	EventClassCredential  = "credential"
)

var (
	errLifecycleBudget = errors.New("audit spool: lifecycle record refused; spool space is reserved for decisions")
	errRecordTooLarge  = errors.New("audit spool: record exceeds the spool cap")
)

type spoolLoss struct {
	EvictedSegments    int64 `json:"evicted_segments"`
	EvictedRecords     int64 `json:"evicted_records"`
	EvictedBytes       int64 `json:"evicted_bytes"`
	LifecycleRefused   int64 `json:"lifecycle_refused"`
	HarnessToolRefused int64 `json:"harness_tool_refused"`
	CredentialRefused  int64 `json:"credential_refused"`
	OversizeRefused    int64 `json:"oversize_refused"`
}

type spoolMeta struct {
	NextSeq uint64    `json:"next_seq"`
	Loss    spoolLoss `json:"loss"`
}

type spoolSegment struct {
	seq  uint64
	path string
	size int64
}

type AuditSpool struct {
	path     string
	maxBytes int64
}

func NewAuditSpool(path string, maxBytes int64) *AuditSpool {
	if maxBytes <= 0 {
		maxBytes = defaultAuditMaxBytes
	}
	return &AuditSpool{path: path, maxBytes: maxBytes}
}

func (s *AuditSpool) segmentBytes() int64 {
	if n := s.maxBytes / auditSegmentsPerCap; n > 0 {
		return n
	}
	return 1
}

func (s *AuditSpool) lockPath() string      { return s.path + ".lock" }
func (s *AuditSpool) metaPath() string      { return s.path + ".meta" }
func (s *AuditSpool) collectorPath() string { return s.path + ".state" }
func (s *AuditSpool) segmentPath(seq uint64) string {
	return fmt.Sprintf("%s.%0*d", s.path, auditSegmentSeqDigits, seq)
}

func (s *AuditSpool) withLock(fn func() error) error {
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

func (s *AuditSpool) Append(class string, record []byte) error {
	if s.path == "" {
		return nil
	}
	switch class {
	case EventClassDecision:
	case EventClassLifecycle:
		if got := recordEventClass(record); got != EventClassLifecycle {
			return fmt.Errorf("audit spool: lifecycle record has event_class %q", got)
		}
	case EventClassHarnessTool, EventClassCredential:
	default:
		return fmt.Errorf("audit spool: unknown event class %q", class)
	}
	if bytes.IndexByte(record, '\n') >= 0 {
		return errors.New("audit spool: record contains a newline")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	line := make([]byte, 0, len(record)+1)
	line = append(append(line, record...), '\n')
	return s.withLock(func() error { return s.appendLocked(class, line) })
}

func (s *AuditSpool) appendLocked(class string, line []byte) error {
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

	if recordClass := recordEventClass(line); recordClass != "" && recordClass != EventClassDecision && total+n > s.maxBytes*lifecycleCeilingPercent/100 {
		switch recordClass {
		case EventClassLifecycle:
			meta.Loss.LifecycleRefused++
		case EventClassHarnessTool:
			meta.Loss.HarnessToolRefused++
		case EventClassCredential:
			meta.Loss.CredentialRefused++
		}
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
	return f.Sync()
}

func (s *AuditSpool) rotateLocked(meta *spoolMeta, segs []spoolSegment, activeSize int64) (spoolSegment, error) {
	seq := meta.NextSeq
	if seq == 0 {
		seq = 1
	}
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

func (s *AuditSpool) evictLocked(meta *spoolMeta, seg spoolSegment) {
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

func (s *AuditSpool) sealActiveLocked(meta *spoolMeta, floorSeq uint64) (uint64, error) {
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

func (s *AuditSpool) segments() ([]spoolSegment, error) {
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
			continue
		}
		segs = append(segs, spoolSegment{seq: seq, path: filepath.Join(dir, name), size: info.Size()})
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].seq < segs[j].seq })
	return segs, nil
}

func (s *AuditSpool) readMeta() spoolMeta {
	var meta spoolMeta
	data, err := os.ReadFile(s.metaPath())
	if err != nil {
		return meta
	}
	_ = json.Unmarshal(data, &meta)
	return meta
}

func (s *AuditSpool) writeMeta(meta spoolMeta) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.metaPath(), data)
}

func recordEventClass(record []byte) string {
	var probe struct {
		EventClass string `json:"event_class"`
	}
	_ = json.Unmarshal(record, &probe)
	return probe.EventClass
}

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
