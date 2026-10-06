package hooks

import (
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// SpoolAppender returns the AppendAudit function for hook records. With
// auditPath (KEI_PROXY_AUDIT) set it appends there; otherwise it appends to
// the private harness-tool spool under stateDir
// (<state dir>/audit/harness-tool.jsonl, directory 0700, files 0600), which
// the collector ships by the same default. With neither it returns nil, and
// WriteAudit drops the record without failing the hook.
func SpoolAppender(auditPath, stateDir string, maxBytes int64) func([]byte) error {
	var spool *keiruntime.AuditSpool
	switch {
	case auditPath != "":
		spool = keiruntime.NewAuditSpool(auditPath, maxBytes)
	case stateDir != "":
		spool = keiruntime.NewPrivateAuditSpool(keiruntime.HarnessAuditPath(stateDir), maxBytes)
	default:
		return nil
	}
	return func(record []byte) error {
		return spool.Append(keiruntime.EventClassHarnessTool, record)
	}
}
