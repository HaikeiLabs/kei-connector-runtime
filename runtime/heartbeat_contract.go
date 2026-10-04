package runtime

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/policybundlehealth"
)

// HeartbeatOutcome classifies one runtime-to-catalog heartbeat result.
type HeartbeatOutcome string

const (
	HeartbeatOK                  HeartbeatOutcome = "ok"
	HeartbeatCatalogUnreachable  HeartbeatOutcome = "catalog_unreachable"
	HeartbeatCatalogTimeout      HeartbeatOutcome = "catalog_timeout"
	HeartbeatCatalogError        HeartbeatOutcome = "catalog_error"
	HeartbeatCatalogBackpressure HeartbeatOutcome = "catalog_backpressure"
	HeartbeatCatalogRejected     HeartbeatOutcome = "catalog_rejected"
	HeartbeatUnauthorized        HeartbeatOutcome = "unauthorized"
)

func (o HeartbeatOutcome) Transient() bool {
	switch o {
	case HeartbeatCatalogUnreachable, HeartbeatCatalogTimeout, HeartbeatCatalogError, HeartbeatCatalogBackpressure:
		return true
	}
	return false
}

func (o HeartbeatOutcome) RetryableInTick() bool {
	return o.Transient() && o != HeartbeatCatalogBackpressure
}

// HeartbeatFailure contains safe, classified heartbeat failure metadata.
type HeartbeatFailure struct {
	Outcome    HeartbeatOutcome
	StatusCode int
	RetryAfter time.Duration
	Wrapped    error
}

func (f *HeartbeatFailure) Error() string { return f.Wrapped.Error() }
func (f *HeartbeatFailure) Unwrap() error { return f.Wrapped }

func ClassifyHeartbeatStatus(status int) HeartbeatOutcome {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return HeartbeatUnauthorized
	case status == http.StatusTooManyRequests:
		return HeartbeatCatalogBackpressure
	case status >= 500:
		return HeartbeatCatalogError
	case status >= 400:
		return HeartbeatCatalogRejected
	default:
		return HeartbeatCatalogError
	}
}

func ClassifyHeartbeatTransportError(err error) HeartbeatOutcome {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return HeartbeatCatalogTimeout
	}
	return HeartbeatCatalogUnreachable
}

// HeartbeatReport is the POST /api/v1/runtime/heartbeat payload.
type HeartbeatReport struct {
	RuntimeVersion   string                     `json:"runtime_version"`
	SchemaVersion    int                        `json:"schema_version,omitempty"`
	RunID            string                     `json:"run_id,omitempty"`
	Seq              uint64                     `json:"seq,omitempty"`
	IntervalSeconds  int                        `json:"interval_seconds,omitempty"`
	RuntimeStartedAt string                     `json:"runtime_started_at,omitempty"`
	Harness          *HarnessEnvelope           `json:"harness,omitempty"`
	Counters         *HeartbeatCounter          `json:"counters,omitempty"`
	ToolSyncStatus   string                     `json:"tool_sync_status,omitempty"`
	PolicyBundle     *policybundlehealth.Health `json:"policy_bundle,omitempty"`
}

type HeartbeatCounter struct {
	BeatsFailedSinceOK int `json:"beats_failed_since_ok"`
}
type HarnessEnvelope struct {
	Kind          string `json:"kind,omitempty"`
	Version       string `json:"version,omitempty"`
	DeploymentEnv string `json:"deployment_env,omitempty"`
	SDKLang       string `json:"sdk_lang,omitempty"`
	SDKVersion    string `json:"sdk_version,omitempty"`
	Link          string `json:"link,omitempty"`
}

func ParseHeartbeatRetryAfter(value string, now time.Time) time.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return 0
}
