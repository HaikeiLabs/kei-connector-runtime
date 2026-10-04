package connectorruntime

import (
	"context"
	"errors"
	"fmt"
	"time"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// Heartbeat exit codes. They are part of the `runtime heartbeat --output jsonl`
// contract a supervising SDK (Agentware RuntimeLink) maps to link state. Legacy
// text mode keeps exiting 1 on every failure.
const (
	heartbeatExitOK           = 0 // graceful: stdin EOF, SIGTERM, or cancellation
	heartbeatExitTransient    = 1 // transient or internal; the supervisor restarts with backoff
	heartbeatExitContract     = 2 // usage error, catalog 400, or malformed catalog response
	heartbeatExitUnauthorized = 3 // unknown, revoked, or inactive installation
	heartbeatExitConfig       = 4 // invalid runtime configuration
)

type HeartbeatOutcome = keiruntime.HeartbeatOutcome
type HeartbeatFailure = keiruntime.HeartbeatFailure
type HeartbeatReport = keiruntime.HeartbeatReport
type HeartbeatCounter = keiruntime.HeartbeatCounter
type HarnessEnvelope = keiruntime.HarnessEnvelope

const (
	HeartbeatOK                  = keiruntime.HeartbeatOK
	HeartbeatCatalogUnreachable  = keiruntime.HeartbeatCatalogUnreachable
	HeartbeatCatalogTimeout      = keiruntime.HeartbeatCatalogTimeout
	HeartbeatCatalogError        = keiruntime.HeartbeatCatalogError
	HeartbeatCatalogBackpressure = keiruntime.HeartbeatCatalogBackpressure
	HeartbeatCatalogRejected     = keiruntime.HeartbeatCatalogRejected
	HeartbeatUnauthorized        = keiruntime.HeartbeatUnauthorized
)

func retryableInTick(o HeartbeatOutcome) bool { return o.RetryableInTick() }
func classifyHeartbeatStatus(status int) HeartbeatOutcome {
	return keiruntime.ClassifyHeartbeatStatus(status)
}
func classifyTransportError(err error) HeartbeatOutcome {
	return keiruntime.ClassifyHeartbeatTransportError(err)
}

// parseRetryAfter reads delay-seconds or an HTTP date. Anything else is zero.
func parseRetryAfter(value string, now time.Time) time.Duration {
	return keiruntime.ParseHeartbeatRetryAfter(value, now)
}

// toHeartbeatIdentity converts a root RuntimeIdentity to the runtime/ package
// HeartbeatIdentity subset used for the identity stdout event.
func toHeartbeatIdentity(identity *RuntimeIdentity) *keiruntime.HeartbeatIdentity {
	agents := make([]keiruntime.HeartbeatAgent, len(identity.Agents))
	for i, a := range identity.Agents {
		agents[i] = keiruntime.HeartbeatAgent{AgentID: a.AgentID, IsDefault: a.IsDefault}
	}
	return &keiruntime.HeartbeatIdentity{
		ID:            identity.ID,
		OrgID:         identity.OrgID,
		WorkspaceID:   identity.WorkspaceID,
		Platform:      identity.Platform,
		Status:        identity.Status,
		BindingStatus: identity.BindingStatus,
		AgentID:       identity.AgentID,
		Agents:        agents,
	}
}

// resolveIdentity fetches the authoritative installation identity from whoami.
// The token is the only identity source; nothing declared by the harness is
// consulted. A transient failure is reported as a beat without a seq and
// retried each interval, so a catalog outage at startup reads as a catalog
// problem rather than a crash-looping runtime. It returns a nil identity and
// the exit code when it gives up or ctx ends.
func resolveIdentity(ctx context.Context, client RuntimeClient, loop *keiruntime.HeartbeatLoop, cfg Config) (*RuntimeIdentity, int) {
	for {
		started := loop.Now()
		identity, err := client.WhoAmI(ctx, loop.Token)
		if err != nil && retryableInTick(classifyWhoamiError(err)) {
			if !keiruntime.SleepContext(ctx, min(5*time.Second, loop.Interval/4)) {
				return nil, heartbeatExitOK
			}
			identity, err = client.WhoAmI(ctx, loop.Token)
		}
		if ctx.Err() != nil {
			return nil, heartbeatExitOK
		}
		if err == nil {
			if identity == nil {
				loop.Events.Terminal(keiruntime.ReasonContractMismatch)
				return nil, heartbeatExitContract
			}
			if err := registerCredentialSyncKey(ctx, client, cfg); err != nil {
				fmt.Fprintf(loop.Warn, "runtime heartbeat failed: %v\n", err)
				return nil, heartbeatExitTransient
			}
			return identity, heartbeatExitOK
		}
		outcome := classifyWhoamiError(err)
		switch {
		case outcome == HeartbeatUnauthorized:
			loop.Events.Terminal(string(HeartbeatUnauthorized))
			return nil, heartbeatExitUnauthorized
		case !outcome.Transient():
			loop.Events.Terminal(keiruntime.ReasonContractMismatch)
			return nil, heartbeatExitContract
		}
		wait := loop.Jitter(loop.Interval)
		var failure *WhoamiFailure
		status := 0
		if errors.As(err, &failure) {
			status = failure.StatusCode
		}
		latency, next := loop.Now().Sub(started).Milliseconds(), wait.Milliseconds()
		loop.Events.Emit(keiruntime.HeartbeatEvent{Event: "beat", At: started.UTC().Format(time.RFC3339), Outcome: outcome, HTTPStatus: status, LatencyMS: &latency, NextInMS: &next})
		if !keiruntime.SleepContext(ctx, wait) {
			return nil, heartbeatExitOK
		}
	}
}
