// Package collector runs the audit collector inside a long-lived runtime
// process: it polls while the runtime serves and makes one bounded final flush
// when the runtime stops.
package collector

import (
	"context"
	"log/slog"
	"time"
)

// Flusher is the audit collector the service drives. Run flushes pending
// records once and reports how many were sent; RunPolling flushes on every
// interval until ctx is done. Records a flush fails to send must stay in the
// flusher's spool.
type Flusher interface {
	Run(ctx context.Context) (int, error)
	RunPolling(ctx context.Context, interval time.Duration) error
}

// Service is the in-process collector lifecycle.
type Service struct {
	Flusher Flusher
	// Path identifies the audit spool in diagnostics.
	Path string
	// PollInterval is how often pending records are flushed while running.
	PollInterval time.Duration
	// FinalFlushTimeout bounds the single flush attempted at shutdown.
	FinalFlushTimeout time.Duration
	// Logger defaults to slog.Default.
	Logger *slog.Logger
}

// Start polls in the background until ctx is done or stop is called. stop
// ends polling, makes one final flush bounded by FinalFlushTimeout, and
// returns when that flush has finished. It is safe to call more than once.
func (s Service) Start(ctx context.Context) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.run(ctx)
	}()
	return func() {
		cancel()
		<-done
	}
}

func (s Service) run(ctx context.Context) {
	pollDone := make(chan struct{})
	go func() {
		defer close(pollDone)
		_ = s.Flusher.RunPolling(ctx, s.PollInterval)
	}()
	<-ctx.Done()
	<-pollDone

	flushCtx, cancel := context.WithTimeout(context.Background(), s.FinalFlushTimeout)
	defer cancel()
	sent, err := s.Flusher.Run(flushCtx)
	if err != nil {
		s.logger().Warn("audit collector shutdown flush failed; retaining spool", "path", s.Path, "records_sent", sent, "error", err)
	}
}

func (s Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}
