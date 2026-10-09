package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"
)

// Supervisor runs a daemon's long-lived children under one context. The
// first child to fail cancels the others, and Wait returns that failure once
// every child has stopped, so the daemon never keeps running with a dead
// child.
type Supervisor struct {
	group *errgroup.Group
	ctx   context.Context
}

// NewSupervisor returns a Supervisor whose children stop when ctx ends or
// any one of them fails.
func NewSupervisor(ctx context.Context) *Supervisor {
	group, ctx := errgroup.WithContext(ctx)
	return &Supervisor{group: group, ctx: ctx}
}

// Go starts a child. run must return when its context ends; a non-nil error
// is fatal and stops every child.
func (s *Supervisor) Go(name string, run func(context.Context) error) {
	s.group.Go(func() error {
		if err := run(s.ctx); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	})
}

// GoService starts a child that runs in the background behind a stop
// function, such as StartCollector or StartPolicyRefresher. stop runs when the
// supervisor's context ends and must block until the child has finished.
func (s *Supervisor) GoService(start func(context.Context) (stop func())) {
	stop := start(s.ctx)
	s.group.Go(func() error {
		<-s.ctx.Done()
		stop()
		return nil
	})
}

// Wait blocks until every child has stopped and returns the first fatal
// error.
func (s *Supervisor) Wait() error {
	return s.group.Wait()
}

// ServeHTTP serves srv on ln until ctx ends, then shuts it down within
// shutdownTimeout. A listener failure is returned as fatal.
func ServeHTTP(ctx context.Context, srv *http.Server, ln net.Listener, shutdownTimeout time.Duration) error {
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	select {
	case err := <-served:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("runtime_http_shutdown_incomplete", "error", err)
		_ = srv.Close()
	}
	<-served
	return nil
}
