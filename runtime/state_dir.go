package runtime

import (
	"errors"
	"fmt"
	"strings"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

// ErrStateDirOwned means another kei-proxy process already owns the state
// directory: it runs that directory's policy refresher and audit collector.
var ErrStateDirOwned = errors.New("another kei-proxy process owns the runtime state directory")

// ClaimStateDir makes the caller the one process that refreshes policy and
// ships audit for dir (ADR-026 §5). It takes the directory's refresher lock
// without waiting and holds it until release is called, so a refresher
// started with WithClaimedStateDir never races another process for it. An
// empty dir has nothing to own and is a no-op.
func ClaimStateDir(dir string) (release func(), err error) {
	if strings.TrimSpace(dir) == "" {
		return func() {}, nil
	}
	store, err := policybundle.OpenStore(dir)
	if err != nil {
		return nil, err
	}
	release, err = store.LockRefresher()
	if errors.Is(err, policybundle.ErrRefresherLocked) {
		return nil, fmt.Errorf("%w: %s", ErrStateDirOwned, dir)
	}
	if err != nil {
		return nil, err
	}
	return release, nil
}
