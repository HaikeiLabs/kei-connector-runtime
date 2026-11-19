package invoke

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	runtimecredentials "github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

// HAI-1071: shared opaque_ref connector credentials are served from daemon
// memory. They are prefetched when a session starts and when the bundle
// syncs, refreshed in the background with backoff, dropped on session end,
// connector removal or a changed reference, never logged, and a call never
// waits on the secret store.

const (
	cacheConnectorID = "00000000-0000-4000-8000-000000001071"
	cacheField       = "dsn"
	cacheBackend     = "aws-secrets-manager"
	cacheRef         = "aws-secrets-manager://us-east-1/kei/connectors/" + cacheConnectorID + "/" + cacheField
	cacheValue       = "cache-canary-1071-v1"
	cacheRotated     = "cache-canary-1071-v2"
)

// cacheStore counts reads; it can fail or sleep on demand.
type cacheStore struct {
	mu    sync.Mutex
	value string
	fail  bool
	sleep time.Duration
	reads int
}

func (s *cacheStore) Get(ctx context.Context, _, _ string) (*string, error) {
	s.mu.Lock()
	s.reads++
	value, fail, sleep := s.value, s.fail, s.sleep
	s.mu.Unlock()
	if sleep > 0 {
		select {
		case <-time.After(sleep):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if fail || value == "" {
		return nil, errors.New("secret store unavailable")
	}
	return &value, nil
}

func (s *cacheStore) set(fn func(*cacheStore)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

func (s *cacheStore) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

func cacheDescriptor() policybundle.Connector {
	return policybundle.Connector{
		ID: cacheConnectorID, Name: "pg", Provider: "postgres", CredentialSource: "opaque_ref", AccountModel: "shared",
		CredentialRef: "kei://connectors/" + cacheConnectorID + "/" + cacheField, CredentialBackend: cacheBackend,
	}
}

type cacheRig struct {
	cache *SecretCache
	store *cacheStore
	logs  *bytes.Buffer
	now   time.Time
	mu    sync.Mutex
}

func (r *cacheRig) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

func newCacheRig(t *testing.T) *cacheRig {
	t.Helper()
	logs := &bytes.Buffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	index := runtimecredentials.ConnectorIndexPath(filepath.Join(t.TempDir(), "state"))
	if err := runtimecredentials.WriteConnectorReference(index, runtimecredentials.ConnectorReference{ConnectorID: cacheConnectorID, Field: cacheField, SecretBackend: cacheBackend, SecretRef: cacheRef, Generation: 1}); err != nil {
		t.Fatal(err)
	}
	rig := &cacheRig{store: &cacheStore{value: cacheValue}, logs: logs, now: time.Unix(1_800_000_000, 0)}
	rig.cache = NewSecretCache(SecretResolver{IndexPath: index, Store: rig.store, Timeout: 50 * time.Millisecond}, SecretCacheOptions{
		RefreshInterval: time.Minute, MinBackoff: time.Second, MaxBackoff: 8 * time.Second,
		Now: func() time.Time { rig.mu.Lock(); defer rig.mu.Unlock(); return rig.now },
	})
	return rig
}

func (r *cacheRig) assertNoValueLogged(t *testing.T) {
	t.Helper()
	for _, needle := range []string{cacheValue, cacheRotated, "cache-canary", cacheRef} {
		if strings.Contains(r.logs.String(), needle) {
			t.Fatalf("logs contain %q:\n%s", needle, r.logs.String())
		}
	}
}

func resolveFast(t *testing.T, c *SecretCache, conn policybundle.Connector) (string, error) {
	t.Helper()
	start := time.Now()
	value, err := c.Resolve(context.Background(), conn)
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("Resolve took %s, want a memory read under 50ms", elapsed)
	}
	return value, err
}

func codeOf(err error) string {
	var se *SecretError
	if errors.As(err, &se) {
		return se.Code
	}
	return ""
}

func TestSecretCacheSteadyStateDoesNoStoreIO(t *testing.T) {
	rig := newCacheRig(t)
	rig.cache.SetConnectors([]policybundle.Connector{cacheDescriptor()})
	rig.cache.SessionStarted(context.Background(), "s1")
	if rig.store.readCount() != 1 {
		t.Fatalf("session start read the store %d times, want one prefetch", rig.store.readCount())
	}
	// The store now sleeps 5s and then fails: no call may wait on it.
	rig.store.set(func(s *cacheStore) { s.sleep, s.fail = 5*time.Second, true })
	for range 100 {
		value, err := resolveFast(t, rig.cache, cacheDescriptor())
		if err != nil || value != cacheValue {
			t.Fatalf("value matches %v, err %v", value == cacheValue, err)
		}
	}
	if rig.store.readCount() != 1 {
		t.Fatalf("steady-state calls read the store: %d reads", rig.store.readCount())
	}
	rig.assertNoValueLogged(t)
}

func TestSecretCachePrefetchesOnBundleSync(t *testing.T) {
	rig := newCacheRig(t)
	rig.cache.SessionStarted(context.Background(), "s1")
	if _, err := resolveFast(t, rig.cache, cacheDescriptor()); codeOf(err) != "credential_unavailable" {
		t.Fatalf("before the bundle names the connector: err %v, want credential_unavailable", err)
	}
	rig.cache.SetConnectors([]policybundle.Connector{cacheDescriptor()})
	rig.cache.Refresh(context.Background())
	if rig.store.readCount() != 1 {
		t.Fatalf("bundle sync prefetch read the store %d times, want 1", rig.store.readCount())
	}
	if value, err := resolveFast(t, rig.cache, cacheDescriptor()); err != nil || value != cacheValue {
		t.Fatalf("after the sync: value matches %v, err %v", value == cacheValue, err)
	}
}

func TestSecretCacheBackgroundRunPrefetchesOnSync(t *testing.T) {
	rig := newCacheRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rig.cache.Run(ctx)
	rig.cache.SessionStarted(context.Background(), "s1")
	rig.cache.SetConnectors([]policybundle.Connector{cacheDescriptor()})
	deadline := time.Now().Add(2 * time.Second)
	for {
		if value, err := rig.cache.Resolve(context.Background(), cacheDescriptor()); err == nil && value == cacheValue {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the background loop never prefetched the synced connector")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestSecretCacheRefreshPicksUpRotation(t *testing.T) {
	rig := newCacheRig(t)
	rig.cache.SetConnectors([]policybundle.Connector{cacheDescriptor()})
	rig.cache.SessionStarted(context.Background(), "s1")
	rig.store.set(func(s *cacheStore) { s.value = cacheRotated })

	rig.cache.Refresh(context.Background())
	if value, _ := resolveFast(t, rig.cache, cacheDescriptor()); value != cacheValue {
		t.Fatal("refreshed before the refresh interval elapsed")
	}
	rig.advance(time.Minute)
	rig.cache.Refresh(context.Background())
	if value, err := resolveFast(t, rig.cache, cacheDescriptor()); err != nil || value != cacheRotated {
		t.Fatalf("after the refresh interval: rotated value served %v, err %v", value == cacheRotated, err)
	}

	// A bundle sync also refreshes at once.
	rig.store.set(func(s *cacheStore) { s.value = cacheValue })
	rig.cache.SetConnectors([]policybundle.Connector{cacheDescriptor()})
	rig.cache.Refresh(context.Background())
	if value, _ := resolveFast(t, rig.cache, cacheDescriptor()); value != cacheValue {
		t.Fatal("a bundle sync did not refresh the value")
	}
	rig.assertNoValueLogged(t)
}

func TestSecretCacheOutageKeepsLoadedValueAndBacksOff(t *testing.T) {
	rig := newCacheRig(t)
	rig.cache.SetConnectors([]policybundle.Connector{cacheDescriptor()})
	rig.cache.SessionStarted(context.Background(), "s1")
	rig.store.set(func(s *cacheStore) { s.fail = true })
	rig.advance(time.Minute)
	rig.cache.Refresh(context.Background())
	if value, err := resolveFast(t, rig.cache, cacheDescriptor()); err != nil || value != cacheValue {
		t.Fatalf("a store outage broke a loaded value: matches %v, err %v", value == cacheValue, err)
	}
	reads := rig.store.readCount()
	rig.cache.Refresh(context.Background())
	if rig.store.readCount() != reads {
		t.Fatal("retried before the backoff elapsed")
	}
	rig.advance(time.Second)
	rig.cache.Refresh(context.Background())
	if rig.store.readCount() != reads+1 {
		t.Fatalf("reads = %d, want a retry after the first backoff", rig.store.readCount()-reads)
	}
	rig.advance(time.Second)
	rig.cache.Refresh(context.Background())
	if rig.store.readCount() != reads+1 {
		t.Fatal("the backoff did not grow after a second failure")
	}
	rig.assertNoValueLogged(t)
}

func TestSecretCacheLoadFailureDeniesImmediately(t *testing.T) {
	rig := newCacheRig(t)
	rig.store.set(func(s *cacheStore) { s.fail = true })
	rig.cache.SetConnectors([]policybundle.Connector{cacheDescriptor()})
	rig.cache.SessionStarted(context.Background(), "s1")
	rig.store.set(func(s *cacheStore) { s.fail, s.sleep = false, 5*time.Second })
	reads := rig.store.readCount()
	if _, err := resolveFast(t, rig.cache, cacheDescriptor()); codeOf(err) != "credential_unavailable" {
		t.Fatalf("err = %v, want credential_unavailable", err)
	}
	if rig.store.readCount() != reads {
		t.Fatal("a call on a failed connector read the store")
	}
}

func TestSecretCacheDropsValues(t *testing.T) {
	t.Run("connector removed from the bundle", func(t *testing.T) {
		rig := newCacheRig(t)
		rig.cache.SetConnectors([]policybundle.Connector{cacheDescriptor()})
		rig.cache.SessionStarted(context.Background(), "s1")
		rig.cache.SetConnectors(nil)
		if _, err := resolveFast(t, rig.cache, cacheDescriptor()); codeOf(err) != "credential_unavailable" {
			t.Fatalf("err = %v, want credential_unavailable after removal", err)
		}
		if rig.cache.held() != 0 {
			t.Fatalf("%d values still held after removal", rig.cache.held())
		}
	})
	t.Run("credential reference changed", func(t *testing.T) {
		rig := newCacheRig(t)
		rig.cache.SetConnectors([]policybundle.Connector{cacheDescriptor()})
		rig.cache.SessionStarted(context.Background(), "s1")
		changed := cacheDescriptor()
		changed.CredentialBackend = "azure-key-vault"
		rig.cache.SetConnectors([]policybundle.Connector{changed})
		if _, err := resolveFast(t, rig.cache, cacheDescriptor()); err == nil {
			t.Fatal("the old descriptor still resolves after its reference changed")
		}
		if _, err := resolveFast(t, rig.cache, changed); err == nil {
			t.Fatal("the changed descriptor resolves before it was loaded")
		}
	})
	t.Run("last session ends", func(t *testing.T) {
		rig := newCacheRig(t)
		rig.cache.SetConnectors([]policybundle.Connector{cacheDescriptor()})
		rig.cache.SessionStarted(context.Background(), "s1")
		rig.cache.SessionStarted(context.Background(), "s2")
		rig.cache.SessionEnded("s1")
		if value, _ := resolveFast(t, rig.cache, cacheDescriptor()); value != cacheValue {
			t.Fatal("value dropped while a session is still live")
		}
		rig.cache.SessionEnded("s2")
		if _, err := resolveFast(t, rig.cache, cacheDescriptor()); codeOf(err) != "credential_unavailable" {
			t.Fatalf("err = %v, want credential_unavailable after the last session ended", err)
		}
		if rig.cache.held() != 0 {
			t.Fatalf("%d values still held with no session", rig.cache.held())
		}
		rig.cache.SetConnectors([]policybundle.Connector{cacheDescriptor()})
		reads := rig.store.readCount()
		rig.cache.Refresh(context.Background())
		if rig.store.readCount() != reads {
			t.Fatal("prefetched with no live session")
		}
	})
	t.Run("flush", func(t *testing.T) {
		rig := newCacheRig(t)
		rig.cache.SetConnectors([]policybundle.Connector{cacheDescriptor()})
		rig.cache.SessionStarted(context.Background(), "s1")
		rig.cache.Flush()
		if rig.cache.held() != 0 {
			t.Fatal("Flush kept a value")
		}
	})
}

func TestSecretCacheSkipsNonSharedConnectors(t *testing.T) {
	rig := newCacheRig(t)
	perUser := cacheDescriptor()
	perUser.AccountModel = "per_user"
	oauth := cacheDescriptor()
	oauth.ID, oauth.CredentialSource, oauth.CredentialRef, oauth.CredentialBackend = "00000000-0000-4000-8000-000000000002", "oauth", "", ""
	rig.cache.SetConnectors([]policybundle.Connector{perUser, oauth})
	rig.cache.SessionStarted(context.Background(), "s1")
	if rig.store.readCount() != 0 {
		t.Fatalf("prefetched a non-shared connector: %d reads", rig.store.readCount())
	}
}

func TestSecretCacheValueNeverPrinted(t *testing.T) {
	rig := newCacheRig(t)
	rig.cache.SetConnectors([]policybundle.Connector{cacheDescriptor()})
	rig.cache.SessionStarted(context.Background(), "s1")
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if text := fmt.Sprintf(format, rig.cache); strings.Contains(text, cacheValue) {
			t.Fatalf("%s of the cache prints the value", format)
		}
	}
}
