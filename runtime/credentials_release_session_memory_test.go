package runtime_test

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
)

// HAI-1071: once a session started, POST /v1/credentials:release for a shared
// opaque_ref connector is served from daemon memory. A secret store that
// sleeps 5s and then fails cannot slow or break a release, and the release
// audit row is unchanged (credential_kind secret_store).

func TestCredentialsReleaseSharedOpaqueRefFromSessionMemory(t *testing.T) {
	rig := newPGRig(t, pgRigOptions{entries: []credentials.ConnectorReference{deliveredEntry()}})
	session := createSession(t, rig.h, "ext-alice")
	if got := rig.store.readCount(); got != 1 {
		t.Fatalf("session start read the store %d times, want one prefetch", got)
	}
	rig.store.mu.Lock()
	rig.store.fail = true
	rig.store.sleep = 5 * time.Second
	rig.store.mu.Unlock()

	body := fmt.Sprintf(`{"schema":"kei.credential-release-request/v1","tool":"pg_query","connector":{"connector_id":"%s","capability":"query.run"},"resource":"%s"}`, pgConnectorID, pgResource)
	for i := range 5 {
		start := time.Now()
		rec := sessionRequest(rig.h, http.MethodPost, "/v1/credentials:release", session, body)
		if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
			t.Fatalf("release %d took %s, want under 50ms from memory", i, elapsed)
		}
		if rec.Code != http.StatusOK || !containsAll(rec.Body.String(), `"decision":"allow"`, pgDSN) {
			t.Fatalf("release %d: status %d, allow with the DSN: %v", i, rec.Code, containsAll(rec.Body.String(), `"decision":"allow"`, pgDSN))
		}
	}
	if got := rig.store.readCount(); got != 1 {
		t.Fatalf("steady-state releases read the store: %d reads after the prefetch", got-1)
	}
	if !containsAll(rig.auditText(), `"decision":"allow"`, `"credential_kind":"secret_store"`) {
		t.Fatal("the release audit row changed: want an allow with credential_kind secret_store")
	}
	rig.assertNoLeak(t)
}

func TestCredentialsReleaseSharedOpaqueRefLoadFailureDeniesAtOnce(t *testing.T) {
	rig := newPGRig(t, pgRigOptions{entries: []credentials.ConnectorReference{deliveredEntry()}})
	rig.store.mu.Lock()
	rig.store.fail = true
	rig.store.mu.Unlock()
	session := createSession(t, rig.h, "ext-alice")
	rig.store.mu.Lock()
	rig.store.fail, rig.store.sleep = false, 5*time.Second
	rig.store.mu.Unlock()
	reads := rig.store.readCount()

	body := fmt.Sprintf(`{"schema":"kei.credential-release-request/v1","tool":"pg_query","connector":{"connector_id":"%s","capability":"query.run"},"resource":"%s"}`, pgConnectorID, pgResource)
	start := time.Now()
	rec := sessionRequest(rig.h, http.MethodPost, "/v1/credentials:release", session, body)
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("a failed connector's release took %s, want an immediate deny", elapsed)
	}
	if !containsAll(rec.Body.String(), `"decision":"deny"`, `"reason_code":"credential_unavailable"`) {
		t.Fatalf("body = %s, want deny credential_unavailable", rec.Body.String())
	}
	if rig.store.readCount() != reads {
		t.Fatal("a release read the secret store")
	}
	rig.assertNoLeak(t)
}

func TestCredentialsReleaseSharedOpaqueRefDroppedWhenConnectorLeavesBundle(t *testing.T) {
	rig := newPGRig(t, pgRigOptions{entries: []credentials.ConnectorReference{deliveredEntry()}})
	session := createSession(t, rig.h, "ext-alice")
	body := fmt.Sprintf(`{"schema":"kei.credential-release-request/v1","tool":"pg_query","connector":{"connector_id":"%s","capability":"query.run"},"resource":"%s"}`, pgConnectorID, pgResource)
	if rec := sessionRequest(rig.h, http.MethodPost, "/v1/credentials:release", session, body); !containsAll(rec.Body.String(), `"decision":"allow"`) {
		t.Fatalf("before the sync: %s", rec.Body.String())
	}
	// The bundle syncs with the connector re-pointed at another backend: the
	// held value is dropped at once, and nothing is read on the call path.
	next := pgBundle(t, func(d map[string]any) map[string]any {
		d["credential_backend"] = "azure-key-vault"
		return d
	})
	next = bytes.Replace(next, []byte(`"bundle_version":1,`), []byte(`"bundle_version":2,`), 1)
	activateBundle(t, rig.dir, next)
	rig.pdp.AfterSync(nil)
	if held := rig.pdp.ConnectorSecrets(); held == nil {
		t.Fatal("no connector secrets")
	}
	rec := sessionRequest(rig.h, http.MethodPost, "/v1/credentials:release", session, body)
	if containsAll(rec.Body.String(), pgDSN) || !containsAll(rec.Body.String(), `"decision":"deny"`) {
		t.Fatalf("after the reference changed: %s, want a deny without the DSN", rec.Body.String())
	}
	rig.assertNoLeak(t)
}

func containsAll(text string, needles ...string) bool {
	for _, n := range needles {
		if !strings.Contains(text, n) {
			return false
		}
	}
	return true
}
