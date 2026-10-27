package credentials

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConnectorReferenceIndexWritesPrivateAtomicLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime", "connector-credentials.json")
	entry := ConnectorReference{ConnectorID: "00000000-0000-4000-8000-000000000123", Field: "api_token", SecretBackend: "aws-secrets-manager", SecretRef: "aws-secrets-manager://region/connectors/00000000-0000-4000-8000-000000000123/api_token", Generation: 7}
	if err := WriteConnectorReference(path, entry); err != nil {
		t.Fatal(err)
	}
	got, err := ReadConnectorReference(path, entry.ConnectorID, entry.Field)
	if err != nil {
		t.Fatal(err)
	}
	if got != entry {
		t.Fatalf("entry = %+v, want %+v", got, entry)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("index mode = %o, want 600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-value") {
		t.Fatal("index contains secret value")
	}
}

func TestResolvedExternalConnectorIDsReturnsResolvedConnectors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime", "connector-credentials.json")
	first := ConnectorReference{ConnectorID: "00000000-0000-4000-8000-000000000123", Field: "api_token", SecretBackend: "aws-secrets-manager", SecretRef: "aws-secrets-manager://region/connectors/00000000-0000-4000-8000-000000000123/api_token", Generation: 1}
	if err := WriteConnectorReference(path, first); err != nil {
		t.Fatal(err)
	}
	second := ConnectorReference{ConnectorID: "00000000-0000-4000-8000-000000000456", Field: "api_token", SecretBackend: "aws-secrets-manager", SecretRef: "aws-secrets-manager://region/connectors/00000000-0000-4000-8000-000000000456/api_token", Generation: 1}
	if err := WriteConnectorReference(path, second); err != nil {
		t.Fatal(err)
	}
	// The same connector resolving a second field still activates once.
	again := first
	again.Field = "api_secret"
	again.SecretRef = "aws-secrets-manager://region/connectors/00000000-0000-4000-8000-000000000123/api_secret"
	if err := WriteConnectorReference(path, again); err != nil {
		t.Fatal(err)
	}
	ids, err := ResolvedExternalConnectorIDs(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"00000000-0000-4000-8000-000000000123", "00000000-0000-4000-8000-000000000456"}
	if len(ids) != len(want) || ids[0] != want[0] || ids[1] != want[1] {
		t.Fatalf("resolved connector ids = %v, want %v", ids, want)
	}
}

func TestResolvedExternalConnectorIDsExcludesKeiManagedRefs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connector-credentials.json")
	keiManaged := ConnectorReference{ConnectorID: "00000000-0000-4000-8000-000000000123", Field: "api_token", SecretBackend: "custom", SecretRef: "kei://connectors/00000000-0000-4000-8000-000000000123/api_token", Generation: 1}
	if err := WriteConnectorReference(path, keiManaged); err != nil {
		t.Fatal(err)
	}
	ids, err := ResolvedExternalConnectorIDs(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("resolved connector ids = %v, want none for kei:// refs", ids)
	}
}

func TestResolvedExternalConnectorIDsFailsClosedWithoutIndex(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "absent", "connector-credentials.json")
	ids, err := ResolvedExternalConnectorIDs(missingDir)
	if err != nil {
		t.Fatalf("missing state directory must not error: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("ids = %v, want none", ids)
	}
	missingFile := filepath.Join(t.TempDir(), "state", "connector-credentials.json")
	if err := os.MkdirAll(filepath.Dir(missingFile), 0700); err != nil {
		t.Fatal(err)
	}
	ids, err = ResolvedExternalConnectorIDs(missingFile)
	if err != nil {
		t.Fatalf("missing index file must not error: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("ids = %v, want none", ids)
	}
}

func TestConnectorReferenceIndexReplacesGenerationAndFailsMissingClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.json")
	entry := ConnectorReference{ConnectorID: "00000000-0000-4000-8000-000000000123", Field: "api_token", SecretBackend: "aws-secrets-manager", SecretRef: "aws-secrets-manager://region/connectors/00000000-0000-4000-8000-000000000123/api_token", Generation: 1}
	if err := WriteConnectorReference(path, entry); err != nil {
		t.Fatal(err)
	}
	entry.Generation = 2
	if err := WriteConnectorReference(path, entry); err != nil {
		t.Fatal(err)
	}
	got, err := ReadConnectorReference(path, entry.ConnectorID, entry.Field)
	if err != nil || got.SecretRef != entry.SecretRef || got.Generation != 2 {
		t.Fatalf("latest entry = %+v, err=%v", got, err)
	}
	if _, err := ReadConnectorReference(path, "00000000-0000-4000-8000-000000000999", "api_token"); err == nil {
		t.Fatal("missing entry unexpectedly resolved")
	}
}
