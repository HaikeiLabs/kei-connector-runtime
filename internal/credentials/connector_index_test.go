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
