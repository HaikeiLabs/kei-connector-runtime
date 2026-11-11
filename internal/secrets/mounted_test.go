package secrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeMountedSecret writes value to root/name and returns the full path.
func writeMountedSecret(t *testing.T, root, name, value string) string {
	t.Helper()
	full := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(full, []byte(value), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return full
}

func TestMountedReadsFile(t *testing.T) {
	root := t.TempDir()
	writeMountedSecret(t, root, "snowflake/key.pem", "the-key")

	store, err := NewMountedStore(root)
	if err != nil {
		t.Fatalf("NewMountedStore: %v", err)
	}
	got, err := store.Get(context.Background(), "mounted", "mounted:snowflake/key.pem")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if *got != "the-key" {
		t.Fatalf("Get = %q, want the-key", *got)
	}
}

func TestMountedTrimsOneTrailingNewline(t *testing.T) {
	root := t.TempDir()
	writeMountedSecret(t, root, "one", "value\n")
	writeMountedSecret(t, root, "two", "value\n\n")
	writeMountedSecret(t, root, "none", "value")

	store, err := NewMountedStore(root)
	if err != nil {
		t.Fatalf("NewMountedStore: %v", err)
	}
	cases := []struct {
		name string
		want string
	}{
		{"one", "value"},
		{"two", "value\n"}, // only a single trailing newline is trimmed
		{"none", "value"},
	}
	for _, tc := range cases {
		got, err := store.Get(context.Background(), "mounted", "mounted:"+tc.name)
		if err != nil {
			t.Fatalf("Get(%s): %v", tc.name, err)
		}
		if *got != tc.want {
			t.Fatalf("Get(%s) = %q, want %q", tc.name, *got, tc.want)
		}
	}
}

func TestMountedRejectsDotDot(t *testing.T) {
	root := t.TempDir()
	store, err := NewMountedStore(root)
	if err != nil {
		t.Fatalf("NewMountedStore: %v", err)
	}
	_, err = store.Get(context.Background(), "mounted", "mounted:../x")
	if err == nil {
		t.Fatal("Get(mounted:../x) succeeded, want rejection")
	}
}

func TestMountedRejectsAbsolute(t *testing.T) {
	root := t.TempDir()
	store, err := NewMountedStore(root)
	if err != nil {
		t.Fatalf("NewMountedStore: %v", err)
	}
	_, err = store.Get(context.Background(), "mounted", "mounted:/etc/passwd")
	if err == nil {
		t.Fatal("Get(mounted:/etc/passwd) succeeded, want rejection")
	}
}

func TestMountedRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsideFile := writeMountedSecret(t, outside, "secret", "outside")

	link := filepath.Join(root, "link")
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	store, err := NewMountedStore(root)
	if err != nil {
		t.Fatalf("NewMountedStore: %v", err)
	}
	_, err = store.Get(context.Background(), "mounted", "mounted:link")
	if err == nil {
		t.Fatal("Get(mounted:link) succeeded, want symlink-escape rejection")
	}
}

func TestMountedMissingFileErrorHasNoValue(t *testing.T) {
	root := t.TempDir()
	store, err := NewMountedStore(root)
	if err != nil {
		t.Fatalf("NewMountedStore: %v", err)
	}
	_, err = store.Get(context.Background(), "mounted", "mounted:does-not-exist")
	if err == nil {
		t.Fatal("Get succeeded, want error for missing file")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get error = %v, want ErrNotFound", err)
	}
	if strings.Contains(err.Error(), "does-not-exist") {
		t.Fatalf("error echoes the reference: %v", err)
	}
}

func TestMountedErrorsNeverContainSecret(t *testing.T) {
	const value = "s3cr3t-value"
	root := t.TempDir()
	writeMountedSecret(t, root, "real", value)
	outside := t.TempDir()
	outsideFile := writeMountedSecret(t, outside, "real", value)
	if err := os.Symlink(outsideFile, filepath.Join(root, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	store, err := NewMountedStore(root)
	if err != nil {
		t.Fatalf("NewMountedStore: %v", err)
	}

	refs := []string{
		"mounted:../x",
		"mounted:/etc/passwd",
		"mounted:link",
		"mounted:missing",
	}
	// Also the wrong-backend-name error path.
	if _, err := store.Get(context.Background(), "aws-secrets-manager", "mounted:real"); err == nil {
		t.Fatal("Get with wrong backend succeeded, want error")
	}
	refs = append(refs, "mounted:real")

	for _, ref := range refs {
		_, err := store.Get(context.Background(), "mounted", ref)
		if err == nil {
			t.Fatalf("Get(%s) succeeded, want an error", ref)
		}
		if strings.Contains(err.Error(), value) {
			t.Fatalf("Get(%s) error contains the secret value: %v", ref, err)
		}
	}
}

func TestMountedRereadsAfterRotation(t *testing.T) {
	root := t.TempDir()
	full := writeMountedSecret(t, root, "key", "old-value")

	store, err := NewMountedStore(root)
	if err != nil {
		t.Fatalf("NewMountedStore: %v", err)
	}
	got, err := store.Get(context.Background(), "mounted", "mounted:key")
	if err != nil {
		t.Fatalf("Get (first): %v", err)
	}
	if *got != "old-value" {
		t.Fatalf("Get (first) = %q, want old-value", *got)
	}

	// Rotate: overwrite the mounted file.
	if err := os.WriteFile(full, []byte("new-value"), 0o600); err != nil {
		t.Fatalf("WriteFile (rotate): %v", err)
	}
	got, err = store.Get(context.Background(), "mounted", "mounted:key")
	if err != nil {
		t.Fatalf("Get (second): %v", err)
	}
	if *got != "new-value" {
		t.Fatalf("Get (second) = %q, want new-value (no caching)", *got)
	}
}

func TestDefaultRegistryHasMounted(t *testing.T) {
	reg := DefaultBackendRegistry()
	store, err := reg.store("mounted")
	if err != nil {
		t.Fatalf("registry has no mounted backend: %v", err)
	}
	if store == nil {
		t.Fatal("mounted backend is nil")
	}
}
