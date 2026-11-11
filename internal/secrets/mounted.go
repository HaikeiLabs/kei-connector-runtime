package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// mountedStore implements Store for secrets delivered as files mounted into
// the runtime container (a Kubernetes Secret volume or the Secrets Store CSI
// driver). The runtime stays decision-only: it reads the file it is pointed
// at and never writes to the mount.
//
// Reference form: mounted:<relative/path>, resolved under the root directory
// from KEI_SECRETS_MOUNT_DIR (default /var/run/secrets/kei). The file is read
// on every call, so a rotated secret is picked up on the existing 401
// re-fetch without a restart.
type mountedStore struct {
	root string
}

const (
	// mountedBackendName is the registered backend name for mounted secrets.
	mountedBackendName = "mounted"
	// mountedRefPrefix is the required reference prefix.
	mountedRefPrefix = "mounted:"
	// mountedEnvVar overrides the mount root directory.
	mountedEnvVar = "KEI_SECRETS_MOUNT_DIR"
	// defaultMountedRoot is the conventional mount point inside the runtime
	// container.
	defaultMountedRoot = "/var/run/secrets/kei"
)

// NewMountedStore creates a mounted secret store rooted at root. The root is
// taken as an argument (rather than read from the environment here) so tests
// can point it at a temporary directory.
func NewMountedStore(root string) (Store, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, mountedBackendName)
	}
	return &mountedStore{root: root}, nil
}

// NewMountedStoreFromEnv creates a mounted secret store rooted at
// KEI_SECRETS_MOUNT_DIR, or the default mount point when the variable is
// unset or blank.
func NewMountedStoreFromEnv() (Store, error) {
	root := os.Getenv(mountedEnvVar)
	if strings.TrimSpace(root) == "" {
		root = defaultMountedRoot
	}
	return NewMountedStore(root)
}

// parseMountedRef parses a mounted secret reference into its relative path.
// The path must be non-empty, relative, and free of dot-dot segments. Errors
// are generic and never echo the reference.
func parseMountedRef(secretRef string) (string, error) {
	if !strings.HasPrefix(secretRef, mountedRefPrefix) {
		return "", fmt.Errorf("%w: %s", ErrRefMalformed, mountedBackendName)
	}
	rel := strings.TrimPrefix(secretRef, mountedRefPrefix)
	if rel == "" {
		return "", fmt.Errorf("%w: %s", ErrRefMalformed, mountedBackendName)
	}
	if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, "../") || strings.Contains(rel, "/../") || strings.HasSuffix(rel, "/..") {
		return "", fmt.Errorf("%w: %s", ErrRefMalformed, mountedBackendName)
	}
	return rel, nil
}

// resolvePath joins rel under the store root and resolves symlinks, refusing
// any result that escapes the root. Errors are generic and never echo the
// reference or the resolved path.
func (s *mountedStore) resolvePath(rel string) (string, error) {
	root, err := filepath.EvalSymlinks(s.root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("%w: %s", ErrUnavailable, mountedBackendName)
	}
	full := filepath.Join(root, rel)
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("%w: %s", ErrUnavailable, mountedBackendName)
	}
	if resolved != root && !strings.HasPrefix(resolved, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: %s", ErrUnavailable, mountedBackendName)
	}
	return resolved, nil
}

// Get reads the secret file on every call (no caching) and trims a single
// trailing newline, so rotated secrets are picked up immediately.
func (s *mountedStore) Get(ctx context.Context, backend, secretRef string) (*string, error) {
	if backend != mountedBackendName {
		return nil, fmt.Errorf("%w: backend is %q, expected %s", ErrUnavailable, backend, mountedBackendName)
	}
	rel, err := parseMountedRef(secretRef)
	if err != nil {
		return nil, err
	}
	resolved, err := s.resolvePath(rel)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, mountedBackendName)
	}
	if strings.HasSuffix(string(data), "\n") {
		data = data[:len(data)-1]
	}
	value := string(data)
	return &value, nil
}

// Put is unsupported: the mount is read-only from the runtime's point of
// view. Secrets are delivered by the orchestrator (k8s, CSI driver).
func (s *mountedStore) Put(ctx context.Context, backend, secretRef, value string) error {
	if backend != mountedBackendName {
		return fmt.Errorf("%w: backend is %q, expected %s", ErrUnavailable, backend, mountedBackendName)
	}
	return fmt.Errorf("%w: %s", ErrUnavailable, mountedBackendName)
}

// Delete is unsupported: the runtime never mutates the mount.
func (s *mountedStore) Delete(ctx context.Context, backend, secretRef string) error {
	if backend != mountedBackendName {
		return fmt.Errorf("%w: backend is %q, expected %s", ErrUnavailable, backend, mountedBackendName)
	}
	return fmt.Errorf("%w: %s", ErrUnavailable, mountedBackendName)
}

// Validate reports whether the referenced file exists and is readable.
func (s *mountedStore) Validate(ctx context.Context, backend, secretRef string) error {
	_, err := s.Get(ctx, backend, secretRef)
	if errors.Is(err, ErrNotFound) {
		return ErrNotFound
	}
	return err
}
