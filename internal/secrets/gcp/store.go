// Package gcp is the runtime's GCP Secret Manager secret-store backend. It
// writes each delivered secret as a new secret version (a rotation
// generation) and reads the latest version. It authenticates with the host's
// Application Default Credentials (workload identity) and reads no key files.
// Errors are a closed, redacted set — not found, permission denied, or
// provider error — and a secret value never appears in an error.
package gcp

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	gax "github.com/googleapis/gax-go/v2"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets/errdef"
)

// Backend is the control-plane name of this backend.
const Backend = "gcp-secret-manager"

// Client is the subset of the GCP Secret Manager API the store uses. The
// generated apiv1 client satisfies it; tests use a deterministic in-memory
// fake so CI never needs live GCP.
type Client interface {
	AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	DeleteSecret(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, opts ...gax.CallOption) error
}

// Store is the GCP Secret Manager backend for the runtime's secret store.
// The client is created lazily on the first call, so registering and
// constructing the store never requires GCP credentials: a deployment that
// uses no GCP backend never pays for one, and a misconfigured GCP identity
// fails only when a GCP secret is actually requested.
type Store struct {
	c        Client
	once     sync.Once
	buildErr error
}

// NewStore builds the backend. Its client is created on the first call from
// the host's Application Default Credentials: the pod's workload identity
// (GKE metadata server), a user-managed service account, or
// GOOGLE_APPLICATION_CREDENTIALS for local development. No key file is read
// from the runtime's state.
func NewStore() *Store {
	return &Store{}
}

// NewStoreWithClient is the seam for a deployment that builds its own client
// (an explicit endpoint or credential) and for tests.
func NewStoreWithClient(client Client) *Store {
	return &Store{c: client}
}

// client returns the backend client, creating it once on first use. A
// construction failure is redacted to the closed set: an unavailable
// backend, never a credential detail.
func (s *Store) client() (Client, error) {
	if s.c != nil {
		return s.c, nil
	}
	s.once.Do(func() {
		c, err := secretmanager.NewClient(context.Background())
		if err != nil {
			s.buildErr = fmt.Errorf("%w: gcp-secret-manager: the GCP Secret Manager client could not be created; check the runtime's workload identity", errdef.ErrUnavailable)
			return
		}
		s.c = c
	})
	return s.c, s.buildErr
}

var (
	projectID = regexp.MustCompile(`^[a-z][a-z0-9-]{4,29}$`)
	secretID  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,254}$`)
	versionID = regexp.MustCompile(`^[0-9]+$`)
)

// ParseSecretRef parses a GCP Secret Manager reference:
//
//	projects/{project}/secrets/{secret}
//	projects/{project}/secrets/{secret}/versions/{version}
//
// The returned name is the secret's resource name; version is empty when the
// reference names no version. The error never echoes the reference.
func ParseSecretRef(secretRef string) (name, version string, err error) {
	segments := strings.Split(secretRef, "/")
	if (len(segments) != 4 && len(segments) != 6) ||
		segments[0] != "projects" || segments[2] != "secrets" ||
		!projectID.MatchString(segments[1]) || !secretID.MatchString(segments[3]) {
		return "", "", errors.New("gcp-secret-manager: malformed secret reference")
	}
	name = "projects/" + segments[1] + "/secrets/" + segments[3]
	if len(segments) == 6 {
		if segments[4] != "versions" || !versionID.MatchString(segments[5]) {
			return "", "", errors.New("gcp-secret-manager: malformed secret reference")
		}
		version = segments[5]
	}
	return name, version, nil
}

// errPermissionDenied and errProvider are the closed, redacted failure
// classes. The raw provider error is never propagated: it can echo the
// reference and request details into logs.
var (
	errPermissionDenied = fmt.Errorf("%w: gcp-secret-manager permission denied: grant the workload identity roles/secretmanager.secretVersionAdder (write) and roles/secretmanager.secretAccessor (read) on the secret", errdef.ErrUnavailable)
	errProvider         = fmt.Errorf("%w: gcp-secret-manager provider error: the GCP Secret Manager call failed; check the runtime's workload identity and network egress", errdef.ErrUnavailable)
)

// classify maps a provider error to the closed, redacted set.
func classify(err error) error {
	switch status.Code(err) {
	case codes.NotFound:
		return errdef.ErrNotFound
	case codes.PermissionDenied, codes.Unauthenticated:
		return errPermissionDenied
	default:
		return errProvider
	}
}

// Get reads the latest version of the secret (or the version the reference
// names). A secret value never appears in the returned error.
func (s *Store) Get(ctx context.Context, backend, secretRef string) (*string, error) {
	if backend != Backend {
		return nil, fmt.Errorf("%w: backend is %q, expected %s", errdef.ErrUnavailable, backend, Backend)
	}
	name, version, err := ParseSecretRef(secretRef)
	if err != nil {
		return nil, err
	}
	client, err := s.client()
	if err != nil {
		return nil, err
	}
	target := name + "/versions/" + version
	if version == "" {
		target = name + "/versions/latest"
	}
	resp, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: target})
	if err != nil {
		return nil, classify(err)
	}
	if resp == nil || resp.GetPayload() == nil || len(resp.GetPayload().GetData()) == 0 {
		return nil, errdef.ErrNotFound
	}
	value := string(resp.GetPayload().GetData())
	return &value, nil
}

// Put writes the value as a new secret version (a rotation generation). A
// version in the reference is not honored for writes: a delivery always
// appends. The secret must already exist; creating secrets is the customer's
// setup step, not the runtime's.
func (s *Store) Put(ctx context.Context, backend, secretRef, value string) error {
	if backend != Backend {
		return fmt.Errorf("%w: backend is %q, expected %s", errdef.ErrUnavailable, backend, Backend)
	}
	name, _, err := ParseSecretRef(secretRef)
	if err != nil {
		return err
	}
	client, err := s.client()
	if err != nil {
		return err
	}
	_, err = client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent:  name,
		Payload: &secretmanagerpb.SecretPayload{Data: []byte(value)},
	})
	if err != nil {
		return classify(err)
	}
	return nil
}

// Delete removes the whole secret. An already-deleted secret is a no-op.
func (s *Store) Delete(ctx context.Context, backend, secretRef string) error {
	if backend != Backend {
		return fmt.Errorf("%w: backend is %q, expected %s", errdef.ErrUnavailable, backend, Backend)
	}
	name, _, err := ParseSecretRef(secretRef)
	if err != nil {
		return err
	}
	client, err := s.client()
	if err != nil {
		return err
	}
	err = client.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{Name: name})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil
		}
		return classify(err)
	}
	return nil
}

// Validate verifies that the secret exists and is readable.
func (s *Store) Validate(ctx context.Context, backend, secretRef string) error {
	_, err := s.Get(ctx, backend, secretRef)
	return err
}
