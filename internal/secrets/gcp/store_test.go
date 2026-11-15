package gcp_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	gax "github.com/googleapis/gax-go/v2"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets/gcp"
)

// fakeClient is a deterministic in-memory GCP Secret Manager. A secret is a
// list of version payloads; "latest" is the last one; a missing secret or
// version is codes.NotFound. It never needs live GCP.
type fakeClient struct {
	versions map[string][][]byte
	putErr   error
	getErr   error
	delErr   error
}

func (f *fakeClient) AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	if f.putErr != nil {
		return nil, f.putErr
	}
	f.versions[req.GetParent()] = append(f.versions[req.GetParent()], req.GetPayload().GetData())
	n := len(f.versions[req.GetParent()])
	return &secretmanagerpb.SecretVersion{Name: fmt.Sprintf("%s/versions/%d", req.GetParent(), n)}, nil
}

func (f *fakeClient) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	parent, version, ok := strings.Cut(req.GetName(), "/versions/")
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "missing version")
	}
	versions := f.versions[parent]
	if len(versions) == 0 {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	var data []byte
	if version == "latest" {
		data = versions[len(versions)-1]
	} else {
		n, err := strconv.Atoi(version)
		if err != nil || n < 1 || n > len(versions) {
			return nil, status.Error(codes.NotFound, "version not found")
		}
		data = versions[n-1]
	}
	return &secretmanagerpb.AccessSecretVersionResponse{Payload: &secretmanagerpb.SecretPayload{Data: data}}, nil
}

func (f *fakeClient) DeleteSecret(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, opts ...gax.CallOption) error {
	if f.delErr != nil {
		return f.delErr
	}
	delete(f.versions, req.GetName())
	return nil
}

const testRef = "projects/my-proj/secrets/github-token"

func TestPutThenGetRoundTrip(t *testing.T) {
	store := gcp.NewStoreWithClient(&fakeClient{versions: map[string][][]byte{}})
	const value = "super-secret-value-123"
	if err := store.Put(context.Background(), "gcp-secret-manager", testRef, value); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := store.Get(context.Background(), "gcp-secret-manager", testRef)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil || *got != value {
		t.Fatal("Get did not return the written value")
	}
}

func TestPermissionDeniedFailsClosedAndRedacts(t *testing.T) {
	store := gcp.NewStoreWithClient(&fakeClient{
		versions: map[string][][]byte{},
		putErr:   status.Error(codes.PermissionDenied, "Permission 'secretmanager.versions.access' denied on projects/my-proj/secrets/github-token"),
	})
	const value = "super-secret-value-123"
	err := store.Put(context.Background(), "gcp-secret-manager", testRef, value)
	if err == nil {
		t.Fatal("Put with permission denied: want an error (fail closed), got nil")
	}
	if !errors.Is(err, secrets.ErrUnavailable) {
		t.Fatalf("Put = %v, want errors.Is(err, secrets.ErrUnavailable)", err)
	}
	if strings.Contains(err.Error(), value) {
		t.Fatalf("error contains the secret value: %v", err)
	}
}

func TestRotationReturnsLatestGeneration(t *testing.T) {
	store := gcp.NewStoreWithClient(&fakeClient{versions: map[string][][]byte{}})
	if err := store.Put(context.Background(), "gcp-secret-manager", testRef, "generation-1"); err != nil {
		t.Fatalf("Put generation 1: %v", err)
	}
	if err := store.Put(context.Background(), "gcp-secret-manager", testRef, "generation-2"); err != nil {
		t.Fatalf("Put generation 2: %v", err)
	}
	got, err := store.Get(context.Background(), "gcp-secret-manager", testRef)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if *got != "generation-2" {
		t.Fatalf("Get = %q, want the latest generation", *got)
	}
	first, err := store.Get(context.Background(), "gcp-secret-manager", testRef+"/versions/1")
	if err != nil {
		t.Fatalf("Get(version 1): %v", err)
	}
	if *first != "generation-1" {
		t.Fatalf("Get(version 1) = %q, want the first generation", *first)
	}
}

func TestGetMissingSecretIsNotFound(t *testing.T) {
	store := gcp.NewStoreWithClient(&fakeClient{versions: map[string][][]byte{}})
	_, err := store.Get(context.Background(), "gcp-secret-manager", testRef)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("Get(missing) = %v, want errors.Is(err, secrets.ErrNotFound)", err)
	}
}

func TestSecretValueNeverAppearsInLogsOrErrors(t *testing.T) {
	store := gcp.NewStoreWithClient(&fakeClient{
		versions: map[string][][]byte{},
		putErr:   status.Error(codes.PermissionDenied, "Permission 'secretmanager.versions.access' denied on projects/my-proj/secrets/github-token"),
		getErr:   status.Error(codes.NotFound, "projects/my-proj/secrets/github-token"),
	})
	const value = "super-secret-value-123"

	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	putErr := store.Put(context.Background(), "gcp-secret-manager", testRef, value)
	getVal, getErr := store.Get(context.Background(), "gcp-secret-manager", testRef)
	w.Close()
	os.Stderr = oldStderr
	var logs bytes.Buffer
	_, _ = io.Copy(&logs, r)

	if getVal != nil && *getVal == value {
		t.Fatal("Get returned the secret after a failed write")
	}
	for _, e := range []error{putErr, getErr} {
		if e != nil && strings.Contains(e.Error(), value) {
			t.Fatalf("error contains the secret value: %v", e)
		}
	}
	if strings.Contains(logs.String(), value) {
		t.Fatalf("captured log output contains the secret value: %s", logs.String())
	}
}

// HAI-1022: Validate classifies a permission failure as ErrPermissionDenied
// (still ErrUnavailable for existing callers) so credential sync can report it.
func TestValidatePermissionDeniedIsClassified(t *testing.T) {
	for _, code := range []codes.Code{codes.PermissionDenied, codes.Unauthenticated} {
		store := gcp.NewStoreWithClient(&fakeClient{
			versions: map[string][][]byte{},
			getErr:   status.Error(code, "denied on "+testRef),
		})
		err := store.Validate(context.Background(), "gcp-secret-manager", testRef)
		if !errors.Is(err, secrets.ErrPermissionDenied) || !errors.Is(err, secrets.ErrUnavailable) {
			t.Fatalf("Validate(%v) = %v, want ErrPermissionDenied and ErrUnavailable", code, err)
		}
		if strings.Contains(err.Error(), testRef) {
			t.Fatalf("error leaks the reference: %v", err)
		}
	}
	store := gcp.NewStoreWithClient(&fakeClient{versions: map[string][][]byte{}, getErr: status.Error(codes.Internal, "boom")})
	if err := store.Validate(context.Background(), "gcp-secret-manager", testRef); errors.Is(err, secrets.ErrPermissionDenied) || errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("Validate(Internal) = %v, want neither not found nor permission denied", err)
	}
}
