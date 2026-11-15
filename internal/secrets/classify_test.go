package secrets

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"
)

// HAI-1022: backend errors are classified into the closed set the external
// ref resolution reports (not found, permission denied, anything else), and
// a classified error never carries the provider's message, which can echo
// the reference.

const leakyRef = "arn:aws:secretsmanager:us-east-1:123456789012:secret:customer/crm/api-key"

func TestClassifyAWSError(t *testing.T) {
	cases := []struct {
		name           string
		err            error
		wantNotFound   bool
		wantPermission bool
	}{
		{"resource not found", &types.ResourceNotFoundException{Message: smithyMsg("no secret " + leakyRef)}, true, false},
		{"access denied", &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized to read " + leakyRef}, false, true},
		{"other api error", &smithy.GenericAPIError{Code: "InternalServiceError", Message: "boom " + leakyRef}, false, false},
		{"transport error", errors.New("dial tcp: " + leakyRef), false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyAWSError(tc.err)
			assertClassified(t, got, tc.wantNotFound, tc.wantPermission)
		})
	}
}

func TestClassifyAzureError(t *testing.T) {
	cases := []struct {
		name           string
		err            error
		wantNotFound   bool
		wantPermission bool
	}{
		{"404", &azcore.ResponseError{StatusCode: http.StatusNotFound, ErrorCode: "SecretNotFound " + leakyRef}, true, false},
		{"403", &azcore.ResponseError{StatusCode: http.StatusForbidden, ErrorCode: "Forbidden " + leakyRef}, false, true},
		{"401", &azcore.ResponseError{StatusCode: http.StatusUnauthorized, ErrorCode: "Unauthorized " + leakyRef}, false, true},
		{"500", &azcore.ResponseError{StatusCode: http.StatusInternalServerError, ErrorCode: "Internal " + leakyRef}, false, false},
		{"transport error", errors.New("dial tcp: " + leakyRef), false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyAzureError(tc.err)
			assertClassified(t, got, tc.wantNotFound, tc.wantPermission)
		})
	}
}

func assertClassified(t *testing.T, got error, wantNotFound, wantPermission bool) {
	t.Helper()
	if got == nil {
		t.Fatal("classified error is nil; want fail closed")
	}
	if errors.Is(got, ErrNotFound) != wantNotFound {
		t.Fatalf("errors.Is(%v, ErrNotFound) = %v, want %v", got, !wantNotFound, wantNotFound)
	}
	if errors.Is(got, ErrPermissionDenied) != wantPermission {
		t.Fatalf("errors.Is(%v, ErrPermissionDenied) = %v, want %v", got, !wantPermission, wantPermission)
	}
	if !wantNotFound && !errors.Is(got, ErrUnavailable) {
		t.Fatalf("errors.Is(%v, ErrUnavailable) = false; a failed call stays ErrUnavailable for existing callers", got)
	}
	if wantNotFound || wantPermission {
		if strings.Contains(got.Error(), leakyRef) {
			t.Fatalf("classified error leaks the reference: %v", got)
		}
	}
}

func smithyMsg(s string) *string { return &s }
