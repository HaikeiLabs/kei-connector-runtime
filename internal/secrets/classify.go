package secrets

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"
)

// The classified backend failures (HAI-1022). Not found and permission
// denied are fixed, redacted errors: the provider's message can echo the
// reference, so it is dropped. Permission denied also wraps ErrUnavailable so
// callers that only check ErrUnavailable keep failing closed.
var (
	errAWSPermissionDenied   = fmt.Errorf("%w: %w: aws-secrets-manager access denied: grant the runtime identity secretsmanager:GetSecretValue on the secret", ErrUnavailable, ErrPermissionDenied)
	errAzurePermissionDenied = fmt.Errorf("%w: %w: azure-key-vault access denied: grant the runtime identity get on secrets in the vault", ErrUnavailable, ErrPermissionDenied)
)

// classifyAWSError maps an AWS Secrets Manager error: ResourceNotFoundException
// is ErrNotFound, AccessDeniedException is ErrPermissionDenied, and anything
// else is ErrUnavailable.
func classifyAWSError(err error) error {
	var resourceNotFound *types.ResourceNotFoundException
	if errors.As(err, &resourceNotFound) {
		return ErrNotFound
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode() == "AccessDeniedException" {
		return errAWSPermissionDenied
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}

// classifyAzureError maps an Azure Key Vault error: 404 is ErrNotFound, 401
// and 403 are ErrPermissionDenied, and anything else is ErrUnavailable.
func classifyAzureError(err error) error {
	var responseError *azcore.ResponseError
	if errors.As(err, &responseError) {
		switch responseError.StatusCode {
		case http.StatusNotFound:
			return ErrNotFound
		case http.StatusUnauthorized, http.StatusForbidden:
			return errAzurePermissionDenied
		}
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}
