package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// awsSecretsManagerStore implements SecretStore for AWS Secrets Manager. It
// holds the resolved base configuration and derives a per-region client from
// it, so an injected credential provider (e.g. an IRSA web-identity token) is
// preserved across region overrides instead of being re-resolved from the
// environment.
type awsSecretsManagerStore struct {
	base    aws.Config
	clients map[string]*secretsmanager.Client
	mu      sync.Mutex
}

// NewAWSSecretsManagerStore creates a new AWS Secrets Manager store.
// It uses the default AWS credentials chain, which includes:
// - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
// - Shared config/credentials files
// - EC2 instance metadata (IAM role)
// - ECS container credentials
// - Web identity token (IRSA for EKS)
//
// On EKS this resolves to the pod's IRSA identity: the chain reads
// AWS_WEB_IDENTITY_TOKEN_FILE, AWS_ROLE_ARN, and AWS_ROLE_SESSION_NAME and
// exchanges the projected service-account token for short-lived STS
// credentials. No static cloud credentials are read or stored.
func NewAWSSecretsManagerStore() (SecretStore, error) {
	awsCfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("create AWS config: %w", err)
	}
	return NewAWSSecretsManagerStoreFromConfig(awsCfg)
}

// NewAWSSecretsManagerStoreFromConfig is the workload-identity seam. Callers
// that build their own aws.Config — a test with a stub provider, or a
// deployment that wires an explicit STS / web-identity credential provider —
// inject it here. The store derives every region client from the injected
// config so the chosen credential provider is never replaced by the default
// chain.
func NewAWSSecretsManagerStoreFromConfig(awsCfg aws.Config) (SecretStore, error) {
	return &awsSecretsManagerStore{
		base:    awsCfg,
		clients: map[string]*secretsmanager.Client{},
	}, nil
}

// parseAWSSecretRef parses an AWS Secrets Manager secret reference.
// Format: aws-secrets-manager://region:account_id/secret_name
// Or: aws-secrets-manager:///secret_name (uses default region from config)
func parseAWSSecretRef(secretRef string) (region, secretName string, err error) {
	// Format: aws-secrets-manager://region:account_id/secret-name
	// Or: aws-secrets-manager:///secret-name (no region)
	if !strings.HasPrefix(secretRef, "aws-secrets-manager://") {
		return "", "", fmt.Errorf("invalid AWS Secrets Manager secret reference: must start with aws-secrets-manager://")
	}
	ref := strings.TrimPrefix(secretRef, "aws-secrets-manager://")
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) < 2 || parts[1] == "" {
		return "", "", fmt.Errorf("invalid AWS Secrets Manager secret reference: must be aws-secrets-manager://region/account/secret-name")
	}
	// parts[0] is region:account_id
	regionPart := parts[0]
	secretName = parts[1]
	if regionPart == "" {
		// No region specified, use default
		return "", secretName, nil
	}
	return regionPart, secretName, nil
}

func (s *awsSecretsManagerStore) clientFor(region string) (*secretsmanager.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if client, ok := s.clients[region]; ok {
		return client, nil
	}
	// Derive the region client from the injected base config so the workload
	// identity / credential provider is preserved. An empty region falls back
	// to the region resolved from the base config (e.g. the IRSA default).
	cfg := s.base
	if region != "" {
		cfg.Region = region
	}
	client := secretsmanager.NewFromConfig(cfg)
	s.clients[region] = client
	return client, nil
}

func (s *awsSecretsManagerStore) Get(ctx context.Context, backend, secretRef string) (*string, error) {
	if backend != "aws-secrets-manager" {
		return nil, fmt.Errorf("%w: backend is %q, expected aws-secrets-manager", errSecretStore, backend)
	}
	region, secretName, err := parseAWSSecretRef(secretRef)
	if err != nil {
		return nil, err
	}
	client, err := s.clientFor(region)
	if err != nil {
		return nil, err
	}
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	}
	result, err := client.GetSecretValue(ctx, input)
	if err != nil {
		var resourceNotFound *types.ResourceNotFoundException
		if errors.As(err, &resourceNotFound) {
			return nil, errSecretNotFound
		}
		return nil, fmt.Errorf("%w: %v", errSecretStore, err)
	}
	if result.SecretString == nil {
		return nil, errSecretNotFound
	}
	return result.SecretString, nil
}

func (s *awsSecretsManagerStore) Put(ctx context.Context, backend, secretRef, value string) error {
	if backend != "aws-secrets-manager" {
		return fmt.Errorf("%w: backend is %q, expected aws-secrets-manager", errSecretStore, backend)
	}
	region, secretName, err := parseAWSSecretRef(secretRef)
	if err != nil {
		return err
	}
	client, err := s.clientFor(region)
	if err != nil {
		return err
	}
	input := &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(secretName),
		SecretString: aws.String(value),
	}
	_, err = client.PutSecretValue(ctx, input)
	if err != nil {
		var notFound *types.ResourceNotFoundException
		if !errors.As(err, &notFound) {
			return fmt.Errorf("%w: %v", errSecretStore, err)
		}
		// Fresh-install cutovers have no pre-existing secret. Create the secret
		// once, then tolerate the create race by retrying PutSecretValue.
		_, createErr := client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String(value),
		})
		if createErr == nil {
			return nil
		}
		var exists *types.ResourceExistsException
		if !errors.As(createErr, &exists) {
			return fmt.Errorf("%w: %v", errSecretStore, createErr)
		}
		if _, err = client.PutSecretValue(ctx, input); err != nil {
			return fmt.Errorf("%w: %v", errSecretStore, err)
		}
	}
	return nil
}

func (s *awsSecretsManagerStore) Delete(ctx context.Context, backend, secretRef string) error {
	if backend != "aws-secrets-manager" {
		return fmt.Errorf("%w: backend is %q, expected aws-secrets-manager", errSecretStore, backend)
	}
	region, secretName, err := parseAWSSecretRef(secretRef)
	if err != nil {
		return err
	}
	client, err := s.clientFor(region)
	if err != nil {
		return err
	}
	input := &secretsmanager.DeleteSecretInput{
		SecretId: aws.String(secretName),
	}
	_, err = client.DeleteSecret(ctx, input)
	if err != nil {
		var resourceNotFound *types.ResourceNotFoundException
		if errors.As(err, &resourceNotFound) {
			// Already deleted, which is fine for idempotency
			return nil
		}
		return fmt.Errorf("%w: %v", errSecretStore, err)
	}
	return nil
}

func (s *awsSecretsManagerStore) Validate(ctx context.Context, backend, secretRef string) error {
	// Validate by attempting to get the secret - if it exists and is readable, it's valid
	_, err := s.Get(ctx, backend, secretRef)
	if errors.Is(err, errSecretNotFound) {
		return errSecretNotFound
	}
	return err
}
