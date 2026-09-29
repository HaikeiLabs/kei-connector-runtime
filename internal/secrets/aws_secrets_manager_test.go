package secrets

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestNewAWSSecretsManagerStoreUsesLocalEndpointOverride(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("KEI_AWS_SECRETS_MANAGER_ENDPOINT", "http://ministack:4566")

	store, err := NewAWSSecretsManagerStore()
	if err != nil {
		t.Fatalf("NewAWSSecretsManagerStore: %v", err)
	}
	awsStore, ok := store.(*awsSecretsManagerStore)
	if !ok {
		t.Fatalf("store type = %T, want *awsSecretsManagerStore", store)
	}
	if awsStore.base.BaseEndpoint == nil || *awsStore.base.BaseEndpoint != "http://ministack:4566" {
		t.Fatalf("base endpoint = %v, want http://ministack:4566", awsStore.base.BaseEndpoint)
	}
}

// TestNewAWSSecretsManagerStoreFromConfigIsInjectable exercises the
// workload-identity seam: an injected aws.Config (which in production carries
// the IRSA web-identity provider) is used to build the store, and region
// clients are derived from it rather than re-resolved from the environment.
// No real AWS call is made.
func TestNewAWSSecretsManagerStoreFromConfigIsInjectable(t *testing.T) {
	cfg := aws.Config{Region: "us-east-1"}
	store, err := NewAWSSecretsManagerStoreFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewAWSSecretsManagerStoreFromConfig: %v", err)
	}
	awsStore, ok := store.(*awsSecretsManagerStore)
	if !ok {
		t.Fatalf("store type = %T, want *awsSecretsManagerStore", store)
	}
	if awsStore.base.Region != "us-east-1" {
		t.Fatalf("base region = %q, want us-east-1", awsStore.base.Region)
	}
	// A region-less reference derives a client from the injected config.
	client, err := awsStore.clientFor("")
	if err != nil {
		t.Fatalf("clientFor(\"\"): %v", err)
	}
	if client == nil {
		t.Fatal("clientFor returned nil")
	}
	// A region override still derives from the injected config (same provider).
	if _, err := awsStore.clientFor("eu-west-1"); err != nil {
		t.Fatalf("clientFor(eu-west-1): %v", err)
	}
}
