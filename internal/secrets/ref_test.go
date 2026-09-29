package secrets

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateSecretRefAcceptsBackendReferences(t *testing.T) {
	cases := []struct {
		backend string
		ref     string
	}{
		{"azure-key-vault", "https://demo.vault.azure.net/secrets/github-token"},
		{"azure-key-vault", "https://demo.vault.azure.net/secrets/github-token/v1"},
		{"aws-secrets-manager", "aws-secrets-manager://us-east-1/123456789012/github-token"},
		{"aws-secrets-manager", "aws-secrets-manager:///github-token"},
		{"vault", "secret/kei/github-oauth"},
		{"custom", "projects/my-proj/secrets/github-token"},
		{"gcp-secret-manager", "projects/my-proj/secrets/github-token/versions/1"},
	}
	for _, c := range cases {
		if err := ValidateRef(c.backend, c.ref); err != nil {
			t.Errorf("ValidateRef(%q, %q) = %v, want nil", c.backend, c.ref, err)
		}
	}
}

func TestValidateSecretRefRejectsInlineMaterial(t *testing.T) {
	// Each of these is a secret value, not a location.
	material := []string{
		"ghp_" + strings.Repeat("a", 36),
		"sk_live_" + strings.Repeat("b", 24),
		"AKIA" + strings.Repeat("C", 16),
		"xoxb-" + strings.Repeat("d", 24),
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJrZXkifQ." + strings.Repeat("e", 20),
		"-----BEGIN PRIVATE KEY-----" + strings.Repeat("f", 20),
		"postgres://user:hunter2@db.internal:5432/prod",
		"J7kQ9mX2vL4pR8wN3tY6uZ1aB5cD0eF7gH2iJ4kL6mN8pQ0rS", // high-entropy blob
		"vault\nsecret",
	}
	for _, ref := range material {
		err := ValidateRef("custom", ref)
		if err == nil {
			t.Errorf("ValidateRef accepted inline material (len=%d)", len(ref))
			continue
		}
		if !errors.Is(err, ErrRefMaterial) {
			t.Errorf("ValidateRef(len=%d) = %v, want ErrRefMaterial", len(ref), err)
		}
	}
}

func TestValidateSecretRefRejectsMalformedFormat(t *testing.T) {
	cases := []struct {
		backend string
		ref     string
	}{
		{"aws-secrets-manager", "https://example.com/secret"},
		{"aws-secrets-manager", "vault/kei/github-oauth"},
		{"azure-key-vault", "http://demo.vault.azure.net/secrets/token"},
		{"azure-key-vault", "aws-secrets-manager://us-east-1/123/github-token"},
	}
	for _, c := range cases {
		err := ValidateRef(c.backend, c.ref)
		if !errors.Is(err, ErrRefMalformed) {
			t.Errorf("ValidateRef(%q, %q) = %v, want ErrRefMalformed", c.backend, c.ref, err)
		}
	}
}

func TestValidateSecretRefRejectsEmptyTooLongUnknown(t *testing.T) {
	if err := ValidateRef("custom", ""); !errors.Is(err, ErrRefEmpty) {
		t.Errorf("empty = %v, want ErrRefEmpty", err)
	}
	if err := ValidateRef("custom", strings.Repeat("x", maxRefLen+1)); !errors.Is(err, ErrRefTooLong) {
		t.Errorf("too long = %v, want ErrRefTooLong", err)
	}
	if err := ValidateRef("not-a-backend", "secret/kei/x"); !errors.Is(err, ErrRefUnknown) {
		t.Errorf("unknown = %v, want ErrRefUnknown", err)
	}
}

// TestValidateSecretRefErrorNeverEchoesReference guards the redaction contract:
// a reference that is actually secret material must not be repeated in the
// returned error.
func TestValidateSecretRefErrorNeverEchoesReference(t *testing.T) {
	secret := "ghp_" + strings.Repeat("Z", 36)
	err := ValidateRef("custom", secret)
	if err == nil {
		t.Fatal("expected error for inline material")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error echoed the reference: %v", err)
	}

	weird := "https://example.com/" + strings.Repeat("Y", 50)
	if err := ValidateRef("aws-secrets-manager", weird); err != nil && strings.Contains(err.Error(), weird) {
		t.Fatalf("error echoed the reference: %v", err)
	}
}
