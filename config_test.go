package main

import (
	"testing"
)

func TestValidateRuntimeTokenFormatAcceptsValidToken(t *testing.T) {
	token := "kh_live_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	if err := ValidateRuntimeTokenFormat(token); err != nil {
		t.Fatalf("ValidateRuntimeTokenFormat(...) = %v", err)
	}
}

func TestValidateRuntimeTokenFormatRejectsEmpty(t *testing.T) {
	if err := ValidateRuntimeTokenFormat(""); err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestValidateRuntimeTokenFormatRejectsNonStandardPrefix(t *testing.T) {
	if err := ValidateRuntimeTokenFormat("runtime-token-1234567890abcde"); err == nil {
		t.Fatal("expected error for non-standard token prefix")
	}
}

func TestValidateRuntimeTokenFormatRejectsShortToken(t *testing.T) {
	if err := ValidateRuntimeTokenFormat("short"); err == nil {
		t.Fatal("expected error for token that is too short")
	}
}
