package policybundle_test

import (
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
)

func TestValidate_ExternalCompileCheck(t *testing.T) {
	// This test verifies the public API compiles from an external package.
	// It sends a minimal v2 bundle; without a registered schema validator
	// ValidateV2 should fail with a clear error.
	input := []byte(`{"schema":"kei.policy-bundle/v2"}`)
	_, err := policybundle.Validate(input, "inst", "org", "ws", 0, time.Now())
	if err == nil {
		t.Fatal("Validate on a bare v2 bundle without schema validator must fail")
	}
	if !strings.Contains(err.Error(), "schema validator") {
		t.Fatalf("expected error mentioning schema validator, got: %v", err)
	}
}
