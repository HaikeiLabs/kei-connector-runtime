package connectorruntime

import (
	"strings"
	"testing"
)

func TestPrintVersion(t *testing.T) {
	previous := version
	t.Cleanup(func() { version = previous })
	version = "test-v1.2.3"

	var output strings.Builder
	printVersion(&output)

	if got, want := output.String(), "kei-proxy test-v1.2.3\n"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}
