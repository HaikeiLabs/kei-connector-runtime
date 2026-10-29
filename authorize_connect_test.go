package connectorruntime

import (
	"strings"
	"testing"
)

func TestRunAuthorizeAcceptsInvokingSubjectFlag(t *testing.T) {
	t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_test_token_1234567890")
	stderr := captureStderr(func() {
		if code := runAuthorize([]string{"--tool", "web_search", "--invoking-subject", "victim"}); code != 2 {
			t.Fatalf("exit = %d, want 2 (error: no decision)", code)
		}
	})
	if strings.Contains(stderr, "flag provided but not defined") {
		t.Fatalf("invoking-subject flag rejected: %s", stderr)
	}
}
