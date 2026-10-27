package connectorruntime

import "testing"

// API-012: authorize exits 0 permit, 1 deny, 2 error. An error is anything
// that stopped the call before a decision was made.
func TestRunAuthorizeExitsTwoWhenNoDecisionWasMade(t *testing.T) {
	t.Run("missing tool", func(t *testing.T) {
		t.Setenv("KEI_RUNTIME_TOKEN", "kh_live_runtime_test_token_1234567890")
		if code := runAuthorize(nil); code != 2 {
			t.Fatalf("exit = %d, want 2", code)
		}
	})
	t.Run("missing runtime token", func(t *testing.T) {
		t.Setenv("KEI_RUNTIME_TOKEN", "")
		if code := runAuthorize([]string{"--tool", "web_search"}); code != 2 {
			t.Fatalf("exit = %d, want 2", code)
		}
	})
	t.Run("unknown flag", func(t *testing.T) {
		if code := runAuthorize([]string{"--no-such-flag"}); code != 2 {
			t.Fatalf("exit = %d, want 2", code)
		}
	})
}
