package connectorruntime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "kei-connector-runtime-test-state-")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("KEI_RUNTIME_STATE_DIR", filepath.Join(dir, "policy-state"))
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
