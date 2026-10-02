package harness

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCodexDiscoveryGolden(t *testing.T) {
	got, err := (CodexAdapter{}).DiscoverTools(context.Background(), Env{HomeDir: filepath.Join("testdata", "codex")})
	if err != nil {
		t.Fatal(err)
	}
	assertDiscoveryGolden(t, filepath.Join("testdata", "codex", "discovery.golden.json"), got)
}

func TestOpenCodeDiscoveryGolden(t *testing.T) {
	got, err := (OpenCodeAdapter{}).DiscoverTools(context.Background(), Env{HomeDir: filepath.Join("testdata", "opencode")})
	if err != nil {
		t.Fatal(err)
	}
	assertDiscoveryGolden(t, filepath.Join("testdata", "opencode", "discovery.golden.json"), got)
}

func assertDiscoveryGolden(t *testing.T, path string, got Discovery) {
	t.Helper()
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var gotValue, wantValue any
	if err = json.Unmarshal(encoded, &gotValue); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(golden, &wantValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("discovery differs from %s\n got: %s\nwant: %s", path, encoded, golden)
	}
}
