package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

func TestLoadRegistry(t *testing.T) {
	path := writeTempFile(t, "tools.yaml", `
tools:
  github.list_pages: github
  github.create_pr: github
  notion.query: notion
  web_search: ""
`)
	reg, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}

	tests := []struct {
		tool    string
		service string
	}{
		{"github.list_pages", "github"},
		{"github.create_pr", "github"},
		{"notion.query", "notion"},
		{"web_search", ""},
		{"unknown.tool", ""},
	}
	for _, tt := range tests {
		if got := reg.Service(tt.tool); got != tt.service {
			t.Errorf("Service(%q) = %q, want %q", tt.tool, got, tt.service)
		}
	}
}

func TestLoadRegistryMissing(t *testing.T) {
	if _, err := LoadRegistry(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing registry, got nil")
	}
}

func TestLoadRegistryInvalidYAML(t *testing.T) {
	path := writeTempFile(t, "tools.yaml", "tools: [not-a-map\n")
	if _, err := LoadRegistry(path); err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}
