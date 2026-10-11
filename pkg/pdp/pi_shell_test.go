package pdp

import (
	"reflect"
	"testing"
)

func TestParseSimpleShellCommand(t *testing.T) {
	tests := []struct {
		command string
		want    []string
		ok      bool
	}{
		{"git status --short", []string{"git", "status", "--short"}, true},
		{`git commit -m "hello world"`, []string{"git", "commit", "-m", "hello world"}, true},
		{`printf '%s' a\ b`, []string{"printf", "%s", "a b"}, true},
		{"git status && whoami", nil, false},
		{"echo $HOME", nil, false},
		{`echo "${HOME}"`, nil, false},
		{`echo "backslash\\x"`, nil, false},
		{"cat file | head", nil, false},
		{"echo hi > out", nil, false},
		{"echo `id`", nil, false},
		{"git status\nwhoami", nil, false},
		{"echo 'unterminated", nil, false},
		{"  \t", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got, ok := parseSimpleShellCommand(tt.command)
			if ok != tt.ok || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseSimpleShellCommand(%q) = %#v, %v; want %#v, %v", tt.command, got, ok, tt.want, tt.ok)
			}
		})
	}
}
