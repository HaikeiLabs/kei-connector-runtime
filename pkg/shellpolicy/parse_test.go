package shellpolicy

import (
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	sixteen := strings.TrimSuffix(strings.Repeat("a && ", 16), " && ")
	seventeen := strings.TrimSuffix(strings.Repeat("a && ", 17), " && ")
	tests := []struct {
		name    string
		command string
		want    [][]string
		ok      bool
	}{
		{"simple", "git status --short", [][]string{{"git", "status", "--short"}}, true},
		{"double quoted word", `git commit -m "hello world"`, [][]string{{"git", "commit", "-m", "hello world"}}, true},
		{"escaped space", `printf '%s' a\ b`, [][]string{{"printf", "%s", "a b"}}, true},

		{"and", "cd x && go test", [][]string{{"cd", "x"}, {"go", "test"}}, true},
		{"or", "a || b", [][]string{{"a"}, {"b"}}, true},
		{"semicolon", "a; b", [][]string{{"a"}, {"b"}}, true},
		{"pipe", "cat f | head", [][]string{{"cat", "f"}, {"head"}}, true},
		{"operators without spaces", "a&&b||c;d|e", [][]string{{"a"}, {"b"}, {"c"}, {"d"}, {"e"}}, true},
		{"mixed", "a && b | c ; d", [][]string{{"a"}, {"b"}, {"c"}, {"d"}}, true},
		{"single-quoted operators stay literal", `echo 'a && b | c; d'`, [][]string{{"echo", "a && b | c; d"}}, true},
		{"double-quoted operators stay literal", `echo "a || b"`, [][]string{{"echo", "a || b"}}, true},
		{"escaped operator stays literal", `echo a\;b`, [][]string{{"echo", "a;b"}}, true},
		{"quoted redirect text stays literal", `echo "2>&1"`, [][]string{{"echo", "2>&1"}}, true},
		{"quoted slash dev null is a plain word", `echo '>/dev/null'`, [][]string{{"echo", ">/dev/null"}}, true},

		{"2>&1 separate", "go build ./... 2>&1", [][]string{{"go", "build", "./..."}}, true},
		{"2>&1 then pipe", "go build ./... 2>&1 | head -30", [][]string{{"go", "build", "./..."}, {"head", "-30"}}, true},
		{">/dev/null attached", "cmd >/dev/null", [][]string{{"cmd"}}, true},
		{"> /dev/null separate", "cmd > /dev/null", [][]string{{"cmd"}}, true},
		{"1>/dev/null attached", "cmd 1>/dev/null", [][]string{{"cmd"}}, true},
		{"1> /dev/null separate", "cmd 1> /dev/null", [][]string{{"cmd"}}, true},
		{"2>/dev/null attached", "cmd 2>/dev/null", [][]string{{"cmd"}}, true},
		{"2> /dev/null separate", "cmd 2> /dev/null", [][]string{{"cmd"}}, true},
		{"redirect before operator", "a 2>/dev/null && b", [][]string{{"a"}, {"b"}}, true},
		{"redirect then operator without spaces", "a 2>&1|b", [][]string{{"a"}, {"b"}}, true},
		{"redirect mid-argv", "cmd 2>&1 arg", [][]string{{"cmd", "arg"}}, true},

		{"stage cap 16 ok", sixteen, nil, true},
		{"stage cap 17 rejected", seventeen, nil, false},

		{"command substitution", "echo $(id)", nil, false},
		{"parameter expansion", "echo $HOME", nil, false},
		{"braced expansion", "echo ${HOME}", nil, false},
		{"expansion in double quotes", `echo "${HOME}"`, nil, false},
		{"backtick", "echo `id`", nil, false},
		{"backtick in double quotes", "echo \"`id`\"", nil, false},
		{"backslash in double quotes", `echo "backslash\\x"`, nil, false},
		{"redirect to file", "echo hi > out", nil, false},
		{"redirect to file attached", "echo hi >out", nil, false},
		{"append redirect", "echo hi >> out", nil, false},
		{"input redirect", "cat < in", nil, false},
		{"heredoc", "cat << EOF", nil, false},
		{"herestring", "cat <<< x", nil, false},
		{"stderr to file", "cmd 2>err", nil, false},
		{"2>&2", "cmd 2>&2", nil, false},
		{"1>&2", "cmd 1>&2", nil, false},
		{"&> combined", "cmd &>/dev/null", nil, false},
		{"/dev/nullx", "cmd >/dev/nullx", nil, false},
		{"/dev/null path traversal", "cmd >/dev/null/../x", nil, false},
		{"dev null prefixed word", "cmd >/dev/null.txt", nil, false},
		{"redirect with no target", "cmd >", nil, false},
		{"subshell", "(cd x && ls)", nil, false},
		{"brace group", "{ ls; }", nil, false},
		{"lone ampersand background", "sleep 1 &", nil, false},
		{"background then command", "sleep 1 & ls", nil, false},
		{"glob star", "ls *.go", nil, false},
		{"glob question", "ls a?.go", nil, false},
		{"glob bracket", "ls [ab]", nil, false},
		{"tilde", "ls ~", nil, false},
		{"history bang", "echo !!", nil, false},
		{"comment hash", "ls # hi", nil, false},
		{"newline", "git status\nwhoami", nil, false},
		{"carriage return", "git status\rwhoami", nil, false},
		{"tab is a control character", "a\t&&\tb", nil, false},
		{"nul byte", "git\x00status", nil, false},
		{"escaped newline", "echo a\\\nb", nil, false},
		{"invalid utf8", "echo \xff", nil, false},

		{"leading operator", "&& a", nil, false},
		{"trailing &&", "a &&", nil, false},
		{"trailing semicolon", "a;", nil, false},
		{"trailing pipe", "a |", nil, false},
		{"double operator", "a && && b", nil, false},
		{"double semicolon", "a;; b", nil, false},
		{"mixed double operator", "a ; | b", nil, false},
		{"redirect only stage", "a && 2>&1", nil, false},
		{"empty", "", nil, false},
		{"whitespace only", "  \t", nil, false},
		{"unterminated quote", "echo 'unterminated", nil, false},
		{"unterminated escape", `echo a\`, nil, false},
		{"over 4096 bytes", "echo " + strings.Repeat("a", 4092), nil, false},
		{"exactly 4096 bytes", "echo " + strings.Repeat("a", 4091), [][]string{{"echo", strings.Repeat("a", 4091)}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Parse(tt.command)
			if ok != tt.ok {
				t.Fatalf("Parse(%q) ok=%v; want %v (stages %#v)", tt.command, ok, tt.ok, got)
			}
			if tt.want == nil {
				if tt.ok && len(got) == 0 {
					t.Fatalf("Parse(%q) returned no stages", tt.command)
				}
				if !tt.ok && got != nil {
					t.Fatalf("Parse(%q) returned stages %#v with ok=false", tt.command, got)
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Parse(%q) = %#v; want %#v", tt.command, got, tt.want)
			}
		})
	}
}

func TestParseWithDiagnosticReturnsBoundedCategories(t *testing.T) {
	tests := []struct {
		input string
		want  DiagnosticCode
	}{
		{"echo $HOME", DiagnosticParameterExpansion},
		{"$(id)", DiagnosticCommandSubstitution},
		{"echo `id`", DiagnosticBacktickSubstitution},
		{"echo hi > file", DiagnosticUnsupportedRedirection},
		{"(echo hi)", DiagnosticUnsupportedGrouping},
		{"echo *.go", DiagnosticUnsupportedGlob},
		{"sleep 1 &", DiagnosticUnsupportedBackground},
		{"echo ~", DiagnosticUnsupportedTildeExpansion},
		{"echo !!", DiagnosticUnsupportedHistoryExpansion},
		{"echo # comment", DiagnosticUnsupportedShellComment},
		{"echo 'unfinished", DiagnosticMalformedQuoting},
		{"echo a\nb", DiagnosticControlCharacter},
		{"a &&", DiagnosticInvalidCommandStructure},
		{"", DiagnosticInvalidInput},
		{"echo " + strings.Repeat("a", MaxCommandBytes), DiagnosticInputTooLarge},
	}
	for _, tc := range tests {
		t.Run(string(tc.want), func(t *testing.T) {
			stages, got := ParseWithDiagnostic(tc.input)
			if got != tc.want || stages != nil {
				t.Fatalf("ParseWithDiagnostic(input) = %#v, %q; want nil, %q", stages, got, tc.want)
			}
			if strings.Contains(string(got), tc.input) {
				t.Fatalf("diagnostic echoed input: %q", got)
			}
		})
	}
	if stages, got := ParseWithDiagnostic("git status && whoami"); got != "" || len(stages) != 2 {
		t.Fatalf("supported command = %#v, %q; want two stages and no diagnostic", stages, got)
	}
}

func TestParseRejectsControlCharactersInsideQuotes(t *testing.T) {
	for _, command := range []string{"echo 'a\nb'", "echo \"a\nb\"", "echo 'a\x00b'", "echo \"a\rb\""} {
		if got, ok := Parse(command); ok {
			t.Fatalf("Parse(%q) = %#v, true; want rejected", command, got)
		}
	}
}
