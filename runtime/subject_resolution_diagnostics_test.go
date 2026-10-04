package runtime

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestWritePolicyStateDenialLogsOnlySubjectDiagnostic(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure *SubjectResolutionFailure
		want    string
	}{
		{"transport", &SubjectResolutionFailure{Category: "transport"}, "category=transport"},
		{"status", &SubjectResolutionFailure{Category: "http_status", HTTPStatus: 503}, "category=http_status http_status=503"},
		{"decode", &SubjectResolutionFailure{Category: "decode"}, "category=decode"},
		{"invalid", &SubjectResolutionFailure{Category: "invalid_response"}, "category=invalid_response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			sensitive := "provider-user-secret tenant-secret installation-secret token-secret"
			if got := WritePolicyStateDenial(&stdout, &stderr, "subject_resolution_unavailable", errors.Join(tc.failure, errors.New(sensitive))); got != 1 {
				t.Fatalf("exit=%d", got)
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("diagnostic %q lacks %q", stderr.String(), tc.want)
			}
			if strings.Contains(stderr.String(), sensitive) {
				t.Fatalf("diagnostic leaked sensitive data: %q", stderr.String())
			}
			if !strings.Contains(stdout.String(), `"reason_code":"subject_resolution_unavailable"`) {
				t.Fatalf("user-facing denial changed: %s", stdout.String())
			}
		})
	}
}
