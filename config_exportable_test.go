package connectorruntime

import (
	"slices"
	"testing"
)

func TestExportableServicePrincipalsFromEnv(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want []string
	}{
		{"", nil},
		{" , ,", nil},
		{"analytics-seed", []string{"analytics-seed"}},
		{" analytics-seed , kei-bug-intake,,", []string{"analytics-seed", "kei-bug-intake"}},
	} {
		t.Setenv("KEI_EXPORTABLE_SERVICE_PRINCIPALS", tc.env)
		if got := configFromEnv().ExportableServicePrincipals; !slices.Equal(got, tc.want) {
			t.Fatalf("env %q: got %q want %q", tc.env, got, tc.want)
		}
	}
}
