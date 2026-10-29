package policybundle

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// HAI-622-F: no installation is on a v1 bundle any more, and the v1 evaluator
// is gone. A kei.policy-bundle/v1 bundle, whatever its evaluation order, is
// rejected as unsupported with an error that names the upgrade.
func TestValidateRejectsAV1BundleNamingTheUpgrade(t *testing.T) {
	now := time.Now().UTC()
	for name, order := range map[string]string{
		"array_order_first_match": "array_order_first_match",
		"deny_overrides":          "deny_overrides",
	} {
		t.Run(name, func(t *testing.T) {
			doc := `{"schema":"kei.policy-bundle/v1","bundle_id":"b","bundle_version":1,"policy_revision":1,"issuer":"kei-policy-catalog",` +
				`"audience":{"installation_id":"i","org_id":"o","workspace_id":"w"},` +
				`"issued_at":"` + now.Format(time.RFC3339) + `","not_after":"` + now.Add(time.Hour).Format(time.RFC3339) + `",` +
				`"refresh":{"poll_interval_seconds":60,"stale_after_seconds":300},"subject_resolution":{"mode":"bundle","max_cache_seconds":0},` +
				`"policy_set":{"schema":"kei.policy-set/v1","match_semantics":"kei.match/v1","evaluation":{"order":"` + order + `","default":"deny"},"groups":[],"agents":[],"tools":[],"policies":[],"connectors":[]},` +
				`"agent_connector_bindings":[],"identities":[]}`
			_, err := Validate([]byte(doc), "i", "o", "w", 0, now)
			if !errors.Is(err, ErrBundleUnsupported) {
				t.Fatalf("err = %v, want ErrBundleUnsupported", err)
			}
			if !strings.Contains(err.Error(), "kei.policy-bundle/v1") || !strings.Contains(err.Error(), "kei.policy-bundle/v2") || !strings.Contains(err.Error(), "upgrade") {
				t.Fatalf("err = %q, want it to name v1, v2 and the upgrade", err)
			}
		})
	}
}
