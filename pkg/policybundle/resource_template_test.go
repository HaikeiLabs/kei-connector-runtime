// Copyright 2026 Haikei Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policybundle

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMatchRenderedResource(t *testing.T) {
	cases := []struct {
		name     string
		template string
		rendered string
		want     bool
	}{
		{"exact template shape", "repos/{owner}/{repository}", "repos/acme/widgets", true},
		{"extra segment rejected", "repos/{owner}/{repository}", "repos/acme/widgets/extra", false},
		{"missing segment rejected", "repos/{owner}/{repository}", "repos/acme", false},
		{"encoded slash rejected", "repos/{owner}/{repository}", "repos/a%2Fb/widgets", false},
		{"lowercase encoded slash rejected", "repos/{owner}/{repository}", "repos/a%2fb/widgets", false},
		{"dotdot segment rejected", "repos/{owner}/{repository}", "repos/../x", false},
		{"dot segment rejected", "repos/{owner}/{repository}", "repos/./x", false},
		{"empty middle segment rejected", "repos/{owner}/{repository}", "repos//widgets", false},
		{"trailing empty segment rejected", "repos/{owner}/{repository}", "repos/acme/", false},
		{"leading empty segment rejected", "repos/{owner}/{repository}", "/repos/acme", false},
		{"scheme prefix template", "github:repo/{owner}/{repo}", "github:repo/acme/widgets", true},
		{"scheme prefix mismatch rejected", "github:repo/{owner}/{repo}", "gitlab:repo/acme/widgets", false},
		{"literal template exact", "repos/acme/widgets", "repos/acme/widgets", true},
		{"literal template mismatch", "repos/acme/widgets", "repos/acme/other", false},
		{"empty template matches nothing", "", "repos/acme", false},
		{"empty rendered matches nothing", "repos/{owner}", "", false},
		{"var must be non-empty", "repos/{owner}", "repos/", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchRenderedResource(tc.template, tc.rendered); got != tc.want {
				t.Errorf("MatchRenderedResource(%q, %q) = %v, want %v", tc.template, tc.rendered, got, tc.want)
			}
		})
	}
}

// v2TemplateBundle rewrites the connector binding of the standard v2 tool
// bundle with the given binding fields (resource_template, version).
func v2TemplateBundle(t *testing.T, now time.Time, checks []any, binding map[string]any) *Verified {
	t.Helper()
	v := v2ToolBundle(t, now, checks)
	var doc map[string]any
	if err := json.Unmarshal(v.PayloadBytes, &doc); err != nil {
		t.Fatal(err)
	}
	set := doc["policy_set"].(map[string]any)
	tools := set["tools"].([]any)
	tools[0].(map[string]any)["route"] = map[string]any{"connector_binding": binding}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var payload Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	return &Verified{Payload: payload, PayloadBytes: raw, Digest: "sha256:test-v2"}
}

func v2RenderedOps(resource, bindingVersion string) []Operation {
	ops := v2TestPlanOps()
	for i := range ops {
		ops[i].ProviderResource = resource
		ops[i].BindingVersion = bindingVersion
	}
	return ops
}

func TestAuthorizeOperation_ResourceOutOfTemplateDenies(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	subject := &SessionSubject{UserID: "user-alice", Source: "discord", ExternalID: "ext-alice", Status: SubjectLinked}
	checks := []any{v2Permit("p1", "pull_request.read"), v2Permit("p2", "check.read")}
	binding := map[string]any{"connector_id": "conn-a", "resource_template": "repos/{owner}/{repository}"}

	t.Run("in template allows", func(t *testing.T) {
		v := v2TemplateBundle(t, now, checks, binding)
		ops := v2RenderedOps("repos/acme/widgets", "")
		if d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, ops, now); d.Outcome != "allow" {
			t.Fatalf("decision = %+v", d)
		}
	})
	t.Run("out of template denies", func(t *testing.T) {
		v := v2TemplateBundle(t, now, checks, binding)
		for _, resource := range []string{"repos/acme/widgets/extra", "repos/acme", "repos/a%2Fb/widgets", "repos/../x"} {
			ops := v2RenderedOps(resource, "")
			d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, ops, now)
			if d.Outcome != "deny" || d.ReasonCode != "resource_out_of_template" {
				t.Fatalf("resource %q: decision = %+v, want deny resource_out_of_template", resource, d)
			}
		}
	})
}

func TestAuthorizeOperation_BindingVersionMismatchDenies(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	subject := &SessionSubject{UserID: "user-alice", Source: "discord", ExternalID: "ext-alice", Status: SubjectLinked}
	checks := []any{v2Permit("p1", "pull_request.read"), v2Permit("p2", "check.read")}
	binding := map[string]any{"connector_id": "conn-a", "version": "binding-v2", "resource_template": "repos/{owner}/{repository}"}

	t.Run("matching version allows", func(t *testing.T) {
		v := v2TemplateBundle(t, now, checks, binding)
		ops := v2RenderedOps("repos/acme/widgets", "binding-v2")
		if d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, ops, now); d.Outcome != "allow" {
			t.Fatalf("decision = %+v", d)
		}
	})
	t.Run("stale version denies", func(t *testing.T) {
		v := v2TemplateBundle(t, now, checks, binding)
		ops := v2RenderedOps("repos/acme/widgets", "binding-v1")
		d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, ops, now)
		if d.Outcome != "deny" || d.ReasonCode != "binding_stale" {
			t.Fatalf("decision = %+v, want deny binding_stale", d)
		}
	})
	t.Run("version named but absent from bundle denies", func(t *testing.T) {
		bindingNoVersion := map[string]any{"connector_id": "conn-a", "resource_template": "repos/{owner}/{repository}"}
		v := v2TemplateBundle(t, now, checks, bindingNoVersion)
		ops := v2RenderedOps("repos/acme/widgets", "binding-v1")
		d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, ops, now)
		if d.Outcome != "deny" || d.ReasonCode != "binding_stale" {
			t.Fatalf("decision = %+v, want deny binding_stale", d)
		}
	})
}

func TestAuthorizeOperation_LegacyBundleUnaffected(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	subject := &SessionSubject{UserID: "user-alice", Source: "discord", ExternalID: "ext-alice", Status: SubjectLinked}
	checks := []any{v2Permit("p1", "pull_request.read"), v2Permit("p2", "check.read")}

	// A bundle whose binding carries neither resource_template nor version
	// must behave exactly as before the fields existed: an old caller names
	// no binding version, so any rendered resource still evaluates the same
	// way.
	v := v2TemplateBundle(t, now, checks, map[string]any{"connector_id": "conn-a"})
	ops := v2RenderedOps("anything/else/at-all", "")
	if d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, ops, now); d.Outcome != "allow" {
		t.Fatalf("legacy bundle denied: %+v", d)
	}

	// Same with an empty rendered resource on every operation.
	ops = v2RenderedOps("", "")
	if d := v.EvaluateV2Plan("github.review_pr", "agent-a", subject, ops, now); d.Outcome != "allow" {
		t.Fatalf("legacy bundle denied: %+v", d)
	}
}
