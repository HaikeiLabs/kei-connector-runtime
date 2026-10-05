package connectorruntime

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

// HAI-346 option A: policy_set.connectors carries each connector's
// non-secret descriptor, so the daemon runs opaque_ref connectors through
// the tenant secret store and tells per_user from shared OAuth connections.
// secretCanary is the Notion connector's API token in the fake tenant secret
// store; like the session canaries, it may reach only the provider and the
// child process.

const (
	secretCanary  = "kei-canary-tenant-secret-91d2f0aa"
	notionBackend = "aws-secrets-manager"
	// notionConnectorID is a UUID, as the catalog emits: the credential-sync
	// index accepts only UUID connector ids.
	notionConnectorID = "00000000-0000-4000-8000-0000000000a1"
	notionSecretRef   = "aws-secrets-manager://us-east-1/connectors/" + notionConnectorID + "/api_token"
	sharedConnectorID = "conn-gmail-shared-0001"
)

func descriptor(id, provider string, capabilities []map[string]string, extra map[string]any) map[string]any {
	d := map[string]any{
		"id": id, "tenant_id": "org-fixture-0001", "workspace_id": "ws-fixture-0001", "name": id,
		"provider": provider, "status": "active", "credential_ref": "api_token", "scopes": []string{"read"},
		"resources": []string{}, "policy": map[string]any{}, "capabilities": capabilities, "created_by": "admin-0001",
		"created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z",
	}
	for k, v := range extra {
		d[k] = v
	}
	return d
}

func read(names ...string) []map[string]string {
	var out []map[string]string
	for _, n := range names {
		out = append(out, map[string]string{"name": n, "action": "read"})
	}
	return out
}

// withDescriptors gives github a per_user OAuth descriptor, adds an
// opaque_ref Notion connector and a shared-account gmail connector, and
// leaves linear and conn-notion-0001 without one (the session fallback).
func withDescriptors(doc map[string]any) {
	ps := doc["policy_set"].(map[string]any)
	for _, c := range ps["connectors"].([]any) {
		conn := c.(map[string]any)
		switch conn["id"] {
		case invokeConnector:
			conn["descriptor"] = descriptor(invokeConnector, "github", read("repository.read", "pull_request.read"),
				map[string]any{"credential_source": "oauth", "account_model": "per_user"})
		}
	}
	ps["connectors"] = append(ps["connectors"].([]any), map[string]any{
		"id": notionConnectorID, "provider": "notion",
		"capabilities": []any{map[string]any{"name": "page.read", "mutating": false}, map[string]any{"name": "credential", "mutating": false}},
		"descriptor": descriptor(notionConnectorID, "notion", read("page.read"),
			map[string]any{"credential_source": "opaque_ref", "credential_backend": notionBackend, "credential_secret_ref": notionSecretRef}),
	}, map[string]any{
		"id": sharedConnectorID, "provider": "gmail",
		"capabilities": []any{map[string]any{"name": "message.get", "mutating": false}},
		"descriptor": descriptor(sharedConnectorID, "gmail", read("message.get"),
			map[string]any{"credential_source": "oauth", "account_model": "shared", "subject": "connector:" + sharedConnectorID}),
	})
	policies := ps["policies"].([]any)
	template := policies[0].(map[string]any)
	add := func(id, dst string) {
		p := map[string]any{}
		for k, v := range template {
			p[k] = v
		}
		p["id"], p["name"], p["dst_pattern"] = id, id, dst
		policies = append(policies, p)
	}
	add("pol-gmail-get", "capability:message.get")
	add("pol-notion-api-token", "resource:kei://connectors/"+notionConnectorID+"/api_token")
	ps["policies"] = policies
	ps["tools"] = append(ps["tools"].([]any),
		map[string]any{"name": "gmail.message_get", "service": "gmail", "action": "gmail:read", "connector_id": sharedConnectorID, "capability": "message.get"},
		map[string]any{"name": "notion2.page_read", "service": "notion", "action": "notion:read", "connector_id": notionConnectorID, "capability": "page.read"},
		map[string]any{"name": "notion2.credential", "service": "notion", "action": "notion:credential", "connector_id": notionConnectorID, "capability": "credential"})
	doc["agent_connector_bindings"] = append(doc["agent_connector_bindings"].([]any),
		map[string]any{"agent_id": "agent-fixture-0001", "connector_id": sharedConnectorID, "capabilities": []string{"message.get"}},
		map[string]any{"agent_id": "agent-fixture-0001", "connector_id": notionConnectorID, "capabilities": []string{"page.read", "credential"}})
}

func TestDescriptorOpaqueRefConnectorRunsWithTenantSecret(t *testing.T) {
	var logs bytes.Buffer
	prevLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prevLog) })

	rig := newInvokeRig(t, withDescriptors)
	rig.secrets.values[notionBackend+"|"+notionSecretRef] = secretCanary
	rig.startSession(t)

	out, resp := rig.invoke(t, notionConnectorID, "page.read", "pages/"+notionPageID)
	if out.Decision != "allow" || out.Provider != "notion" || !strings.Contains(string(out.Result), `"Roadmap"`) {
		t.Fatalf("invoke = %s", resp.dump)
	}
	rig.mu.Lock()
	notionAuth := append([]string(nil), rig.notionAuth...)
	rig.mu.Unlock()
	if len(notionAuth) != 1 || notionAuth[0] != "Bearer "+secretCanary {
		t.Fatalf("Notion did not get the tenant secret: %d calls", len(notionAuth))
	}
	if i11, _ := rig.counts(); len(i11) != 1 {
		t.Fatalf("I11 calls = %v; an opaque_ref connector must not touch I11", i11)
	}
	for name, content := range map[string]string{"response": resp.dump, "log": logs.String(), "audit spool": readSpool(t, rig.cfg.AuditPath)} {
		for _, canary := range []string{secretCanary, credentialCanary, subjectCanary} {
			if strings.Contains(content, canary) {
				t.Errorf("%s leaked %s:\n%s", name, canary, content)
			}
		}
	}

	// The secret missing from the store denies before the provider.
	delete(rig.secrets.values, notionBackend+"|"+notionSecretRef)
	if out, resp := rig.invoke(t, notionConnectorID, "page.read", "pages/"+notionPageID); out.ReasonCode != "credential_unavailable" {
		t.Fatalf("missing secret: %s", resp.dump)
	}
}

func TestDescriptorOAuthAccountModels(t *testing.T) {
	rig := newInvokeRig(t, withDescriptors)
	rig.startSession(t)

	// per_user: the session's own connection, as before.
	if out, resp := rig.invoke(t, invokeConnector, "repository.read", "repos/acme/kei"); out.Decision != "allow" {
		t.Fatalf("per_user = %s", resp.dump)
	}
	// shared: not the session's connection; denied before any credential.
	if out, resp := rig.invoke(t, sharedConnectorID, "message.get", "messages/m-1"); out.ReasonCode != "credential_source_not_supported" {
		t.Fatalf("shared = %s", resp.dump)
	}
	// No descriptor (linear): the session fallback still applies.
	if out, resp := rig.invoke(t, "conn-linear-0001", "team.read", "teams/eng"); out.ReasonCode != "connector_not_connected" {
		t.Fatalf("no descriptor = %s", resp.dump)
	}
	if _, github := rig.counts(); len(github) != 1 {
		t.Fatalf("GitHub calls = %d, want 1", len(github))
	}
}

func TestDescriptorMustMatchTheBundle(t *testing.T) {
	for name, field := range map[string]map[string]any{
		"other workspace": {"workspace_id": "ws-other-0001"},
		"other org":       {"tenant_id": "org-other-0001"},
		"other provider":  {"provider": "linear"},
		"other connector": {"id": "conn-other-0001"},
	} {
		t.Run(name, func(t *testing.T) {
			rig := newInvokeRig(t, withDescriptors, func(doc map[string]any) {
				for _, c := range doc["policy_set"].(map[string]any)["connectors"].([]any) {
					if conn := c.(map[string]any); conn["id"] == invokeConnector {
						for k, v := range field {
							conn["descriptor"].(map[string]any)[k] = v
						}
					}
				}
			})
			rig.startSession(t)
			if out, resp := rig.invoke(t, invokeConnector, "repository.read", "repos/acme/kei"); out.ReasonCode != "descriptor_invalid" {
				t.Fatalf("got %s", resp.dump)
			}
			if _, github := rig.counts(); len(github) != 0 {
				t.Fatal("provider called with a mismatched descriptor")
			}
		})
	}
}

func TestCommandRunResolvesOpaqueRefFromDescriptor(t *testing.T) {
	rig := newInvokeRig(t, withDescriptors)
	rig.secrets.values[notionBackend+"|"+notionSecretRef] = secretCanary
	index := filepath.Join(rig.cfg.RuntimeStateDir, "connector-credentials.json")
	if err := credentials.WriteConnectorReference(index, credentials.ConnectorReference{
		ConnectorID: notionConnectorID, Field: "api_token", SecretBackend: notionBackend, SecretRef: notionSecretRef, Generation: 1,
	}); err != nil {
		t.Fatal(err)
	}
	rig.startSession(t)
	ref := "kei://connectors/" + notionConnectorID + "/api_token"
	code, stdout, stderr := runProxyRunCLI(t, rig.socket, map[string]string{"GH_TOKEN": ref, "KEI_RUN_HELPER_EXIT": "0"}, "--", helperBinary(t))
	if code != 0 || !strings.Contains(stdout, "token-sha256="+sha256Hex(secretCanary)) {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "raw=[REDACTED]") || strings.Contains(stdout+stderr, secretCanary) {
		t.Fatalf("tenant secret not redacted:\nstdout %s\nstderr %s", stdout, stderr)
	}
	if i11, _ := rig.counts(); len(i11) != 1 {
		t.Fatalf("I11 calls = %v", i11)
	}

	// A delivered secret that does not match the descriptor is refused.
	if err := credentials.WriteConnectorReference(index, credentials.ConnectorReference{
		ConnectorID: notionConnectorID, Field: "api_token", SecretBackend: notionBackend,
		SecretRef: "aws-secrets-manager://eu-west-1/connectors/" + notionConnectorID + "/api_token", Generation: 2,
	}); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runProxyRunCLI(t, rig.socket, map[string]string{"GH_TOKEN": ref}, "--", helperBinary(t))
	if code != 1 || strings.Contains(stdout, "token-sha256") || !strings.Contains(stderr, "unresolved_reference") {
		t.Fatalf("mismatched delivery: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
}

func TestBundleDescriptorSchema(t *testing.T) {
	activate := func(mutate func(doc map[string]any)) error {
		store, err := policybundle.OpenStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		_, err = store.Activate(connectorTestBundle(t, withDescriptors, mutate), "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", time.Now().UTC())
		return err
	}
	githubDescriptor := func(doc map[string]any) map[string]any {
		for _, c := range doc["policy_set"].(map[string]any)["connectors"].([]any) {
			if conn := c.(map[string]any); conn["id"] == invokeConnector {
				return conn["descriptor"].(map[string]any)
			}
		}
		t.Fatal("no github connector")
		return nil
	}
	if err := activate(func(map[string]any) {}); err != nil {
		t.Fatalf("bundle with descriptors rejected: %v", err)
	}
	for _, key := range []string{"access_token", "refresh_token", "secret", "credential", "oauth"} {
		if err := activate(func(doc map[string]any) { githubDescriptor(doc)[key] = "x" }); err == nil {
			t.Errorf("descriptor with %q accepted", key)
		}
	}
	if err := activate(func(doc map[string]any) { delete(githubDescriptor(doc), "tenant_id") }); err == nil {
		t.Error("descriptor without tenant_id accepted")
	}
	// The connector entry itself stays closed.
	if err := activate(func(doc map[string]any) {
		doc["policy_set"].(map[string]any)["connectors"].([]any)[0].(map[string]any)["config"] = map[string]any{}
	}); err == nil {
		t.Error("unknown connector field accepted")
	}
}
