package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
)

// HAI-1022: every unresolved external ref carries a coarse reason, and
// neither the reason nor anything else sync emits ever names the ref.

const (
	extConnectorC = "00000000-0000-4000-8000-00000000c003"
	extConnectorD = "00000000-0000-4000-8000-00000000d004"
	extConnectorE = "00000000-0000-4000-8000-00000000e005"
)

// errStore is a secrets.Store whose Validate returns a fixed error per ref.
// The errors deliberately echo the ref, the way a provider message can.
type errStore struct {
	errs map[string]error
}

func (s *errStore) Get(context.Context, string, string) (*string, error) {
	return nil, errors.New("errStore never reads")
}
func (s *errStore) Put(context.Context, string, string, string) error { return errors.New("read-only") }
func (s *errStore) Delete(context.Context, string, string) error      { return errors.New("read-only") }
func (s *errStore) Validate(_ context.Context, _ string, ref string) error {
	if err, ok := s.errs[ref]; ok {
		return err
	}
	return nil
}

func leakyNotFound(ref string) error {
	return fmt.Errorf("%w: ResourceNotFoundException: %s", secrets.ErrNotFound, ref)
}

func leakyPermissionDenied(ref string) error {
	return fmt.Errorf("%w: %w: AccessDeniedException on %s", secrets.ErrUnavailable, secrets.ErrPermissionDenied, ref)
}

func leakyBackendError(ref string) error {
	return fmt.Errorf("%w: throttled reading %s", secrets.ErrUnavailable, ref)
}

func oneRefCatalog(connectorID, ref string) *externalRefsCatalog {
	return &externalRefsCatalog{pages: map[string]externalCredentialRefsPage{
		"": {Refs: []ExternalCredentialRef{{ConnectorID: connectorID, Field: "api_key", CredentialRef: ref, Status: "pending"}}},
	}}
}

func TestResolveExternalRefsReportsAReasonPerUnresolvedConnector(t *testing.T) {
	cases := []struct {
		name    string
		backend string
		ref     string
		store   func(ref string) *errStore
		vault   string
		want    UnresolvedReason
	}{
		{
			name: "missing secret", backend: "aws-secrets-manager", ref: extRefA,
			store: func(ref string) *errStore { return &errStore{errs: map[string]error{ref: leakyNotFound(ref)}} },
			want:  ReasonNotFound,
		},
		{
			name: "permission denied", backend: "aws-secrets-manager", ref: extRefA,
			store: func(ref string) *errStore { return &errStore{errs: map[string]error{ref: leakyPermissionDenied(ref)}} },
			want:  ReasonPermissionDenied,
		},
		{
			name: "unset backend", backend: "", ref: extRefA,
			store: func(string) *errStore { return &errStore{} },
			want:  ReasonNoBackend,
		},
		{
			name: "ref for a backend this runtime does not run", backend: "azure-key-vault", ref: extRefA,
			store: func(string) *errStore { return &errStore{} },
			vault: azureVaultURL,
			want:  ReasonNoBackend,
		},
		{
			name: "bare Azure name without a vault URL", backend: "azure-key-vault", ref: azureBareName,
			store: func(string) *errStore { return &errStore{} },
			want:  ReasonUnqualifiedName,
		},
		{
			name: "any other backend failure", backend: "aws-secrets-manager", ref: extRefA,
			store: func(ref string) *errStore { return &errStore{errs: map[string]error{ref: leakyBackendError(ref)}} },
			want:  ReasonBackendError,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(secrets.AzureVaultURLEnvVar, tc.vault)
			cfg := externalConfig(t, oneRefCatalog(extConnectorA, tc.ref).server(t).URL)
			cfg.SecretsBackend = tc.backend
			cfg.Warnings = &bytes.Buffer{}
			out, err := ResolveExternalRefs(context.Background(), cfg, tc.store(tc.ref))
			if err != nil {
				t.Fatal(err)
			}
			want := []UnresolvedExternalRef{{ConnectorID: extConnectorA, Reason: tc.want}}
			if fmt.Sprint(out.UnresolvedRefs) != fmt.Sprint(want) {
				t.Fatalf("unresolved = %+v, want %+v", out.UnresolvedRefs, want)
			}
			// The ids list stays for compatibility.
			if len(out.Unresolved) != 1 || out.Unresolved[0] != extConnectorA {
				t.Fatalf("unresolved_connector_ids = %v", out.Unresolved)
			}
		})
	}
}

func TestExternalRefsOutputJSONKeepsIDsAndAddsReasons(t *testing.T) {
	cfg := externalConfig(t, oneRefCatalog(extConnectorA, extRefA).server(t).URL)
	out, err := ResolveExternalRefs(context.Background(), cfg, &errStore{errs: map[string]error{extRefA: leakyNotFound(extRefA)}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		IDs        []string `json:"unresolved_connector_ids"`
		Unresolved []struct {
			ConnectorID string `json:"connector_id"`
			Reason      string `json:"reason"`
		} `json:"unresolved"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.IDs) != 1 || got.IDs[0] != extConnectorA {
		t.Fatalf("unresolved_connector_ids = %v in %s", got.IDs, data)
	}
	if len(got.Unresolved) != 1 || got.Unresolved[0].ConnectorID != extConnectorA || got.Unresolved[0].Reason != "not_found" {
		t.Fatalf("unresolved = %+v in %s", got.Unresolved, data)
	}
}

func TestResolveExternalRefsResolvedConnectorHasNoReason(t *testing.T) {
	// One connector, two fields: one resolves, one does not. A connector that
	// resolves is not listed as unresolved, with or without a reason.
	catalog := &externalRefsCatalog{pages: map[string]externalCredentialRefsPage{
		"": {Refs: []ExternalCredentialRef{
			{ConnectorID: extConnectorA, Field: "api_key", CredentialRef: extRefA, Status: "pending"},
			{ConnectorID: extConnectorA, Field: "api_secret", CredentialRef: extRefB, Status: "pending"},
		}},
	}}
	cfg := externalConfig(t, catalog.server(t).URL)
	out, err := ResolveExternalRefs(context.Background(), cfg, &errStore{errs: map[string]error{extRefB: leakyNotFound(extRefB)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Unresolved) != 0 || len(out.UnresolvedRefs) != 0 || len(out.Resolved) != 1 {
		t.Fatalf("out = %+v", out)
	}
}

func TestResolveExternalRefsReasonsNeverNameTheRef(t *testing.T) {
	const awsBare = "customer/hr/payroll-api-key"
	refs := map[string]string{
		extConnectorA: extRefA,         // not_found
		extConnectorB: extRefB,         // permission_denied
		extConnectorC: awsBare,         // backend_error (qualified to aws-secrets-manager:///...)
		extConnectorD: "kei://foo/bar", // unqualified_name (not an external ref)
		extConnectorE: "aws-secrets-manager://us-east-1/customer/ops/other",
	}
	page := externalCredentialRefsPage{}
	for _, id := range []string{extConnectorA, extConnectorB, extConnectorC, extConnectorD, extConnectorE} {
		page.Refs = append(page.Refs, ExternalCredentialRef{ConnectorID: id, Field: "api_key", CredentialRef: refs[id], Status: "pending"})
	}
	catalog := &externalRefsCatalog{pages: map[string]externalCredentialRefsPage{"": page}}
	cfg := externalConfig(t, catalog.server(t).URL)
	warnings := &bytes.Buffer{}
	cfg.Warnings = warnings
	qualifiedBare := "aws-secrets-manager:///" + awsBare
	store := &errStore{errs: map[string]error{
		extRefA:             leakyNotFound(extRefA),
		extRefB:             leakyPermissionDenied(extRefB),
		qualifiedBare:       leakyBackendError(qualifiedBare),
		refs[extConnectorE]: leakyBackendError(refs[extConnectorE]),
	}}

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	var out *ExternalRefsOutput
	stderr := captureStderr(t, func() {
		var err error
		if out, err = ResolveExternalRefs(context.Background(), cfg, store); err != nil {
			t.Fatal(err)
		}
	})
	if len(out.UnresolvedRefs) != 5 {
		t.Fatalf("unresolved = %+v, want all five", out.UnresolvedRefs)
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	emitted := map[string]string{
		"output":   string(data),
		"stderr":   stderr,
		"warnings": warnings.String(),
		"logs":     logs.String(),
	}
	for where, text := range emitted {
		for _, ref := range []string{extRefA, extRefB, awsBare, "kei://foo/bar", refs[extConnectorE], "customer/"} {
			if strings.Contains(text, ref) {
				t.Fatalf("%s names a ref (%q): %s", where, ref, text)
			}
		}
	}
}
