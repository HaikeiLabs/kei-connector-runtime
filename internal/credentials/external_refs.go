package credentials

// External credential refs (HAI-1000). A connector whose credential_ref is a
// secret the customer keeps in their own secret manager is never delivered by
// Kei. Instead the catalog lists those refs, and each sync checks that each
// ref exists in the runtime's configured secret store. A ref that exists is
// recorded in the connector reference index as an external entry, which the
// heartbeat reports as a connector activation and the daemon releases on a
// governed call. Resolution only validates: it never reads, logs, or returns
// a secret value.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
)

// externalCredentialRefsPath is the catalog list of external credential refs
// for the runtime token's installation.
const externalCredentialRefsPath = "/api/v1/runtime/external-credential-refs"

// maxExternalRefPages bounds pagination so a misbehaving catalog cannot loop
// the sync forever.
const maxExternalRefPages = 1000

// ExternalCredentialRef is one external credential_ref the catalog lists.
type ExternalCredentialRef struct {
	ConnectorID   string `json:"connector_id"`
	Field         string `json:"field"`
	CredentialRef string `json:"credential_ref"`
	Status        string `json:"status"`
	SecretRef     string `json:"secret_ref,omitempty"`
	SecretBackend string `json:"secret_backend,omitempty"`
}

type externalCredentialRefsPage struct {
	Refs          []ExternalCredentialRef `json:"external_credential_refs"`
	NextPageToken string                  `json:"next_page_token"`
}

type externalRefsClient struct {
	baseURL string
	client  *http.Client
}

func newExternalRefsClient(baseURL string, timeout time.Duration) *externalRefsClient {
	return &externalRefsClient{baseURL: strings.TrimRight(baseURL, "/"), client: &http.Client{Timeout: timeout}}
}

// external404Once logs the older-catalog 404 once per process.
var external404Once sync.Once

// ListExternalCredentialRefs returns every external credential ref, following
// next_page_token until it is empty. listed is false when the catalog does not
// serve the route (404 from an older catalog), which means no refs.
func (c *externalRefsClient) ListExternalCredentialRefs(ctx context.Context, token string) (refs []ExternalCredentialRef, listed bool, err error) {
	pageToken := ""
	for page := 0; page < maxExternalRefPages; page++ {
		endpoint := c.baseURL + externalCredentialRefsPath
		if pageToken != "" {
			endpoint += "?page_token=" + url.QueryEscape(pageToken)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, false, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		resp, err := c.client.Do(req)
		if err != nil {
			return nil, false, fmt.Errorf("list external credential refs request failed: %w", err)
		}
		if resp.StatusCode == http.StatusNotFound && page == 0 {
			resp.Body.Close()
			external404Once.Do(func() {
				slog.Debug("catalog does not serve external credential refs; treating as none")
			})
			return nil, false, nil
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, false, fmt.Errorf("list external credential refs returned status %d", resp.StatusCode)
		}
		var body externalCredentialRefsPage
		err = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if err != nil {
			return nil, false, fmt.Errorf("decode external credential refs: %w", err)
		}
		refs = append(refs, body.Refs...)
		if body.NextPageToken == "" {
			return refs, true, nil
		}
		if body.NextPageToken == pageToken {
			return nil, false, fmt.Errorf("list external credential refs repeated a page token")
		}
		pageToken = body.NextPageToken
	}
	return nil, false, fmt.Errorf("list external credential refs exceeded %d pages", maxExternalRefPages)
}

// UnresolvedReason is a coarse, closed reason an external ref did not resolve.
type UnresolvedReason string

const (
	ReasonNotFound         UnresolvedReason = "not_found"
	ReasonPermissionDenied UnresolvedReason = "permission_denied"
	ReasonNoBackend        UnresolvedReason = "no_backend"
	ReasonUnqualifiedName  UnresolvedReason = "unqualified_name"
	ReasonBackendError     UnresolvedReason = "backend_error"
)

// UnresolvedExternalRef names an unresolved connector and why.
type UnresolvedExternalRef struct {
	ConnectorID string           `json:"connector_id"`
	Reason      UnresolvedReason `json:"reason"`
}

// ExternalRefsOutput is the redacted result of one external-ref resolution.
// It names connectors only, never a ref or a value.
type ExternalRefsOutput struct {
	// Listed is false when the catalog does not serve the route; the index is
	// then left as it was.
	Listed     bool     `json:"listed"`
	Resolved   []string `json:"resolved_connector_ids,omitempty"`
	Unresolved []string `json:"unresolved_connector_ids,omitempty"`
	// UnresolvedRefs gives each unresolved connector a coarse reason.
	UnresolvedRefs []UnresolvedExternalRef `json:"unresolved,omitempty"`
	// Removed counts external index entries removed as stale.
	Removed int `json:"removed,omitempty"`
}

// ResolveExternalRefs lists the catalog's external credential refs and
// reconciles the external entries of the connector reference index with what
// the configured secret store (cfg.SecretsBackend) can find: a ref that exists
// is written as an external entry; a ref that does not, and any external
// entry the catalog no longer lists, is removed. Entries Kei delivered are
// never touched.
func ResolveExternalRefs(ctx context.Context, cfg Config, store secrets.Store) (*ExternalRefsOutput, error) {
	refs, listed, err := newExternalRefsClient(cfg.ControlPlaneURL, cfg.Timeout).ListExternalCredentialRefs(ctx, cfg.RuntimeToken)
	if err != nil {
		return nil, err
	}
	out := &ExternalRefsOutput{Listed: listed}
	if !listed {
		return out, nil
	}
	indexPath := connectorIndexPath(cfg)
	resolved := map[string]resolvedExternalRef{} // by index key
	resolvedIDs := map[string]bool{}
	// unresolvedReasons keeps the first reason seen per connector, in the
	// catalog's order.
	unresolvedReasons := map[string]UnresolvedReason{}
	warnedVaultURL := false
	for _, ref := range refs {
		if !warnedVaultURL && ref.SecretRef == "" && needsAzureVaultURL(strings.TrimSpace(cfg.SecretsBackend), ref.CredentialRef) {
			// One warning per sync, naming the variable and never a ref.
			warnedVaultURL = true
			fmt.Fprintf(warningWriter(cfg), "warning: external credential refs are bare Azure Key Vault names; set %s to resolve them\n", secrets.AzureVaultURLEnvVar)
		}
		entry, reason := resolveExternalRef(ctx, cfg, store, ref)
		if reason != "" {
			if _, err := uuid.Parse(ref.ConnectorID); err == nil {
				if _, seen := unresolvedReasons[ref.ConnectorID]; !seen {
					unresolvedReasons[ref.ConnectorID] = reason
				}
			}
			continue
		}
		resolved[connectorReferenceKey(entry.ConnectorID, entry.Field)] = resolvedExternalRef{entry: entry, credentialRef: ref.CredentialRef}
		resolvedIDs[entry.ConnectorID] = true
	}
	for _, r := range resolved {
		if err := WriteExternalConnectorReference(indexPath, r.entry, r.credentialRef); err != nil {
			return nil, err
		}
	}
	removed, err := RemoveExternalConnectorReferences(indexPath, func(entry ConnectorReference) bool {
		_, keep := resolved[connectorReferenceKey(entry.ConnectorID, entry.Field)]
		return !keep
	})
	if err != nil {
		return nil, fmt.Errorf("remove stale external credential references failed")
	}
	out.Removed = removed
	out.Resolved = sortedIDs(resolvedIDs)
	for id := range resolvedIDs {
		delete(unresolvedReasons, id)
	}
	unresolvedIDs := make(map[string]bool, len(unresolvedReasons))
	for id := range unresolvedReasons {
		unresolvedIDs[id] = true
	}
	out.Unresolved = sortedIDs(unresolvedIDs)
	for _, id := range out.Unresolved {
		out.UnresolvedRefs = append(out.UnresolvedRefs, UnresolvedExternalRef{ConnectorID: id, Reason: unresolvedReasons[id]})
	}
	return out, nil
}

// resolveExternalRef checks that one listed ref exists in the configured
// store. It only validates the ref; the value is never read into this
// process's output. It returns the index entry and an empty reason when the
// ref resolves, otherwise a coarse reason that never carries the ref.
func resolveExternalRef(ctx context.Context, cfg Config, store secrets.Store, ref ExternalCredentialRef) (ConnectorReference, UnresolvedReason) {
	backend := strings.TrimSpace(cfg.SecretsBackend)
	if backend == "" || store == nil {
		return ConnectorReference{}, ReasonNoBackend
	}
	if _, err := uuid.Parse(ref.ConnectorID); err != nil || !connectorSecretField.MatchString(ref.Field) {
		// Malformed catalog data: no closer reason fits.
		return ConnectorReference{}, ReasonBackendError
	}
	secretRef, reason := externalStoreRef(backend, ref)
	if reason != "" {
		return ConnectorReference{}, reason
	}
	entry := ConnectorReference{ConnectorID: ref.ConnectorID, Field: ref.Field, SecretBackend: backend, SecretRef: secretRef, External: true}
	if validateConnectorReference(entry) != nil {
		return ConnectorReference{}, ReasonUnqualifiedName
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := store.Validate(checkCtx, backend, secretRef); err != nil {
		return ConnectorReference{}, unresolvedReasonFor(err)
	}
	return entry, ""
}

// externalStoreRef returns the store reference for a listed ref in the
// configured backend. A catalog that knows the org/workspace credential store
// sends secret_ref already qualified (HAI-1023); it is used as is, and one
// for another backend is no_backend before any store call. An older catalog
// omits it, and the bare credential_ref is qualified locally
// (ExternalSecretRef).
func externalStoreRef(backend string, ref ExternalCredentialRef) (string, UnresolvedReason) {
	if secretRef := strings.TrimSpace(ref.SecretRef); secretRef != "" {
		if ref.SecretBackend != "" && ref.SecretBackend != backend {
			return "", ReasonNoBackend
		}
		if strings.HasPrefix(secretRef, keiManagedRefPrefix) {
			return "", ReasonUnqualifiedName
		}
		if secrets.ValidateRef(backend, secretRef) != nil {
			if refNamesAnotherBackend(backend, secretRef) {
				return "", ReasonNoBackend
			}
			return "", ReasonUnqualifiedName
		}
		return secretRef, ""
	}
	secretRef, ok := ExternalSecretRef(backend, ref.CredentialRef)
	if !ok {
		if refNamesAnotherBackend(backend, ref.CredentialRef) {
			return "", ReasonNoBackend
		}
		return "", ReasonUnqualifiedName
	}
	return secretRef, ""
}

// unresolvedReasonFor maps a store Validate error to a reason. Only the
// sentinel is inspected; the error text is never used.
func unresolvedReasonFor(err error) UnresolvedReason {
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		return ReasonNotFound
	case errors.Is(err, secrets.ErrPermissionDenied):
		return ReasonPermissionDenied
	default:
		return ReasonBackendError
	}
}

// refNamesAnotherBackend reports whether ref is a well-formed reference for a
// built-in backend other than the configured one: the ref needs a backend
// this runtime does not run.
func refNamesAnotherBackend(backend, ref string) bool {
	for _, name := range secrets.DefaultBackendRegistry().Names() {
		if name != backend && secrets.ValidateRef(name, ref) == nil {
			return true
		}
	}
	return false
}

// resolvedExternalRef is an index entry and the catalog's bare
// credential_ref it was resolved from.
type resolvedExternalRef struct {
	entry         ConnectorReference
	credentialRef string
}

func warningWriter(cfg Config) io.Writer {
	if cfg.Warnings != nil {
		return cfg.Warnings
	}
	return os.Stderr
}

func sortedIDs(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
