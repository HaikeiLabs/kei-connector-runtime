package credentials

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
	"github.com/google/uuid"
)

// ConnectorReference contains only the opaque location of a delivered
// connector secret. The index is private runtime metadata and never stores a
// credential value.
type ConnectorReference struct {
	ConnectorID   string `json:"connector_id"`
	Field         string `json:"field"`
	SecretBackend string `json:"secret_backend"`
	SecretRef     string `json:"secret_ref"`
	Generation    int    `json:"generation"`
	// External marks a reference to a secret the customer keeps in their own
	// secret manager (an external credential_ref, HAI-1000). Credential sync
	// writes it after checking the ref exists in the configured store; Kei
	// never delivered it, so the ref does not name the connector field.
	External bool `json:"external,omitempty"`
	// Do not add fields: an older kei-proxy decodes the index with
	// DisallowUnknownFields, so a new field breaks rollback. Keep new
	// per-entry metadata in a sidecar (external_ref_sidecar.go).
}

type connectorReferenceIndex struct {
	Version int                           `json:"version"`
	Entries map[string]ConnectorReference `json:"entries"`
}

var ErrConnectorReferenceNotFound = errors.New("connector credential reference not found")

// ErrConnectorReferenceMismatch reports an index entry whose secret reference
// names another connector or field than the one asked for.
var ErrConnectorReferenceMismatch = errors.New("connector credential reference names another connector or field")

// WriteConnectorReference atomically inserts or replaces one connector field
// lookup in a 0600 index. The index holds no credential values.
func WriteConnectorReference(path string, entry ConnectorReference) error {
	if err := validateConnectorReference(entry); err != nil {
		return err
	}
	return updateConnectorReferenceIndex(path, func(index *connectorReferenceIndex) bool {
		index.Entries[connectorReferenceKey(entry.ConnectorID, entry.Field)] = entry
		return true
	})
}

// RemoveExternalConnectorReferences deletes the external entries for which
// remove returns true and reports how many it deleted. Entries Kei delivered
// are never removed. A missing index has nothing to remove.
func RemoveExternalConnectorReferences(path string, remove func(ConnectorReference) bool) (int, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	removed := 0
	err := withConnectorIndexLock(path, func() error {
		err := updateConnectorReferenceIndexLocked(path, func(index *connectorReferenceIndex) bool {
			for key, entry := range index.Entries {
				if entry.External && remove(entry) {
					delete(index.Entries, key)
					removed++
				}
			}
			return removed > 0
		})
		if err != nil {
			return err
		}
		// Drop sidecar records of removed entries.
		return reconcileExternalRefSidecarLocked(path, nil)
	})
	return removed, err
}

// updateConnectorReferenceIndex applies update to the index under an
// exclusive lock and atomically rewrites it when update reports a change.
func updateConnectorReferenceIndex(path string, update func(*connectorReferenceIndex) bool) error {
	return withConnectorIndexLock(path, func() error { return updateConnectorReferenceIndexLocked(path, update) })
}

// withConnectorIndexLock runs fn holding the index's exclusive lock. The
// external-ref sidecar is written under the same lock.
func withConnectorIndexLock(path string, fn func() error) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("create credential index directory failed")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return errors.New("secure credential index directory failed")
	}
	if err := checkPrivateDirectory(dir); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return errors.New("open credential index lock failed")
	}
	defer lock.Close()
	if err := lock.Chmod(0600); err != nil {
		return errors.New("secure credential index lock failed")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return errors.New("lock credential index failed")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return fn()
}

// updateConnectorReferenceIndexLocked is updateConnectorReferenceIndex for a
// caller that holds the index lock.
func updateConnectorReferenceIndexLocked(path string, update func(*connectorReferenceIndex) bool) error {
	index := connectorReferenceIndex{Version: 1, Entries: map[string]ConnectorReference{}}
	if existing, readErr := readConnectorReferenceIndex(path); readErr == nil {
		index = existing
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	if index.Version != 1 || index.Entries == nil {
		return errors.New("credential index has an unsupported format")
	}
	if !update(&index) {
		return nil
	}
	data, err := json.Marshal(index)
	if err != nil {
		return errors.New("encode credential index failed")
	}
	return writePrivateAtomic(path, data)
}

// ReadConnectorReference returns the exact delivery location for connector
// id and field. It fails closed on missing, malformed, linked, or permissive
// index files.
func ReadConnectorReference(path, connectorID, field string) (ConnectorReference, error) {
	if _, err := uuid.Parse(connectorID); err != nil || !connectorSecretField.MatchString(field) {
		return ConnectorReference{}, ErrConnectorReferenceNotFound
	}
	index, err := readConnectorReferenceIndex(path)
	if err != nil {
		return ConnectorReference{}, err
	}
	entry, ok := index.Entries[connectorReferenceKey(connectorID, field)]
	if !ok {
		return ConnectorReference{}, ErrConnectorReferenceNotFound
	}
	if entry.ConnectorID != connectorID || entry.Field != field || (!entry.External && !connectorSecretRefNamesField(entry.SecretRef, connectorID, field)) {
		return ConnectorReference{}, ErrConnectorReferenceMismatch
	}
	if validateConnectorReference(entry) != nil {
		return ConnectorReference{}, errors.New("credential index entry is invalid")
	}
	return entry, nil
}

// ReadExternalConnectorReference returns the external entry credential sync
// resolved for connectorID at credentialRef, the external credential_ref a
// bundle descriptor names, matched by ExternalReferenceNames. An entry for
// that ref under another backend is
// ErrConnectorReferenceMismatch; no resolved entry is
// ErrConnectorReferenceNotFound.
func ReadExternalConnectorReference(path, connectorID, backend, credentialRef string) (ConnectorReference, error) {
	if _, err := uuid.Parse(connectorID); err != nil || credentialRef == "" || strings.HasPrefix(credentialRef, keiManagedRefPrefix) {
		return ConnectorReference{}, ErrConnectorReferenceNotFound
	}
	index, err := readConnectorReferenceIndex(path)
	if err != nil {
		return ConnectorReference{}, err
	}
	sidecar := readExternalRefSidecar(path)
	keys := make([]string, 0, len(index.Entries))
	for key := range index.Entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	mismatch := false
	for _, key := range keys {
		entry := index.Entries[key]
		if !entry.External || entry.ConnectorID != connectorID || connectorReferenceKey(entry.ConnectorID, entry.Field) != key {
			continue
		}
		if !externalReferenceNames(sidecar, entry, credentialRef) {
			continue
		}
		if entry.SecretBackend != backend {
			mismatch = true
			continue
		}
		if validateConnectorReference(entry) != nil {
			return ConnectorReference{}, errors.New("credential index entry is invalid")
		}
		return entry, nil
	}
	if mismatch {
		return ConnectorReference{}, ErrConnectorReferenceMismatch
	}
	return ConnectorReference{}, ErrConnectorReferenceNotFound
}

// ExternalSecretRef returns the store reference for an external credential_ref
// in backend. The catalog sends a bare name (contract.ValidateCredentialRef
// rejects a URL scheme), which the runtime qualifies from its one configured
// backend:
//   - aws-secrets-manager: <name> becomes aws-secrets-manager:///<name> in the
//     runtime's default region;
//   - azure-key-vault: <name> becomes <KEI_SECRETS_AZURE_VAULT_URL>/secrets/<name>,
//     and is unresolvable while that variable is unset;
//   - gcp-secret-manager: projects/<p>/secrets/<s> is already a store ref.
//
// A ref the backend already accepts is used as is. Anything else reports false.
func ExternalSecretRef(backend, ref string) (string, bool) {
	if ref == "" || strings.HasPrefix(ref, keiManagedRefPrefix) {
		return "", false
	}
	if secrets.ValidateRef(backend, ref) == nil {
		return ref, true
	}
	if strings.Contains(ref, "://") {
		return "", false
	}
	var canonical string
	switch backend {
	case "aws-secrets-manager":
		canonical = "aws-secrets-manager:///" + strings.TrimPrefix(ref, "/")
	case "azure-key-vault":
		vault := secrets.ConfiguredAzureVaultURL()
		if vault == "" || !azureSecretName.MatchString(ref) {
			return "", false
		}
		canonical = vault + "/secrets/" + ref
	default:
		return "", false
	}
	if secrets.ValidateRef(backend, canonical) != nil {
		return "", false
	}
	return canonical, true
}

// azureSecretName is a Key Vault secret name: 1-127 letters, digits and dashes.
var azureSecretName = regexp.MustCompile(`^[0-9A-Za-z-]{1,127}$`)

// needsAzureVaultURL reports whether ref is a bare Azure secret name that only
// KEI_SECRETS_AZURE_VAULT_URL can qualify, and that variable is unusable.
func needsAzureVaultURL(backend, ref string) bool {
	return backend == "azure-key-vault" && secrets.ConfiguredAzureVaultURL() == "" && azureSecretName.MatchString(ref)
}

// ConnectorIndexPath is the connector reference index kei-proxy credential
// sync writes in stateDir.
func ConnectorIndexPath(stateDir string) string {
	return filepath.Join(stateDir, "connector-credentials.json")
}

// keiManagedRefPrefix marks a kei-managed credential reference
// (kei://connectors/<id>/<field>). Connectors resolved through such a
// reference are activated by their delivery acknowledgment, never by the
// heartbeat.
const keiManagedRefPrefix = "kei://connectors/"

// ResolvedExternalConnectorIDs returns the distinct connector ids whose
// external credential_ref this runtime has actually resolved through
// credential sync: the connector reference index records a delivery only
// after the secret was written to the tenant store and validated, and an
// External entry only after the customer's ref was found in the configured
// store (HAI-1000). Entries
// whose resolved reference is kei-managed are excluded, so a reported id
// always names an external credential_ref. A missing index means nothing has
// resolved yet and yields no ids and no error; an unreadable or unsafe index
// fails closed with an error. Ids are sorted for stable reporting.
func ResolvedExternalConnectorIDs(path string) ([]string, error) {
	if _, err := os.Lstat(filepath.Dir(path)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
	}
	index, err := readConnectorReferenceIndex(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	seen := make(map[string]bool, len(index.Entries))
	ids := make([]string, 0, len(index.Entries))
	for _, entry := range index.Entries {
		if entry.SecretRef == "" || strings.HasPrefix(entry.SecretRef, keiManagedRefPrefix) || seen[entry.ConnectorID] {
			continue
		}
		if _, err := uuid.Parse(entry.ConnectorID); err != nil {
			continue
		}
		seen[entry.ConnectorID] = true
		ids = append(ids, entry.ConnectorID)
	}
	sort.Strings(ids)
	return ids, nil
}

func connectorReferenceKey(connectorID, field string) string { return connectorID + "/" + field }

func validateConnectorReference(entry ConnectorReference) error {
	if _, err := uuid.Parse(entry.ConnectorID); err != nil || !connectorSecretField.MatchString(entry.Field) || entry.SecretBackend == "" || secrets.ValidateRef(entry.SecretBackend, entry.SecretRef) != nil || entry.Generation < 0 {
		return errors.New("connector credential reference is invalid")
	}
	if entry.External {
		if strings.HasPrefix(entry.SecretRef, keiManagedRefPrefix) {
			return errors.New("external connector credential reference is kei-managed")
		}
		return nil
	}
	if !connectorSecretRefNamesField(entry.SecretRef, entry.ConnectorID, entry.Field) {
		return errors.New("connector credential reference does not match its field")
	}
	return nil
}

func readConnectorReferenceIndex(path string) (connectorReferenceIndex, error) {
	if err := checkPrivateDirectory(filepath.Dir(path)); err != nil {
		return connectorReferenceIndex{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return connectorReferenceIndex{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return connectorReferenceIndex{}, errors.New("credential index file permissions or type are unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return connectorReferenceIndex{}, err
	}
	var index connectorReferenceIndex
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&index); err != nil {
		return connectorReferenceIndex{}, errors.New("credential index is malformed")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return connectorReferenceIndex{}, errors.New("credential index has trailing data")
	}
	if index.Version != 1 || index.Entries == nil {
		return connectorReferenceIndex{}, errors.New("credential index has an unsupported format")
	}
	return index, nil
}

func checkPrivateDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return errors.New("credential index directory is unavailable")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("credential index directory permissions or type are unsafe")
	}
	return nil
}

func writePrivateAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".connector-index-*")
	if err != nil {
		return errors.New("create credential index file failed")
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return errors.New("secure credential index file failed")
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return errors.New("write credential index failed")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return errors.New("sync credential index failed")
	}
	if err := tmp.Close(); err != nil {
		return errors.New("close credential index failed")
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return errors.New("replace credential index failed")
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open credential index directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("sync credential index directory failed")
	}
	return nil
}
