package credentials

// The external-ref sidecar (HAI-1023) records, per external index entry, the
// catalog's bare credential_ref the entry was resolved from. Verification then
// compares a bundle descriptor's bare credential_ref with it instead of
// re-qualifying that ref locally (which, for Azure, needs
// KEI_SECRETS_AZURE_VAULT_URL).
//
// It is a separate file because the connector reference index must stay
// readable by older kei-proxy releases, which decode it with
// DisallowUnknownFields: a new field in an index entry would make a rolled-back
// binary fail closed on every connector. Older binaries never open the
// sidecar. It holds references only, never a credential value.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// externalRefRecord binds a bare credential_ref to the store reference of the
// index entry it was resolved into. A record whose SecretRef no longer equals
// its index entry's is stale and ignored.
type externalRefRecord struct {
	CredentialRef string `json:"credential_ref"`
	SecretRef     string `json:"secret_ref"`
}

type externalRefSidecar struct {
	Version int                          `json:"version"`
	Entries map[string]externalRefRecord `json:"entries"`
}

// ExternalRefSidecarPath is the sidecar next to the connector reference index
// at indexPath.
func ExternalRefSidecarPath(indexPath string) string {
	return filepath.Join(filepath.Dir(indexPath), strings.TrimSuffix(filepath.Base(indexPath), ".json")+".external-refs.json")
}

// readExternalRefSidecar returns the sidecar's records. A missing, unsafe or
// malformed sidecar yields none, and verification falls back to qualifying the
// descriptor's ref locally (the pre-HAI-1023 behavior), which fails closed
// where that cannot be done.
func readExternalRefSidecar(indexPath string) map[string]externalRefRecord {
	path := ExternalRefSidecarPath(indexPath)
	if checkPrivateDirectory(filepath.Dir(path)) != nil {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var sidecar externalRefSidecar
	if json.Unmarshal(data, &sidecar) != nil || sidecar.Version != 1 {
		return nil
	}
	return sidecar.Entries
}

// ExternalReferenceNames reports whether external entry, read from the index
// at indexPath, is the one credential sync resolved for credentialRef, the
// credential_ref a bundle descriptor names.
func ExternalReferenceNames(indexPath string, entry ConnectorReference, credentialRef string) bool {
	return externalReferenceNames(readExternalRefSidecar(indexPath), entry, credentialRef)
}

// externalReferenceNames matches credentialRef against entry: by the bare
// credential_ref the sidecar recorded for this exact entry, or, as before
// HAI-1023, by qualifying credentialRef in the entry's backend
// (ExternalSecretRef).
func externalReferenceNames(sidecar map[string]externalRefRecord, entry ConnectorReference, credentialRef string) bool {
	if !entry.External || credentialRef == "" || strings.HasPrefix(credentialRef, keiManagedRefPrefix) {
		return false
	}
	if record, ok := sidecar[connectorReferenceKey(entry.ConnectorID, entry.Field)]; ok && record.CredentialRef != "" && record.SecretRef == entry.SecretRef {
		if credentialRef == record.CredentialRef || credentialRef == entry.SecretRef {
			return true
		}
	}
	canonical, ok := ExternalSecretRef(entry.SecretBackend, credentialRef)
	return ok && canonical == entry.SecretRef
}

// WriteExternalConnectorReference records external entry, resolved from the
// catalog's credentialRef, unless a Kei-delivered entry already holds that
// connector field (external resolution never replaces one). The index entry
// keeps the pre-HAI-1023 schema; credentialRef goes to the sidecar, written
// under the same lock.
func WriteExternalConnectorReference(path string, entry ConnectorReference, credentialRef string) error {
	if !entry.External || validateConnectorReference(entry) != nil || credentialRef == "" || strings.HasPrefix(credentialRef, keiManagedRefPrefix) {
		return errors.New("external connector credential reference is invalid")
	}
	key := connectorReferenceKey(entry.ConnectorID, entry.Field)
	err := withConnectorIndexLock(path, func() error {
		err := updateConnectorReferenceIndexLocked(path, func(index *connectorReferenceIndex) bool {
			if existing, ok := index.Entries[key]; ok && (!existing.External || existing == entry) {
				return false
			}
			index.Entries[key] = entry
			return true
		})
		if err != nil {
			return err
		}
		return reconcileExternalRefSidecarLocked(path, map[string]externalRefRecord{key: {CredentialRef: credentialRef, SecretRef: entry.SecretRef}})
	})
	if err != nil {
		return errors.New("persist external credential reference failed")
	}
	return nil
}

// reconcileExternalRefSidecarLocked applies upserts to the sidecar and drops
// every record that no longer names an external index entry with the same
// store reference. The caller holds the index lock. Nothing is written when
// nothing changes, so a runtime with no external refs never gets a sidecar.
func reconcileExternalRefSidecarLocked(indexPath string, upserts map[string]externalRefRecord) error {
	index, err := readConnectorReferenceIndex(indexPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	current := readExternalRefSidecar(indexPath)
	next := make(map[string]externalRefRecord, len(current)+len(upserts))
	for key, record := range current {
		next[key] = record
	}
	for key, record := range upserts {
		next[key] = record
	}
	changed := len(next) != len(current)
	for key, record := range next {
		entry, ok := index.Entries[key]
		if !ok || !entry.External || entry.SecretRef != record.SecretRef {
			delete(next, key)
			changed = true
			continue
		}
		if old, had := current[key]; !had || old != record {
			changed = true
		}
	}
	if !changed {
		return nil
	}
	path := ExternalRefSidecarPath(indexPath)
	if len(next) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("remove external credential reference sidecar failed")
		}
		return nil
	}
	data, err := json.Marshal(externalRefSidecar{Version: 1, Entries: next})
	if err != nil {
		return errors.New("encode external credential reference sidecar failed")
	}
	return writePrivateAtomic(path, data)
}
