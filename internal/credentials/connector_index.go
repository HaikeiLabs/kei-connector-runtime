package credentials

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	index := connectorReferenceIndex{Version: 1, Entries: map[string]ConnectorReference{}}
	if existing, readErr := readConnectorReferenceIndex(path); readErr == nil {
		index = existing
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	if index.Version != 1 || index.Entries == nil {
		return errors.New("credential index has an unsupported format")
	}
	index.Entries[connectorReferenceKey(entry.ConnectorID, entry.Field)] = entry
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
	if entry.ConnectorID != connectorID || entry.Field != field || !connectorSecretRefNamesField(entry.SecretRef, connectorID, field) {
		return ConnectorReference{}, ErrConnectorReferenceMismatch
	}
	if validateConnectorReference(entry) != nil {
		return ConnectorReference{}, errors.New("credential index entry is invalid")
	}
	return entry, nil
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
// after the secret was written to the tenant store and validated. Entries
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
