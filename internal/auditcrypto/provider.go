package auditcrypto

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
)

// Recipient represents a single age public key from the control plane.
type Recipient struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Kind      string `json:"kind"` // "customer" or "escrow"
}

type fetchResponse struct {
	Recipients  []Recipient `json:"recipients"`
	DigestKeyID string      `json:"digest_key_id"`
	DigestKey   string      `json:"digest_key"` // base64-encoded 32 bytes
	ExpiresAt   string      `json:"expires_at"` // RFC3339
}

type cachedData struct {
	recipients  []Recipient
	digestKey   []byte // raw 32 bytes, nil if absent
	digestKeyID string
	expiresAt   time.Time
}

// Provider fetches and caches audit encryption recipients + digest key from
// the control plane, and provides Digest and Encrypt operations.
// It is safe for concurrent use.
type Provider struct {
	mu            sync.Mutex
	baseURL       string
	token         string
	httpClient    *http.Client
	cached        *cachedData
	escrowEnabled bool
}

// NewProvider creates a Provider that fetches material from baseURL using
// the given runtime token for authentication.
func NewProvider(baseURL, token string) *Provider {
	return &Provider{
		baseURL:    strings.TrimRight(baseURL, "/"),
		token:      token,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// SetEscrowEnabled controls whether escrow-kind recipients are included in
// encryption (default off). This is plumbing only; escrow is opt-in.
func (p *Provider) SetEscrowEnabled(enabled bool) { p.escrowEnabled = enabled }

// Digest computes a keyed HMAC-SHA256 digest of canonicalJSON using the
// cached digest key. If no digest key is available (fetch failed or not
// yet retrieved), it falls back to plain SHA-256 (old behavior).
// The returned digest is prefixed with "hmac-sha256:" or "sha256:".
func (p *Provider) Digest(canonicalJSON []byte) (digest, keyID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = p.ensureFresh(ctx)

	p.mu.Lock()
	cached := p.cached
	p.mu.Unlock()

	if cached != nil && cached.digestKey != nil {
		mac := hmac.New(sha256.New, cached.digestKey)
		mac.Write(canonicalJSON)
		return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), cached.digestKeyID
	}

	sum := sha256.Sum256(canonicalJSON)
	return "sha256:" + hex.EncodeToString(sum[:]), ""
}

// Encrypt encrypts canonicalJSON to all active (customer + optionally escrow)
// recipients using age multi-recipient X25519 encryption. Returns the
// base64-encoded age-armored ciphertext and the list of recipient key IDs.
// If no recipients are available, both values are empty (digest-only mode).
func (p *Provider) Encrypt(canonicalJSON []byte) (ciphertext string, keyIDs []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = p.ensureFresh(ctx)

	p.mu.Lock()
	cached := p.cached
	p.mu.Unlock()

	if cached == nil {
		return "", nil
	}

	active := make([]Recipient, 0, len(cached.recipients))
	for _, r := range cached.recipients {
		if r.Kind == "customer" || (p.escrowEnabled && r.Kind == "escrow") {
			active = append(active, r)
		}
	}
	if len(active) == 0 {
		return "", nil
	}

	ageRecipients := make([]age.Recipient, len(active))
	keyIDs = make([]string, len(active))
	for i, r := range active {
		rec, err := age.ParseX25519Recipient(r.PublicKey)
		if err != nil {
			return "", nil
		}
		ageRecipients[i] = rec
		keyIDs[i] = r.KeyID
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, ageRecipients...)
	if err != nil {
		return "", nil
	}
	if _, err := w.Write(canonicalJSON); err != nil {
		return "", nil
	}
	if err := w.Close(); err != nil {
		return "", nil
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), keyIDs
}

// ensureFresh fetches new material from the control plane if the cache is
// empty or expired. On fetch failure, the existing cache (if any) is kept.
func (p *Provider) ensureFresh(ctx context.Context) error {
	p.mu.Lock()
	if p.cached != nil && time.Now().Before(p.cached.expiresAt) {
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()

	resp, err := p.fetch(ctx)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.cached = resp
	p.mu.Unlock()
	return nil
}

func (p *Provider) fetch(ctx context.Context) (*cachedData, error) {
	u := p.baseURL + "/api/v1/runtime/audit-encryption-recipients"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var fr fetchResponse
	if err := json.NewDecoder(resp.Body).Decode(&fr); err != nil {
		return nil, err
	}

	var expiresAt time.Time
	if fr.ExpiresAt != "" {
		expiresAt, _ = time.Parse(time.RFC3339, fr.ExpiresAt)
	}
	if expiresAt.IsZero() || expiresAt.Before(time.Now()) {
		expiresAt = time.Now().Add(5 * time.Minute)
	}

	var digestKey []byte
	if fr.DigestKey != "" {
		digestKey, _ = base64.StdEncoding.DecodeString(fr.DigestKey)
	}

	return &cachedData{
		recipients:  fr.Recipients,
		digestKey:   digestKey,
		digestKeyID: fr.DigestKeyID,
		expiresAt:   expiresAt,
	}, nil
}

// Decrypt decrypts a base64-encoded age-armored ciphertext using the given
// identity. It is exported for testing only.
func Decrypt(ciphertextB64 string, identity *age.X25519Identity) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	r, err := age.Decrypt(strings.NewReader(string(ciphertext)), identity)
	if err != nil {
		return nil, fmt.Errorf("age decrypt: %w", err)
	}
	return io.ReadAll(r)
}
