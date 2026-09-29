package crm

// The CRM service assertion (docs/connector-execution-contract.md, section 5,
// D3): an ES256 JWT the runtime signs with its own per-installation key. The
// key lives in the tenant secret manager; neither Kei nor the catalog sees it.
// The MarketingSite Worker trusts a list of installation public keys by kid.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"regexp"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/credentials"
)

// KeyConfig names the installation signing key in the secret store.
type KeyConfig struct {
	Backend string
	Ref     string
	KID     string
}

// KeyConfigFromEnv reads KEI_SERVICE_ASSERTION_KEY_BACKEND, _KEY_REF, and _KID.
func KeyConfigFromEnv() KeyConfig {
	return KeyConfig{
		Backend: os.Getenv("KEI_SERVICE_ASSERTION_KEY_BACKEND"),
		Ref:     os.Getenv("KEI_SERVICE_ASSERTION_KEY_REF"),
		KID:     os.Getenv("KEI_SERVICE_ASSERTION_KID"),
	}
}

// kidPattern is kei-rt-<installation_id>-<n>; the issuer is derived from the
// installation id it carries.
var kidPattern = regexp.MustCompile(`^kei-rt-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})-[1-9][0-9]{0,5}$`)

// ErrAssertionKey means the signing key is not configured or not usable
// (reason code assertion_key_unavailable).
var ErrAssertionKey = errors.New("service assertion key unavailable")

type signer struct {
	key    *ecdsa.PrivateKey
	kid    string
	issuer string
}

// loadSigner reads and parses the installation key. Every failure is
// ErrAssertionKey; the reference and key material are never echoed.
func loadSigner(ctx context.Context, store credentials.Store, cfg KeyConfig) (*signer, error) {
	m := kidPattern.FindStringSubmatch(cfg.KID)
	if store == nil || cfg.Backend == "" || cfg.Ref == "" || m == nil {
		return nil, ErrAssertionKey
	}
	lookupCtx, cancel := context.WithTimeout(ctx, credentials.DefaultTimeout)
	defer cancel()
	value, err := store.Get(lookupCtx, cfg.Backend, cfg.Ref)
	if err != nil || value == nil {
		return nil, ErrAssertionKey
	}
	block, _ := pem.Decode([]byte(*value))
	if block == nil {
		return nil, ErrAssertionKey
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrAssertionKey
		}
		key, _ = parsed.(*ecdsa.PrivateKey)
	case "EC PRIVATE KEY":
		key, _ = x509.ParseECPrivateKey(block.Bytes)
	}
	if key == nil || key.Curve != elliptic.P256() {
		return nil, ErrAssertionKey
	}
	return &signer{key: key, kid: cfg.KID, issuer: "kei-runtime:" + m[1]}, nil
}

// sign returns a compact ES256 JWS over claims with the signer's kid.
func (s *signer) sign(claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": s.kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
