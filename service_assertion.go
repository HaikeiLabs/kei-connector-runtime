package connectorruntime

// The CRM service assertion (connector execution contract, section 5, D3):
// an ES256 JWT the runtime signs with its own per-installation key. The key
// lives in the tenant secret manager; neither Kei nor the catalog sees it. The
// MarketingSite Worker trusts a list of installation public keys by kid.

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
)

// assertionKeyConfig names the installation signing key in the secret store.
type assertionKeyConfig struct {
	backend string
	ref     string
	kid     string
}

func assertionKeyConfigFromEnv() assertionKeyConfig {
	return assertionKeyConfig{
		backend: os.Getenv("KEI_SERVICE_ASSERTION_KEY_BACKEND"),
		ref:     os.Getenv("KEI_SERVICE_ASSERTION_KEY_REF"),
		kid:     os.Getenv("KEI_SERVICE_ASSERTION_KID"),
	}
}

// assertionKIDPattern is kei-rt-<installation_id>-<n>; the issuer is derived
// from the installation id it carries.
var assertionKIDPattern = regexp.MustCompile(`^kei-rt-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})-[1-9][0-9]{0,5}$`)

var errAssertionKeyUnavailable = errors.New("service assertion key unavailable")

type assertionSigner struct {
	key    *ecdsa.PrivateKey
	kid    string
	issuer string
}

// loadAssertionSigner reads and parses the installation key. Every failure is
// errAssertionKeyUnavailable; the reference and key material are never
// echoed.
func loadAssertionSigner(ctx context.Context, store SecretStore, cfg assertionKeyConfig) (*assertionSigner, error) {
	m := assertionKIDPattern.FindStringSubmatch(cfg.kid)
	if store == nil || cfg.backend == "" || cfg.ref == "" || m == nil {
		return nil, errAssertionKeyUnavailable
	}
	value, err := store.Get(ctx, cfg.backend, cfg.ref)
	if err != nil || value == nil {
		return nil, errAssertionKeyUnavailable
	}
	block, _ := pem.Decode([]byte(*value))
	if block == nil {
		return nil, errAssertionKeyUnavailable
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errAssertionKeyUnavailable
		}
		key, _ = parsed.(*ecdsa.PrivateKey)
	case "EC PRIVATE KEY":
		key, _ = x509.ParseECPrivateKey(block.Bytes)
	}
	if key == nil || key.Curve != elliptic.P256() {
		return nil, errAssertionKeyUnavailable
	}
	return &assertionSigner{key: key, kid: cfg.kid, issuer: "kei-runtime:" + m[1]}, nil
}

// sign returns a compact ES256 JWS over claims with the signer's kid.
func (s *assertionSigner) sign(claims map[string]any) (string, error) {
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
