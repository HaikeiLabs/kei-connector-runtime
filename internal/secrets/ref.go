package secrets

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets/gcp"
)

// Reference validation for customer-managed secret references.
//
// A reference identifies *where* a secret lives in a backend. It must never
// carry the secret value itself. These checks run before any backend I/O so a
// malformed or inline-material reference is rejected without a round trip.
//
// Every error returned here is deliberately generic and never echoes the
// reference back: a reference that is actually secret material must not be
// repeated into logs, audit records, or API responses.
var (
	ErrRefEmpty     = errors.New("secret_ref is required")
	ErrRefTooLong   = errors.New("secret_ref exceeds maximum length")
	ErrRefMaterial  = errors.New("secret_ref must be an opaque reference, not secret material")
	ErrRefUnknown   = errors.New("unsupported secret_backend")
	ErrRefMalformed = errors.New("secret_ref is malformed for its backend")
)

const maxRefLen = 1024

// secretRefBackends mirrors the control-plane backend allowlist so the runtime
// rejects a backend it cannot resolve before it is ever used.
var secretRefBackends = map[string]bool{
	"azure-key-vault":     true,
	"aws-secrets-manager": true,
	"gcp-secret-manager":  true,
	"mounted":             true,
	"vault":               true,
	"custom":              true,
}

// knownSecretPrefixes are unambiguous token fingerprints. A reference that
// starts with one of these is a secret value, not a location.
var knownSecretPrefixes = []string{
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
	"xoxb-", "xoxp-", "xoxa-", "xapp-",
	"sk_live_", "sk_test_", "pk_live_", "pk_test_", "sk-",
	"AKIA", "ASIA", "AIza",
	"-----BEGIN",
}

// jwtShape matches a compact JWT (three base64url segments, "eyJ" header).
var jwtShape = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

// urlWithEmbeddedCreds matches a URL that carries inline user:password
// credentials, e.g. "postgres://user:hunter2@host/db".
var urlWithEmbeddedCreds = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://[^/@\s]+:[^/@\s]+@`)

// ValidateRef reports whether ref is a safe, well-formed reference for
// backend. It never includes ref in the returned error.
func ValidateRef(backend, ref string) error {
	if ref == "" {
		return ErrRefEmpty
	}
	if len(ref) > maxRefLen {
		return ErrRefTooLong
	}
	if !secretRefBackends[backend] {
		return fmt.Errorf("%w: %s", ErrRefUnknown, backend)
	}
	if looksLikeSecretMaterial(ref) {
		return ErrRefMaterial
	}
	return validateSecretRefFormat(backend, ref)
}

// validateSecretRefFormat enforces the backend-specific reference grammar. The
// two built-in backends reuse their existing parsers; opaque backends accept a
// single token or path (the material checks above already reject URLs with
// embedded credentials and known token shapes).
func validateSecretRefFormat(backend, ref string) error {
	switch backend {
	case "azure-key-vault":
		if _, _, _, err := parseKeyVaultSecretRef(ref); err != nil {
			return fmt.Errorf("%w: %s", ErrRefMalformed, backend)
		}
		return nil
	case "aws-secrets-manager":
		if _, _, err := parseAWSSecretRef(ref); err != nil {
			return fmt.Errorf("%w: %s", ErrRefMalformed, backend)
		}
		return nil
	case "gcp-secret-manager":
		if _, _, err := gcp.ParseSecretRef(ref); err != nil {
			return fmt.Errorf("%w: %s", ErrRefMalformed, backend)
		}
		return nil
	default:
		if strings.ContainsAny(ref, "\r\n\t ") {
			return fmt.Errorf("%w: %s", ErrRefMalformed, backend)
		}
		return nil
	}
}

// looksLikeSecretMaterial heuristically detects a reference that is actually a
// secret value. It is intentionally conservative (precision over recall) so a
// legitimate reference is never mistaken for material.
func looksLikeSecretMaterial(ref string) bool {
	if strings.ContainsAny(ref, "\r\n\t ") {
		return true
	}
	for _, p := range knownSecretPrefixes {
		if strings.HasPrefix(ref, p) {
			return true
		}
	}
	if jwtShape.MatchString(ref) {
		return true
	}
	if urlWithEmbeddedCreds.MatchString(ref) {
		return true
	}
	return highEntropyToken(ref)
}

// highEntropyToken flags a single, long, separator-free token with the entropy
// profile of an encoded secret (base64/hex). A reference should be a structured
// path or id, not a 40+ character blob with no separators.
func highEntropyToken(ref string) bool {
	if len(ref) < 40 {
		return false
	}
	if strings.ContainsAny(ref, "/:.") {
		return false
	}
	return shannonEntropy(ref) >= 3.5
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[byte]float64, len(s))
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	total := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := count / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}
