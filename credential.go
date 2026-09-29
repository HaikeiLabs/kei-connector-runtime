package connectorruntime

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// runCredential provides credential management commands including sync.
// The sync command processes pending credential deliveries from the control plane,
// writes them to the configured external backend (Azure Key Vault or AWS Secrets Manager),
// and acknowledges the result.
func runCredential(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "credential requires a subcommand: sync")
		return 1
	}
	switch args[0] {
	case "sync":
		return runCredentialSync(args[1:], os.Stdout, os.Stderr, configFromEnv())
	default:
		fmt.Fprintf(os.Stderr, "unknown credential command %q\n", args[0])
		return 1
	}
}

// CredentialSyncConfig holds configuration for the credential sync operation
type CredentialSyncConfig struct {
	ControlPlaneURL string
	RuntimeToken    string
	Timeout         time.Duration
}

// CredentialDelivery represents a pending credential delivery from the control plane
type CredentialDelivery struct {
	OperationID  string `json:"operation_id"`
	RecipientID  string `json:"recipient_id"`
	GenerationID string `json:"generation_id,omitempty"`
	// Generation is the monotonic model-profile generation for this delivery.
	// It is additive and optional: when the control plane does not populate it
	// (0), the stale-generation guard is a no-op.
	Generation     int    `json:"generation,omitempty"`
	SecretBackend  string `json:"secret_backend"`
	SecretRef      string `json:"secret_ref"`
	SealedPayload  string `json:"sealed_payload"`
	RecipientKeyID string `json:"recipient_key_id"`
	IdempotencyKey string `json:"idempotency_key"`
	// OperationKind, ConnectorID, and Field are additive (HAI-262). A
	// connector_secret delivery writes one connector's secret setup field; it
	// is written exactly like a model-profile key, to SecretRef.
	OperationKind string `json:"operation_kind,omitempty"`
	ConnectorID   string `json:"connector_id,omitempty"`
	Field         string `json:"field,omitempty"`
}

// OperationKindConnectorSecret is the delivery kind for a connector secret.
const OperationKindConnectorSecret = "connector_secret"

// connectorSecretField bounds a connector secret field name.
var connectorSecretField = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// connectorSecretRefNamesField reports whether ref is the location the
// control plane names for this connector's field in each backend:
// ".../connectors/<id>/<field>" (AWS), ".../<prefix>-connectors-<id>-<field
// with - for _>" (Azure), or ".../<prefix>-connectors-<id>-<field>" (GCP). A
// connector delivery for any other location, such as a model profile's
// secret, is refused before anything is written.
func connectorSecretRefNamesField(ref, connectorID, field string) bool {
	if _, err := uuid.Parse(connectorID); err != nil || !connectorSecretField.MatchString(field) {
		return false
	}
	for _, suffix := range []string{
		"/connectors/" + connectorID + "/" + field,
		"-connectors-" + connectorID + "-" + strings.ReplaceAll(field, "_", "-"),
		"-connectors-" + connectorID + "-" + field,
	} {
		if strings.HasSuffix(ref, suffix) {
			return true
		}
	}
	return false
}

// CredentialDeliveryClaimRequest is the request to claim a delivery
type CredentialDeliveryClaimRequest struct {
	RuntimeInstallationID string `json:"runtime_installation_id"`
}

// CredentialDeliveryClaimResponse is the response from claiming a delivery
type CredentialDeliveryClaimResponse struct {
	Delivery          *CredentialDelivery `json:"delivery,omitempty"`
	LeaseExpiresAt    time.Time           `json:"lease_expires_at,omitempty"`
	NoDeliveryPending bool                `json:"no_delivery_pending"`
	// ActiveGeneration is the highest generation currently active for the
	// delivery's profile, when the control plane reports it. It is additive and
	// optional; when absent (0) the stale-generation guard is a no-op.
	ActiveGeneration int `json:"active_generation,omitempty"`
}

// CredentialDeliveryAckRequest is the request to acknowledge a delivery result
type CredentialDeliveryAckRequest struct {
	OperationID    string `json:"operation_id"`
	RecipientID    string `json:"recipient_id"`
	Success        bool   `json:"success"`
	FailureReason  string `json:"failure_reason,omitempty"` // redacted
	BackendVersion int    `json:"backend_version"`
}

// FailureReason is the closed set of redacted failure classes a sync can
// report. Only these values are ever written to the control plane or emitted,
// so a failure can never carry a raw backend error, a reference, or secret
// material. The first three values are the pre-existing wire contract and must
// not change; the last two are additive.
type FailureReason string

const (
	FailureDecryption      FailureReason = "decryption_failed"
	FailureBackendWrite    FailureReason = "backend_write_failed"
	FailureValidation      FailureReason = "backend_validation_failed"
	FailureInvalidRef      FailureReason = "invalid_secret_ref"
	FailureStaleGeneration FailureReason = "stale_generation"
)

// ackBackendVersion is the best-effort backend version reported on success. The
// backend always advances its own version on Put; the control plane tracks the
// authoritative generation, so the proxy reports a fixed positive sentinel.
const ackBackendVersion = 1

// isStaleGeneration reports whether a delivery for generation gen should be
// rejected because a newer generation (active) is already known. Both values
// must be positive; a zero generation is treated as "unknown" and never stale,
// which keeps the guard backward compatible with deliveries that do not carry
// a generation. Cross-invocation ordering is enforced by the control-plane
// claim; this is a defensive proxy-side check.
func isStaleGeneration(gen, active int) bool {
	return gen > 0 && active > 0 && gen < active
}

// CredentialSyncOutput is the output of the sync command
type CredentialSyncOutput struct {
	Claimed     bool   `json:"claimed"`
	OperationID string `json:"operation_id,omitempty"`
	// OperationKind, ConnectorID, and Field identify a connector secret
	// delivery; they name the field, never its value.
	OperationKind string `json:"operation_kind,omitempty"`
	ConnectorID   string `json:"connector_id,omitempty"`
	Field         string `json:"field,omitempty"`
	Backend       string `json:"backend,omitempty"`
	SecretName    string `json:"secret_name,omitempty"`
	Success       bool   `json:"success"`
	Error         string `json:"error,omitempty"` // redacted error class only
	ProcessedAt   string `json:"processed_at"`
}

func runCredentialSync(args []string, stdout, stderr io.Writer, cfg Config) int {
	flags := flag.NewFlagSet("credential sync", flag.ContinueOnError)
	flags.SetOutput(stderr)
	timeout := flags.Duration("timeout", 30*time.Second, "control-plane request timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *timeout <= 0 {
		fmt.Fprintln(stderr, "credential sync accepts no positional arguments and requires a positive --timeout")
		return 2
	}

	// Validate runtime configuration
	if !cfg.IsRuntime() {
		fmt.Fprintln(stderr, "credential sync requires KEI_RUNTIME_TOKEN to be set")
		return 1
	}
	if cfg.RuntimeControlPlaneURL == "" {
		fmt.Fprintln(stderr, "credential sync requires KEI_RUNTIME_CONTROL_PLANE_URL to be set")
		return 1
	}
	if cfg.CredentialSyncKeyID == "" || cfg.CredentialSyncPrivateKey == "" {
		fmt.Fprintln(stderr, "credential sync requires KEI_CREDENTIAL_SYNC_KEY_ID and KEI_CREDENTIAL_SYNC_PRIVATE_KEY")
		return 1
	}

	// Create secret store (for backend operations)
	store, err := NewSecretStore()
	if err != nil {
		fmt.Fprintf(stderr, "credential sync failed: create secret store: %v\n", err)
		return 1
	}

	// Run the sync
	output, err := performCredentialSync(context.Background(), cfg, *timeout, store)
	if err != nil {
		fmt.Fprintf(stderr, "credential sync failed: %v\n", err)
		return 1
	}

	// Write output (never outputs plaintext credentials)
	if err := json.NewEncoder(stdout).Encode(output); err != nil {
		fmt.Fprintf(stderr, "credential sync failed: write output: %v\n", err)
		return 1
	}

	return 0
}

func performCredentialSync(ctx context.Context, cfg Config, timeout time.Duration, store SecretStore) (out *CredentialSyncOutput, err error) {
	client := NewCredentialDeliveryClient(cfg.RuntimeControlPlaneURL, timeout)

	// Step 1: Get runtime identity to know our installation ID
	runtimeClient := NewRuntimeClient(cfg.RuntimeControlPlaneURL, timeout)
	identity, err := runtimeClient.WhoAmI(ctx, cfg.RuntimeToken)
	if err != nil {
		return nil, fmt.Errorf("resolve runtime installation: %w", err)
	}
	runtimeInstallID := identity.ID

	// Step 2: Claim an eligible delivery
	claimReq := CredentialDeliveryClaimRequest{
		RuntimeInstallationID: runtimeInstallID,
	}

	claimResp, err := client.ClaimDelivery(ctx, cfg.RuntimeToken, claimReq)
	if err != nil {
		return nil, fmt.Errorf("claim delivery: %w", err)
	}

	// No pending delivery - this is fine, just return no-op
	if claimResp.NoDeliveryPending || claimResp.Delivery == nil {
		return &CredentialSyncOutput{
			Claimed:     false,
			Success:     true,
			ProcessedAt: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	delivery := claimResp.Delivery
	activeGeneration := claimResp.ActiveGeneration
	// Every outcome for a connector delivery names the connector field.
	defer func() {
		if out != nil && delivery.OperationKind == OperationKindConnectorSecret {
			out.OperationKind, out.ConnectorID, out.Field = delivery.OperationKind, delivery.ConnectorID, delivery.Field
		}
	}()

	// Step 3: Decrypt the sealed payload (in memory, never log plaintext)
	plaintext, err := decryptDeliveryPayload(delivery.SealedPayload, runtimeInstallID, delivery.RecipientKeyID, cfg.CredentialSyncKeyID, cfg.CredentialSyncPrivateKey)
	if err != nil {
		// Acknowledge failure with redacted error
		ackErr := client.AcknowledgeDelivery(ctx, cfg.RuntimeToken, CredentialDeliveryAckRequest{
			OperationID:    delivery.OperationID,
			RecipientID:    delivery.RecipientID,
			Success:        false,
			FailureReason:  string(FailureDecryption),
			BackendVersion: 0,
		})
		if ackErr != nil {
			// Log but don't fail - the lease will expire anyway
			fmt.Fprintf(os.Stderr, "warning: failed to acknowledge delivery failure: %v\n", ackErr)
		}
		return &CredentialSyncOutput{
			Claimed:     true,
			OperationID: delivery.OperationID,
			Success:     false,
			Error:       "decryption_error", // redacted
			ProcessedAt: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	// Step 4: Guard the reference and generation before any backend I/O. A
	// reference that is actually secret material, or a delivery older than the
	// active generation, is rejected without writing and without echoing the
	// untrusted reference into the output.
	invalidRef := ValidateSecretRef(delivery.SecretBackend, delivery.SecretRef) != nil
	if delivery.OperationKind == OperationKindConnectorSecret && !connectorSecretRefNamesField(delivery.SecretRef, delivery.ConnectorID, delivery.Field) {
		invalidRef = true
	}
	if invalidRef {
		_ = client.AcknowledgeDelivery(ctx, cfg.RuntimeToken, CredentialDeliveryAckRequest{
			OperationID:    delivery.OperationID,
			RecipientID:    delivery.RecipientID,
			Success:        false,
			FailureReason:  string(FailureInvalidRef),
			BackendVersion: 0,
		})
		return &CredentialSyncOutput{
			Claimed:     true,
			OperationID: delivery.OperationID,
			Backend:     delivery.SecretBackend,
			Success:     false,
			Error:       string(FailureInvalidRef),
			ProcessedAt: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}
	if isStaleGeneration(delivery.Generation, activeGeneration) {
		_ = client.AcknowledgeDelivery(ctx, cfg.RuntimeToken, CredentialDeliveryAckRequest{
			OperationID:    delivery.OperationID,
			RecipientID:    delivery.RecipientID,
			Success:        false,
			FailureReason:  string(FailureStaleGeneration),
			BackendVersion: 0,
		})
		return &CredentialSyncOutput{
			Claimed:     true,
			OperationID: delivery.OperationID,
			Backend:     delivery.SecretBackend,
			Success:     false,
			Error:       string(FailureStaleGeneration),
			ProcessedAt: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	// Step 5: Write to the canonical generation-specific backend reference.
	err = store.Put(ctx, delivery.SecretBackend, delivery.SecretRef, plaintext)
	if err != nil {
		// Acknowledge failure with redacted error
		_ = client.AcknowledgeDelivery(ctx, cfg.RuntimeToken, CredentialDeliveryAckRequest{
			OperationID:    delivery.OperationID,
			RecipientID:    delivery.RecipientID,
			Success:        false,
			FailureReason:  string(FailureBackendWrite),
			BackendVersion: 0,
		})
		return &CredentialSyncOutput{
			Claimed:     true,
			OperationID: delivery.OperationID,
			Backend:     delivery.SecretBackend,
			SecretName:  delivery.SecretRef,
			Success:     false,
			Error:       "backend_write_error", // redacted
			ProcessedAt: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	// Step 6: Validate the write by reading back
	if err := store.Validate(ctx, delivery.SecretBackend, delivery.SecretRef); err != nil {
		_ = client.AcknowledgeDelivery(ctx, cfg.RuntimeToken, CredentialDeliveryAckRequest{
			OperationID:    delivery.OperationID,
			RecipientID:    delivery.RecipientID,
			Success:        false,
			FailureReason:  string(FailureValidation),
			BackendVersion: 0,
		})
		return &CredentialSyncOutput{
			Claimed:     true,
			OperationID: delivery.OperationID,
			Backend:     delivery.SecretBackend,
			SecretName:  delivery.SecretRef,
			Success:     false,
			Error:       "validation_error", // redacted
			ProcessedAt: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	// Step 7: Acknowledge success
	err = client.AcknowledgeDelivery(ctx, cfg.RuntimeToken, CredentialDeliveryAckRequest{
		OperationID:    delivery.OperationID,
		RecipientID:    delivery.RecipientID,
		Success:        true,
		FailureReason:  "",
		BackendVersion: ackBackendVersion,
	})
	if err != nil {
		// Log but don't fail - the write succeeded, control plane will reconcile
		fmt.Fprintf(os.Stderr, "warning: failed to acknowledge delivery success: %v\n", err)
	}

	return &CredentialSyncOutput{
		Claimed:     true,
		OperationID: delivery.OperationID,
		Backend:     delivery.SecretBackend,
		SecretName:  delivery.SecretRef,
		Success:     true,
		ProcessedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// decryptDeliveryPayload authenticates and decrypts the KMP1 envelope emitted
// by cmd/web. Key material remains in memory for the duration of sync only.
func decryptDeliveryPayload(sealedPayload, runtimeInstallationID, recipientKeyID, configuredKeyID, encodedPrivateKey string) (string, error) {
	if recipientKeyID == "" || recipientKeyID != configuredKeyID {
		return "", fmt.Errorf("unknown credential sync key")
	}
	payload, err := base64.RawStdEncoding.DecodeString(sealedPayload)
	if err != nil {
		payload, err = base64.StdEncoding.DecodeString(sealedPayload)
	}
	if err != nil || len(payload) < 4+32+12+16 || string(payload[:4]) != "KMP1" {
		return "", fmt.Errorf("invalid credential delivery envelope")
	}
	privateBytes, err := base64.RawStdEncoding.DecodeString(encodedPrivateKey)
	if err != nil {
		privateBytes, err = base64.StdEncoding.DecodeString(encodedPrivateKey)
	}
	if err != nil || len(privateBytes) != 32 {
		return "", fmt.Errorf("invalid credential sync private key")
	}
	curve := ecdh.X25519()
	privateKey, err := curve.NewPrivateKey(privateBytes)
	if err != nil {
		return "", fmt.Errorf("invalid credential sync private key")
	}
	ephemeralKey, err := curve.NewPublicKey(payload[4:36])
	if err != nil {
		return "", fmt.Errorf("invalid credential delivery envelope")
	}
	shared, err := privateKey.ECDH(ephemeralKey)
	if err != nil {
		return "", fmt.Errorf("decrypt credential delivery")
	}
	key := sha256.Sum256(append([]byte("kei-model-profile-envelope-v1\x00"), shared...))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("decrypt credential delivery")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("decrypt credential delivery")
	}
	nonceEnd := 36 + gcm.NonceSize()
	plaintext, err := gcm.Open(nil, payload[36:nonceEnd], payload[nonceEnd:], []byte(runtimeInstallationID+"\x00"+recipientKeyID))
	if err != nil || len(plaintext) == 0 {
		return "", fmt.Errorf("credential delivery authentication failed")
	}
	return string(plaintext), nil
}

// CredentialDeliveryClient handles delivery operations with the control plane
type CredentialDeliveryClient interface {
	ClaimDelivery(ctx context.Context, token string, req CredentialDeliveryClaimRequest) (*CredentialDeliveryClaimResponse, error)
	AcknowledgeDelivery(ctx context.Context, token string, req CredentialDeliveryAckRequest) error
}

type credentialDeliveryClient struct {
	baseURL string
	client  *http.Client
}

// NewCredentialDeliveryClient creates a new credential delivery client
func NewCredentialDeliveryClient(baseURL string, timeout time.Duration) CredentialDeliveryClient {
	return &credentialDeliveryClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *credentialDeliveryClient) ClaimDelivery(ctx context.Context, token string, req CredentialDeliveryClaimRequest) (*CredentialDeliveryClaimResponse, error) {
	endpoint := c.baseURL + "/api/v1/runtime/credential-delivery/claim"
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("claim delivery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent {
		return &CredentialDeliveryClaimResponse{NoDeliveryPending: true}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("claim delivery returned status %d", resp.StatusCode)
	}

	var result CredentialDeliveryClaimResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

func (c *credentialDeliveryClient) AcknowledgeDelivery(ctx context.Context, token string, req CredentialDeliveryAckRequest) error {
	endpoint := c.baseURL + "/api/v1/runtime/credential-delivery/ack"
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("acknowledge delivery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("acknowledge delivery returned status %d", resp.StatusCode)
	}

	return nil
}
