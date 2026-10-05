// Package credentials is the runtime's credential-delivery flow: claim one
// sealed delivery from the control plane, open it, guard its reference and
// generation, write it to the tenant secret store, and acknowledge a redacted
// result. It carries model-profile keys and connector secrets alike. The
// envelope primitives live in internal/crypto and the backends in
// internal/secrets; the kei-proxy CLI only wires this package up.
package credentials

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/crypto"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/statedir"
)

// Config is what one sync needs from the runtime environment.
type Config struct {
	ControlPlaneURL string
	RuntimeToken    string
	// KeyID and PrivateKey are the credential sync key the control plane seals
	// deliveries to (KEI_CREDENTIAL_SYNC_KEY_ID / _PRIVATE_KEY).
	KeyID      string
	PrivateKey string
	// Timeout bounds each control-plane request.
	Timeout time.Duration
	// ConnectorIndexPath is the private runtime-local map from connector fields
	// to their already delivered secret-store references.
	ConnectorIndexPath string
}

// InstallationResolver returns the runtime installation the runtime token
// resolves to. The CLI supplies it from the runtime whoami call.
type InstallationResolver func(ctx context.Context) (string, error)

// pendingDelivery represents a pending credential delivery from the control plane
type pendingDelivery struct {
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

// operationKindConnectorSecret is the delivery kind for a connector secret.
const operationKindConnectorSecret = "connector_secret"

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

// claimRequest is the request to claim a delivery
type claimRequest struct {
	RuntimeInstallationID string `json:"runtime_installation_id"`
}

// claimResponse is the response from claiming a delivery
type claimResponse struct {
	Delivery          *pendingDelivery `json:"delivery,omitempty"`
	LeaseExpiresAt    time.Time        `json:"lease_expires_at,omitempty"`
	NoDeliveryPending bool             `json:"no_delivery_pending"`
	// ActiveGeneration is the highest generation currently active for the
	// delivery's profile, when the control plane reports it. It is additive and
	// optional; when absent (0) the stale-generation guard is a no-op.
	ActiveGeneration int `json:"active_generation,omitempty"`
}

// ackRequest is the request to acknowledge a delivery result
type ackRequest struct {
	OperationID    string `json:"operation_id"`
	RecipientID    string `json:"recipient_id"`
	Success        bool   `json:"success"`
	FailureReason  string `json:"failure_reason,omitempty"` // redacted
	BackendVersion int    `json:"backend_version"`
}

// failureReason is the closed set of redacted failure classes a sync can
// report. Only these values are ever written to the control plane or emitted,
// so a failure can never carry a raw backend error, a reference, or secret
// material. The first three values are the pre-existing wire contract and must
// not change; the last two are additive.
type failureReason string

const (
	failureDecryption      failureReason = "decryption_failed"
	failureBackendWrite    failureReason = "backend_write_failed"
	failureValidation      failureReason = "backend_validation_failed"
	failureInvalidRef      failureReason = "invalid_secret_ref"
	failureStaleGeneration failureReason = "stale_generation"
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

// SyncOutput is the output of the sync command
type SyncOutput struct {
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

// Sync processes at most one pending delivery. A returned error means the
// sync could not reach a delivery at all; every per-delivery failure is a
// SyncOutput with Success false and a redacted error class, already
// acknowledged to the control plane. Plaintext never leaves this function
// except into store.
func Sync(ctx context.Context, cfg Config, store secrets.Store, installation InstallationResolver) (out *SyncOutput, err error) {
	client := newDeliveryClient(cfg.ControlPlaneURL, cfg.Timeout)

	// Step 1: Get runtime identity to know our installation ID
	runtimeInstallID, err := installation(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve runtime installation: %w", err)
	}

	// Step 2: Claim an eligible delivery
	claimReq := claimRequest{
		RuntimeInstallationID: runtimeInstallID,
	}

	claimResp, err := client.ClaimDelivery(ctx, cfg.RuntimeToken, claimReq)
	if err != nil {
		return nil, fmt.Errorf("claim delivery: %w", err)
	}

	// No pending delivery - this is fine, just return no-op
	if claimResp.NoDeliveryPending || claimResp.Delivery == nil {
		return &SyncOutput{
			Claimed:     false,
			Success:     true,
			ProcessedAt: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	delivery := claimResp.Delivery
	activeGeneration := claimResp.ActiveGeneration
	// Every outcome for a connector delivery names the connector field.
	defer func() {
		if out != nil && delivery.OperationKind == operationKindConnectorSecret {
			out.OperationKind, out.ConnectorID, out.Field = delivery.OperationKind, delivery.ConnectorID, delivery.Field
		}
	}()

	// Step 3: Decrypt the sealed payload (in memory, never log plaintext)
	plaintext, err := openDelivery(delivery, runtimeInstallID, cfg)
	if err != nil {
		// Acknowledge failure with redacted error
		ackErr := client.AcknowledgeDelivery(ctx, cfg.RuntimeToken, ackRequest{
			OperationID:    delivery.OperationID,
			RecipientID:    delivery.RecipientID,
			Success:        false,
			FailureReason:  string(failureDecryption),
			BackendVersion: 0,
		})
		if ackErr != nil {
			// Log but don't fail - the lease will expire anyway
			fmt.Fprintf(os.Stderr, "warning: failed to acknowledge delivery failure: %v\n", ackErr)
		}
		return &SyncOutput{
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
	invalidRef := secrets.ValidateRef(delivery.SecretBackend, delivery.SecretRef) != nil
	if delivery.OperationKind == operationKindConnectorSecret && !connectorSecretRefNamesField(delivery.SecretRef, delivery.ConnectorID, delivery.Field) {
		invalidRef = true
	}
	if invalidRef {
		_ = client.AcknowledgeDelivery(ctx, cfg.RuntimeToken, ackRequest{
			OperationID:    delivery.OperationID,
			RecipientID:    delivery.RecipientID,
			Success:        false,
			FailureReason:  string(failureInvalidRef),
			BackendVersion: 0,
		})
		return &SyncOutput{
			Claimed:     true,
			OperationID: delivery.OperationID,
			Backend:     delivery.SecretBackend,
			Success:     false,
			Error:       string(failureInvalidRef),
			ProcessedAt: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}
	if isStaleGeneration(delivery.Generation, activeGeneration) {
		_ = client.AcknowledgeDelivery(ctx, cfg.RuntimeToken, ackRequest{
			OperationID:    delivery.OperationID,
			RecipientID:    delivery.RecipientID,
			Success:        false,
			FailureReason:  string(failureStaleGeneration),
			BackendVersion: 0,
		})
		return &SyncOutput{
			Claimed:     true,
			OperationID: delivery.OperationID,
			Backend:     delivery.SecretBackend,
			Success:     false,
			Error:       string(failureStaleGeneration),
			ProcessedAt: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	// Step 5: Write to the canonical generation-specific backend reference.
	err = store.Put(ctx, delivery.SecretBackend, delivery.SecretRef, plaintext)
	if err != nil {
		// Acknowledge failure with redacted error
		_ = client.AcknowledgeDelivery(ctx, cfg.RuntimeToken, ackRequest{
			OperationID:    delivery.OperationID,
			RecipientID:    delivery.RecipientID,
			Success:        false,
			FailureReason:  string(failureBackendWrite),
			BackendVersion: 0,
		})
		return &SyncOutput{
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
		_ = client.AcknowledgeDelivery(ctx, cfg.RuntimeToken, ackRequest{
			OperationID:    delivery.OperationID,
			RecipientID:    delivery.RecipientID,
			Success:        false,
			FailureReason:  string(failureValidation),
			BackendVersion: 0,
		})
		return &SyncOutput{
			Claimed:     true,
			OperationID: delivery.OperationID,
			Backend:     delivery.SecretBackend,
			SecretName:  delivery.SecretRef,
			Success:     false,
			Error:       "validation_error", // redacted
			ProcessedAt: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}
	if delivery.OperationKind == operationKindConnectorSecret {
		if cfg.ConnectorIndexPath == "" {
			stateDir := os.Getenv("KEI_RUNTIME_STATE_DIR")
			if stateDir == "" {
				stateDir = statedir.DefaultPathOS()
			}
			cfg.ConnectorIndexPath = filepath.Join(stateDir, "connector-credentials.json")
		}
		if err := WriteConnectorReference(cfg.ConnectorIndexPath, ConnectorReference{
			ConnectorID: delivery.ConnectorID, Field: delivery.Field,
			SecretBackend: delivery.SecretBackend, SecretRef: delivery.SecretRef,
			Generation: delivery.Generation,
		}); err != nil {
			return nil, fmt.Errorf("persist connector credential reference failed")
		}
	}

	// Step 7: Acknowledge success
	err = client.AcknowledgeDelivery(ctx, cfg.RuntimeToken, ackRequest{
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

	return &SyncOutput{
		Claimed:     true,
		OperationID: delivery.OperationID,
		Backend:     delivery.SecretBackend,
		SecretName:  delivery.SecretRef,
		Success:     true,
		ProcessedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// openDelivery decrypts a delivery sealed to this runtime's configured sync
// key. A delivery addressed to any other key id is refused unopened.
func openDelivery(d *pendingDelivery, installationID string, cfg Config) (string, error) {
	if d.RecipientKeyID == "" || d.RecipientKeyID != cfg.KeyID {
		return "", fmt.Errorf("unknown credential sync key")
	}
	key, err := crypto.ParsePrivateKey(cfg.PrivateKey)
	if err != nil {
		return "", err
	}
	return crypto.Open(d.SealedPayload, key, installationID, d.RecipientKeyID)
}
