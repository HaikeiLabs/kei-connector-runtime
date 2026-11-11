package connectorruntime

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/HaikeiLabs/kei-connector-contracts/policybundlehealth"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/auditcrypto"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/invoke"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/credrelease"
	runcommand "github.com/HaikeiLabs/kei-connector-runtime/internal/run"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/socket"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

const (
	defaultListenAddr     = ":8085"
	shutdownFlushTimeout  = 5 * time.Second
	collectorPollInterval = time.Minute
)

// runServe starts the runtime-owned HTTP adapter. The adapter is deliberately
// separate from the one-shot stdin/stdout commands so existing harnesses keep
// their process protocol unchanged.
func runServe(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "serve does not accept positional arguments")
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg := configFromEnv()
	return runServeContext(ctx, cfg, runtimeSocketPathFromEnv(), envOr("KEI_PROXY_LISTEN_ADDR", defaultListenAddr))
}

func runtimeSocketPathFromEnv() string {
	return envOr("KEI_RUNTIME_SOCKET_PATH", socket.DefaultPathOS())
}

func runServeContext(ctx context.Context, cfg Config, socketPath, addr string) int {
	// The daemon may hold session credentials in memory; never dump it.
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
		slog.Warn("runtime_core_limit_failed", "error", err)
	}
	// serve owns its state directory: it is the one process that refreshes
	// policy, ships audit, and reports heartbeats for it (HAI-438). Claim it
	// before any child starts, so a `runtime heartbeat` beside it can never
	// win the refresher lock and leave the daemon without an identity.
	releaseStateDir, err := keiruntime.ClaimStateDir(cfg.RuntimeStateDir)
	if err != nil {
		slog.Error("runtime_state_dir_unavailable", "dir", cfg.RuntimeStateDir, "error", err,
			"hint", "kei-proxy serve runs the heartbeat, policy refresher and audit collector itself; stop any kei-proxy runtime heartbeat on this state directory")
		return 1
	}
	defer releaseStateDir()
	local, err := newServeLocalPDP(cfg, serveSeams{})
	if err != nil {
		slog.Error("runtime_credential_release_invalid", "error", err)
		return 1
	}
	defer local.Close()
	unixListener, err := socket.Listen(socketPath)
	if err != nil {
		slog.Error("runtime_unix_listener_failed", "path", socketPath, "error", err)
		return 1
	}
	defer func() {
		_ = unixListener.Close()
		_ = os.Remove(socketPath)
	}()
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("runtime_http_listener_failed", "addr", addr, "error", err)
		return 1
	}
	newServer := func(h http.Handler) *http.Server {
		return &http.Server{
			Handler:           h,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      2 * time.Minute,
			IdleTimeout:       2 * time.Minute,
		}
	}
	tcpHandler, socketHandler := newServeHandlers(cfg, local)

	// One supervisor owns every long-lived child. They share one context: a
	// signal or any child's fatal error stops all of them, and the collector
	// makes its final flush on the way out.
	var identity atomic.Pointer[keiruntime.Identity]
	children := keiruntime.NewSupervisor(ctx)
	children.Go("http listener", func(ctx context.Context) error {
		return keiruntime.ServeHTTP(ctx, newServer(tcpHandler), tcpListener, shutdownFlushTimeout)
	})
	children.Go("unix listener", func(ctx context.Context) error {
		return keiruntime.ServeHTTP(ctx, newServer(socketHandler), unixListener, shutdownFlushTimeout)
	})
	children.Go("session sweeper", func(ctx context.Context) error {
		local.SweepSessions(ctx)
		return nil
	})
	children.GoService(func(ctx context.Context) func() {
		return keiruntime.StartPolicyRefresher(ctx, cfg,
			func() (*keiruntime.Identity, error) {
				id, err := NewRuntimeClient(cfg.RuntimeControlPlaneURL, 10*time.Second).WhoAmI(ctx, cfg.RuntimeToken)
				if err != nil {
					return nil, err
				}
				return identityFromRoot(id), nil
			},
			func(identity *keiruntime.Identity) error {
				return SyncPolicyBundle(ctx, cfg, &RuntimeIdentity{
					ID: identity.ID, OrgID: identity.OrgID, WorkspaceID: identity.WorkspaceID, AgentID: identity.AgentID,
				}, 10*time.Second)
			},
			IsRuntimeRevocation,
			func() { RevokePolicyState(cfg) },
			func(id *keiruntime.Identity) {
				identity.Store(id)
				local.SetIdentity(id)
			},
			local.AfterSync,
			keiruntime.WithClaimedStateDir(),
			keiruntime.WithBootstrapResult(func(syncErr error) {
				var bundleVersion int64
				var bundleDigest string
				if syncErr == nil {
					if store, err := policybundle.OpenStore(cfg.RuntimeStateDir); err == nil {
						if status, err := store.Status(time.Now().UTC()); err == nil {
							bundleVersion, bundleDigest = status.BundleVersion, status.BundleDigest
						}
					}
				}
				runID, _ := keiruntime.HeartbeatRunID(os.Getenv)
				event := keiruntime.PolicyBootstrapEvent(syncErr, bundleVersion, bundleDigest, version, runID, time.Now().UTC())
				_ = keiruntime.AppendLifecycleEvent(cfg.PolicyAuditPath(), cfg.PolicyAuditMaxBytes(), event)
			}),
			keiruntime.WithHarnessResync(keiruntime.NewHarnessResync(cfg, os.Getenv)),
		)
	})
	children.GoService(func(ctx context.Context) func() {
		return keiruntime.StartCollector(ctx, cfg, keiruntime.ResolveAuditPath(cfg.AuditPath, cfg.RuntimeStateDir), collectorPollInterval, shutdownFlushTimeout)
	})
	if cfg.IsRuntime() {
		children.Go("heartbeat", serveHeartbeat(cfg, NewRuntimeClient(cfg.RuntimeControlPlaneURL, 15*time.Second), identity.Load))
	}
	slog.Info("runtime_http_listener_started", "addr", addr)
	slog.Info("runtime_unix_listener_started", "path", socketPath, "mode", "0600")

	if err := children.Wait(); err != nil {
		slog.Error("runtime_serve_stopped", "error", err)
		return 1
	}
	return 0
}

// serveHeartbeat reports the daemon's liveness to the control plane with the
// v2 body until ctx ends. Transient catalog failures are retried by the loop;
// a rejected or revoked installation is fatal and stops the daemon.
func serveHeartbeat(cfg Config, client keiruntime.HeartbeatClient, identity func() *keiruntime.Identity) func(context.Context) error {
	return func(ctx context.Context) error {
		runID, err := keiruntime.HeartbeatRunID(os.Getenv)
		if err != nil {
			slog.Warn("runtime_heartbeat_run_id_invalid", "error", err)
			runID = uuid.NewString()
		}
		envelope, err := keiruntime.HarnessEnvelopeFromEnv(os.Getenv)
		if err != nil {
			slog.Warn("runtime_heartbeat_envelope_invalid", "error", err)
			envelope = nil
		}
		interval := cfg.RuntimeHeartbeatInterval
		if interval <= 0 {
			interval = defaultRuntimeHeartbeatInterval
		}
		loop := newRuntimeHeartbeatLoop(cfg, client, interval)
		loop.Report = versionedHeartbeatReport(runID, interval, time.Now(), envelope)
		loop.Versioned = true
		loop.Warn = os.Stderr
		loop.PolicyBundle = func() *policybundlehealth.Health {
			id := identity()
			if id == nil {
				return nil
			}
			return currentPolicyBundleHealth(cfg, &RuntimeIdentity{ID: id.ID, OrgID: id.OrgID, WorkspaceID: id.WorkspaceID})
		}
		slog.Info("runtime_heartbeat_started", "interval", interval.String(), "run_id", runID)
		if err := loop.Run(ctx, true); err != nil {
			if IsRuntimeRevocation(err) {
				RevokePolicyState(cfg)
			}
			return fmt.Errorf("control plane rejected the runtime heartbeat: %w", err)
		}
		return nil
	}
}

// serveSeams are test seams for the daemon; the zero value is production.
type serveSeams struct {
	providerTransport http.RoundTripper
}

// newServeLocalPDP builds the daemon's local PDP: decision audit goes to the
// spool and, with KEI_CREDENTIAL_RELEASE=identity, linked sessions and an
// owner session with matching linked bundle identity hold connector credentials
// in session stores; POST /v1/commands:run resolves credential references with
// them. The caller must Close it on exit.
func newServeLocalPDP(cfg Config, seams serveSeams) (*keiruntime.LocalPDP, error) {
	creds, err := newSessionCredentialStore(cfg)
	if err != nil {
		return nil, err
	}
	auditPath := keiruntime.ResolveAuditPath(cfg.AuditPath, cfg.RuntimeStateDir)
	emitFunc := func(data json.RawMessage) {
		if auditPath == "" {
			return
		}
		if err := keiruntime.NewAuditSpool(auditPath, cfg.AuditMaxBytes).Append(keiruntime.EventClassDecision, data); err != nil {
			slog.Error("runtime decision audit append failed", "path", auditPath, "error", err)
		}
	}
	local := keiruntime.NewLocalPDP(cfg, emitFunc)
	local.SetSessionIdleTTL(cfg.SessionIdleTTL)
	local.SetTokenlessOwnerSession(cfg.TokenlessOwnerSession)
	local.SetExportableServicePrincipals(cfg.ExportableServicePrincipals)
	if creds != nil {
		store := connectorSecretStore()
		secretResolver := invoke.SecretResolver{IndexPath: credentials.ConnectorIndexPath(cfg.RuntimeStateDir), Store: store}
		local.SetCredentialStore(creds)
		local.SetCommandRunner(&runcommand.Daemon{
			Authorize:     local.ConnectorGrant,
			UseCredential: local.UseCredential,
			Secrets:       secretResolver,
			AppendAudit: func(record []byte) error {
				emitFunc(record)
				return nil
			},
			AuditCrypto: auditcrypto.NewProvider(cfg.RuntimeControlPlaneURL, cfg.RuntimeToken),
		})
	}
	return local, nil
}

// newServeHandlers builds the TCP handler and the Unix socket handler (the
// TCP routes plus the local PDP's authorize and session routes). The owner-only
// Unix socket is the caller boundary for local authorize requests; all session
// routes still require the runtime token. The TCP handler exposes no PDP route.
func newServeHandlers(cfg Config, local *keiruntime.LocalPDP) (tcp, unix http.Handler) {
	base := newRuntimeHTTPHandler(cfg, local.Sessions).(*runtimeHTTPHandler)
	local.SetModelConfigHandler(http.HandlerFunc(base.handleModelConfig))
	return base, local.NewSocketHandler(base, base.runtimeConfigError, base.authorized)
}

const (
	CredentialReleaseLegacy   = "legacy"
	CredentialReleaseIdentity = "identity"
)

// newSessionCredentialStore returns the session credential store for
// KEI_CREDENTIAL_RELEASE=identity, or nil for legacy. I11 is called on
// KEI_CREDENTIAL_RELEASE_URL, defaulting to the runtime control plane (the
// gateway's runtime host serves the resolve route).
func newSessionCredentialStore(cfg Config) (*credrelease.Store, error) {
	switch cfg.CredentialRelease {
	case "", CredentialReleaseLegacy:
		return nil, nil
	case CredentialReleaseIdentity:
	default:
		return nil, fmt.Errorf("KEI_CREDENTIAL_RELEASE must be %q or %q", CredentialReleaseIdentity, CredentialReleaseLegacy)
	}
	base := cfg.CredentialReleaseURL
	if base == "" {
		base = cfg.RuntimeControlPlaneURL
	}
	if err := keiruntime.ValidatePolicyControlPlaneURL(base, !cfg.IsProduction()); err != nil {
		return nil, fmt.Errorf("credential release URL is invalid: %w", err)
	}
	return credrelease.NewStore(credrelease.NewClient(base, cfg.RuntimeToken, 10*time.Second)), nil
}

type runtimeHTTPHandler struct {
	cfg      Config
	profiles ControlPlaneModelProfileClient
	client   *http.Client
	sessions *pdp.Sessions
}

func newRuntimeHTTPHandler(cfg Config, sessions *pdp.Sessions) http.Handler {
	return &runtimeHTTPHandler{
		cfg:      cfg,
		profiles: NewControlPlaneModelProfileClient(cfg.RuntimeControlPlaneURL, cfg.RuntimeToken, 10*time.Second),
		client:   &http.Client{Timeout: 2 * time.Minute},
		sessions: sessions,
	}
}

func (h *runtimeHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/healthz":
		h.handleHealth(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/readyz":
		h.handleReady(w)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/model-config":
		h.handleModelConfig(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/model-profiles":
		h.handleModelProfiles(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/models":
		h.handleModels(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *runtimeHTTPHandler) handleReady(w http.ResponseWriter) {
	if err := h.runtimeConfigError(); err != nil {
		writeRuntimeError(w, http.StatusServiceUnavailable, "runtime_not_configured", err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ready\n")
}

// handleHealth probes the resolved model provider with a bounded request to
// its /models endpoint. It is intentionally separate from runtime identity and
// heartbeat: the runtime can be alive and authenticated while the provider is
// unreachable. Only redacted error classes are returned; credential material
// and provider payloads never appear in the response or logs.
func (h *runtimeHTTPHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := h.runtimeConfigError(); err != nil {
		writeRuntimeError(w, http.StatusServiceUnavailable, "runtime_not_configured", err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	profile, err := h.resolveAssignedOrDefaultProfile(ctx)
	if err != nil {
		slog.Warn("health_probe_no_profile")
		writeRuntimeError(w, http.StatusServiceUnavailable, "health_no_profile", "no model profile assigned to this runtime")
		return
	}

	endpoint := strings.TrimRight(profile.Endpoint, "/") + "/models"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		slog.Warn("health_probe_request_build_failed")
		writeRuntimeError(w, http.StatusServiceUnavailable, "health_provider_unreachable", "provider health check failed")
		return
	}

	if profile.AuthType == "api_key" {
		apiKey, err := getModelProfileAPIKey(profile)
		if err != nil {
			slog.Warn("health_probe_credential_unavailable")
			writeRuntimeError(w, http.StatusServiceUnavailable, "health_credential_unavailable", "provider credential could not be resolved")
			return
		}
		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
	}

	resp, err := h.client.Do(req)
	if err != nil {
		slog.Warn("health_probe_provider_unreachable")
		writeRuntimeError(w, http.StatusServiceUnavailable, "health_provider_unreachable", "provider health check failed")
		return
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("health_probe_provider_unhealthy", "status", resp.StatusCode)
		writeRuntimeError(w, http.StatusServiceUnavailable, "health_provider_unhealthy", "provider returned non-200 status")
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

// handleModelConfig serves GET /v1/model-config (HAI-671): returns the runtime's
// assigned model profile as a config source for the harness. The Unix-socket
// handler applies auth before reaching this method; on the external TCP listener
// this path requires runtime-token auth.
func (h *runtimeHTTPHandler) handleModelProfiles(w http.ResponseWriter, r *http.Request) {
	if err := h.runtimeConfigError(); err != nil {
		writeRuntimeError(w, http.StatusServiceUnavailable, "runtime_not_configured", err.Error())
		return
	}
	if !h.authorized(r) {
		writeRuntimeError(w, http.StatusUnauthorized, "invalid_runtime_token", "runtime authentication failed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	profiles, err := h.profiles.ListRuntimeModelProfiles(ctx, r.URL.Query().Get("agent_id"))
	if err != nil {
		slog.Warn("model_profiles_lookup_failed", "error", err)
		writeRuntimeError(w, http.StatusBadGateway, "model_profiles_unavailable", "model profiles could not be resolved")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(profiles)
}

func (h *runtimeHTTPHandler) handleModels(w http.ResponseWriter, r *http.Request) {
	if err := h.runtimeConfigError(); err != nil {
		writeRuntimeError(w, http.StatusServiceUnavailable, "runtime_not_configured", err.Error())
		return
	}
	if !h.authorized(r) {
		writeRuntimeError(w, http.StatusUnauthorized, "invalid_runtime_token", "runtime authentication failed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	profile, err := h.resolveSelectedModelProfile(ctx, r.URL.Query().Get("agent_id"), r.URL.Query().Get("profile_id"))
	if err != nil || profile == nil || profile.Status != "active" {
		writeRuntimeError(w, http.StatusNotFound, "model_not_assigned", "no active assigned model profile was found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"object": "list",
		"data":   []map[string]string{{"id": profile.DefaultModel, "object": "model"}},
	})
}

func (h *runtimeHTTPHandler) handleModelConfig(w http.ResponseWriter, r *http.Request) {
	if err := h.runtimeConfigError(); err != nil {
		writeRuntimeError(w, http.StatusServiceUnavailable, "runtime_not_configured", err.Error())
		return
	}

	if !h.authorized(r) {
		writeRuntimeError(w, http.StatusUnauthorized, "invalid_runtime_token", "runtime authentication failed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	profile, err := h.resolveSelectedModelProfile(ctx, r.URL.Query().Get("agent_id"), r.URL.Query().Get("profile_id"))
	if err != nil {
		slog.Warn("model_config_no_profile", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "no_profile"})
		return
	}
	if profile == nil {
		slog.Warn("model_config_nil_profile")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "no_profile"})
		return
	}
	if profile.Status != "" && profile.Status != "active" {
		slog.Warn("model_config_profile_revoked", "profile_id", profile.ProfileID, "status", profile.Status)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "profile_revoked"})
		return
	}

	var credential string
	if profile.AuthType == "api_key" {
		apiKey, err := getModelProfileAPIKey(profile)
		if err != nil {
			slog.Warn("model_config_credential_unavailable", "profile_id", profile.ProfileID, "error", err)
			writeRuntimeError(w, http.StatusInternalServerError, "credential_unavailable", "provider credential could not be resolved")
			return
		}
		credential = apiKey
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"model":      profile.DefaultModel,
		"endpoint":   profile.Endpoint,
		"credential": credential,
		"is_default": profile.IsDefault,
	})
}

// connectorSecretStore is the tenant secret store for connector credentials:
// the same backends model profiles use. Without one, opaque_ref connectors
// deny credential_backend_unavailable.
func connectorSecretStore() secrets.Store {
	store, err := secrets.NewStoreFromEnv()
	if err != nil {
		return nil
	}
	return store
}

func (h *runtimeHTTPHandler) runtimeConfigError() error {
	if err := ValidateRuntimeTokenFormat(h.cfg.RuntimeToken); err != nil {
		return err
	}
	if h.cfg.RuntimeControlPlaneURL == "" {
		return errors.New("KEI_RUNTIME_CONTROL_PLANE_URL is required")
	}
	if err := keiruntime.ValidatePolicyControlPlaneURL(h.cfg.RuntimeControlPlaneURL, !h.cfg.IsProduction()); err != nil {
		return fmt.Errorf("KEI_RUNTIME_CONTROL_PLANE_URL is invalid: %w", err)
	}
	return nil
}

func (h *runtimeHTTPHandler) authorized(r *http.Request) bool {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(h.cfg.RuntimeToken)) == 1
}

func (h *runtimeHTTPHandler) resolveSelectedModelProfile(ctx context.Context, agentID, profileID string) (*ModelProfile, error) {
	if agentID != "" {
		parsed, err := uuid.Parse(agentID)
		if err != nil || parsed == uuid.Nil {
			return nil, fmt.Errorf("invalid agent_id")
		}
		agentID = parsed.String()
	}
	if profileID != "" {
		parsed, err := uuid.Parse(profileID)
		if err != nil || parsed == uuid.Nil {
			return nil, fmt.Errorf("invalid profile_id")
		}
		return h.profiles.GetRuntimeModelProfileForAgent(ctx, parsed.String(), agentID)
	}
	if agentID != "" {
		return h.profiles.GetRuntimeAssignedModelProfileForAgent(ctx, agentID)
	}
	return h.profiles.GetRuntimeAssignedModelProfile(ctx)
}

func (h *runtimeHTTPHandler) resolveAssignedOrDefaultProfile(ctx context.Context) (*ModelProfile, error) {
	profile, err := h.profiles.GetRuntimeAssignedModelProfile(ctx)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, fmt.Errorf("runtime has no active model profile assigned to its default agent (or has no default agent assigned)")
	}
	return profile, nil
}

func writeRuntimeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"message": message, "type": "runtime_error", "code": code},
	})
}
