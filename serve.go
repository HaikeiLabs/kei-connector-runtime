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
	"syscall"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/collector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/socket"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

const (
	defaultListenAddr     = ":8085"
	maxModelRequest       = 4 << 20
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
	ctx, stop := context.WithCancel(ctx)
	defer stop()
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
		_ = unixListener.Close()
		_ = os.Remove(socketPath)
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
	emitFunc := func(data json.RawMessage) {
		if cfg.AuditPath == "" {
			return
		}
		_ = keiruntime.NewAuditSpool(cfg.AuditPath, cfg.AuditMaxBytes).Append(keiruntime.EventClassDecision, data)
	}
	local := keiruntime.NewLocalPDP(cfg, emitFunc)
	base := newRuntimeHTTPHandler(cfg, local.Sessions).(*runtimeHTTPHandler)
	server := newServer(base)
	socketServer := newServer(local.NewHandler(base, base.runtimeConfigError, base.authorized))

	refresherDone := make(chan struct{})
	if cfg.IsRuntime() {
		refresher := keiruntime.NewPolicyRefresher(cfg,
			func() (*keiruntime.Identity, error) {
				id, err := NewRuntimeClient(cfg.RuntimeControlPlaneURL, 10*time.Second).WhoAmI(ctx, cfg.RuntimeToken)
				if err != nil {
					return nil, err
				}
				return &keiruntime.Identity{ID: id.ID, OrgID: id.OrgID, WorkspaceID: id.WorkspaceID}, nil
			},
			func(identity *keiruntime.Identity) error {
				return SyncPolicyBundle(ctx, cfg, &RuntimeIdentity{
					ID: identity.ID, OrgID: identity.OrgID, WorkspaceID: identity.WorkspaceID,
				}, 10*time.Second)
			},
			IsRuntimeRevocation,
			func() { RevokePolicyState(cfg) },
		)
		refresher.OnIdentity = local.SetIdentity
		refresher.AfterSync = local.AfterSync
		go func() {
			defer close(refresherDone)
			refresher.Run(ctx)
		}()
	} else {
		close(refresherDone)
	}
	slog.Info("runtime_http_listener_started", "addr", addr)
	slog.Info("runtime_unix_listener_started", "path", socketPath, "mode", "0600")
	serveErrors := make(chan error, 2)
	go func() { serveErrors <- server.Serve(tcpListener) }()
	go func() { serveErrors <- socketServer.Serve(unixListener) }()
	stopCollector := func() {}
	if cfg.AuditPath != "" {
		audit := keiruntime.NewCollector(cfg.AuditPath, keiruntime.NewABACFlushClientFromConfig(cfg, shutdownFlushTimeout), 100)
		audit.LifecycleClient = keiruntime.NewLifecycleFlushClientFromConfig(cfg, shutdownFlushTimeout)
		audit.HarnessToolClient = keiruntime.NewHarnessToolFlushClientFromConfig(cfg, shutdownFlushTimeout)
		stopCollector = collector.Service{
			Flusher:           audit,
			Path:              cfg.AuditPath,
			PollInterval:      collectorPollInterval,
			FinalFlushTimeout: shutdownFlushTimeout,
		}.Start(ctx)
	}

	exitCode := 0
	select {
	case <-ctx.Done():
	case err := <-serveErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("runtime_http_listener_failed", "error", err)
			exitCode = 1
		}
	}
	stopCollector()
	stop()
	<-refresherDone
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownFlushTimeout)
	defer cancel()
	for _, srv := range []*http.Server{server, socketServer} {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("runtime_http_shutdown_incomplete", "error", err)
			_ = srv.Close()
		}
	}
	return exitCode
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
	case r.Method == http.MethodGet && r.URL.Path == "/v1/models":
		h.handleModels(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions":
		h.handleChatCompletions(w, r)
	default:
		http.NotFound(w, r)
	}
}

type openAIModelList struct {
	Object string        `json:"object"`
	Data   []openAIModel `json:"data"`
}

type openAIModel struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Object  string `json:"object"`
	OwnedBy string `json:"owned_by"`
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
	profile, err := h.resolveAssignedOrDefaultProfile(ctx)
	if err != nil {
		writeRuntimeError(w, http.StatusBadGateway, "profile_unavailable", err.Error())
		return
	}
	models := openAIModelList{Object: "list", Data: []openAIModel{}}
	if profile != nil && profile.Status == "active" {
		models.Data = append(models.Data, openAIModel{
			ID:      profile.ProfileID,
			Name:    profile.DisplayName,
			Object:  "model",
			OwnedBy: "kei",
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(models)
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

func (h *runtimeHTTPHandler) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if err := h.runtimeConfigError(); err != nil {
		writeRuntimeError(w, http.StatusServiceUnavailable, "runtime_not_configured", err.Error())
		return
	}
	if !h.authorized(r) {
		writeRuntimeError(w, http.StatusUnauthorized, "invalid_runtime_token", "runtime authentication failed")
		return
	}

	invokingSubject := ""
	if h.sessions != nil {
		if sub, ok := h.sessions.Current(); ok {
			invokingSubject = sub.UserID
		}
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxModelRequest))
	if err != nil {
		writeRuntimeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds the configured limit")
		return
	}
	var request struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", "request body must be valid JSON")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	profile, err := h.resolveProfile(ctx, request.Model)
	if err != nil {
		writeRuntimeError(w, http.StatusBadGateway, "profile_unavailable", err.Error())
		return
	}
	if profile == nil {
		writeRuntimeError(w, http.StatusNotFound, "model_not_found", "requested model is not configured")
		return
	}
	if profile.Status != "active" {
		writeRuntimeError(w, http.StatusServiceUnavailable, "model_unavailable", "configured model is not active")
		return
	}
	if err := h.authorizeModel(ctx, profile, invokingSubject); err != nil {
		writeRuntimeError(w, http.StatusForbidden, "model_invocation_denied", err.Error())
		return
	}
	providerBody, err := rewriteProviderModel(body, profile.DefaultModel)
	if err != nil {
		writeRuntimeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	response, err := h.invokeProvider(ctx, profile, providerBody)
	if err != nil {
		writeRuntimeError(w, http.StatusBadGateway, "provider_unavailable", err.Error())
		return
	}
	defer response.Body.Close()
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

// rewriteProviderModel translates the OpenAI-facing model profile ID into the
// provider's configured model name. OpenWebUI selects profiles by ID, while
// the upstream endpoint expects profile.DefaultModel.
func rewriteProviderModel(body []byte, defaultModel string) ([]byte, error) {
	if defaultModel == "" {
		return body, nil
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, errors.New("request body must be valid JSON")
	}
	model, err := json.Marshal(defaultModel)
	if err != nil {
		return nil, errors.New("could not encode configured model")
	}
	payload["model"] = model
	return json.Marshal(payload)
}

func (h *runtimeHTTPHandler) authorizeModel(ctx context.Context, profile *ModelProfile, invokingSubject string) error {
	identity, err := NewRuntimeClient(h.cfg.RuntimeControlPlaneURL, 10*time.Second).WhoAmI(ctx, h.cfg.RuntimeToken)
	if err != nil {
		return fmt.Errorf("resolve runtime identity for local policy: %w", err)
	}
	if identity == nil || identity.Status != "active" || identity.BindingStatus != "verified" || identity.WorkspaceID == nil {
		return errors.New("runtime installation is inactive, unverified, or unscoped")
	}
	store, err := policybundle.OpenStore(h.cfg.RuntimeStateDir)
	if err != nil {
		return err
	}
	bundle, _, err := store.Check(identity.ID, identity.OrgID, *identity.WorkspaceID, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("local policy bundle unavailable: %w", err)
	}
	var attrs *policybundle.Subject
	if invokingSubject != "" || h.cfg.ProviderUserID != "" {
		client := keiruntime.NewPolicyControlClient(h.cfg.ABACURL, h.cfg.RuntimeToken, 10*time.Second, !h.cfg.IsProduction())
		req := keiruntime.SubjectResolveRequest{}
		if invokingSubject != "" {
			req.UserID = invokingSubject
		} else {
			req.PlatformUserID = h.cfg.ProviderUserID
			req.TenantID = os.Getenv("KEI_PROXY_PLATFORM_TENANT_ID")
		}
		resolved, e := client.ResolveSubject(ctx, req)
		if errors.Is(e, ErrPolicyInstallationRevoked) {
			_ = store.Revoke(time.Now().UTC())
			return e
		}
		if e != nil {
			return fmt.Errorf("subject resolution unavailable: %w", e)
		}
		attrs = &resolved
	}
	agentID := envOr("KEI_PROXY_AGENT_ID", "")
	decision := bundle.EvaluateAction("model:invoke", "model:"+profile.ProfileID, agentID, attrs)
	if decision.Outcome != "allow" {
		return fmt.Errorf("local policy denied model invocation (%s)", decision.ReasonCode)
	}
	return nil
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

func (h *runtimeHTTPHandler) resolveProfile(ctx context.Context, model string) (*ModelProfile, error) {
	profile, err := h.resolveAssignedOrDefaultProfile(ctx)
	if err != nil {
		return nil, err
	}
	if model != "" && model != profile.ProfileID {
		return nil, fmt.Errorf("model %q is not assigned to the runtime's default agent", model)
	}
	return profile, nil
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

func (h *runtimeHTTPHandler) invokeProvider(ctx context.Context, profile *ModelProfile, body []byte) (*http.Response, error) {
	endpoint := strings.TrimRight(profile.Endpoint, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("build provider request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if profile.AuthType == "api_key" {
		apiKey, err := getModelProfileAPIKey(profile)
		if err != nil {
			return nil, fmt.Errorf("resolve provider credentials: %w", err)
		}
		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
	}
	return h.client.Do(req)
}

func writeRuntimeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"message": message, "type": "runtime_error", "code": code},
	})
}
