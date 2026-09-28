package connectorruntime

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CredentialResponse carries only the secret value. Injection is decided by the
// tool, not by the proxy.
type CredentialResponse struct {
	Value string `json:"value"`
}

type AuthorizeOutput struct {
	Decision   string              `json:"decision"`
	Reason     string              `json:"reason,omitempty"`
	Service    string              `json:"service,omitempty"`
	Credential *CredentialResponse `json:"credential,omitempty"`
	Enrollment *json.RawMessage    `json:"enrollment,omitempty"`
}

type authorizeParams struct {
	ctx          context.Context
	user         string
	providerUser string
	tool         string
	action       string
	resource     string
	harness      string
	abac         ABACClient
	// Deprecated compatibility fields; runtime authorization never uses them.
	credentialBinding CredentialBindingClient
	secretStore       SecretStore
	oidcBridge        OIDCBridgeClient
	auditPath         string
	auditMaxBytes     int64
	registry          *Registry

	// Identity-propagation context supplied by the invoking harness.
	spanID          string
	invokingSubject string
	parentSpan      string
	delegationDepth int
	agentID         string
	agentVersion    string
	framework       string
	toolArgsDigest  string
	resources       []string
	orgID           string
	workspaceID     string
}

// authorizeDecision is the shared policy-catalog decision path used by both
// the authorize CLI and long-running runtime adapters. Credential resolution
// stays outside this helper so every caller can enforce allow before touching
// secret material.
func authorizeDecision(p authorizeParams, service, resource string) (*AuthorizeResponse, error) {
	resp, err := p.abac.Authorize(p.ctx, AuthorizeRequest{
		HarnessToken:    p.harness,
		UserID:          p.user,
		ProviderUserID:  p.providerUser,
		Action:          p.action,
		Resource:        resource,
		Service:         service,
		AgentID:         p.agentID,
		WorkspaceID:     p.workspaceID,
		InvokingSubject: p.invokingSubject,
		ParentSpan:      p.parentSpan,
		DelegationDepth: p.delegationDepth,
		AgentVersion:    p.agentVersion,
		Framework:       p.framework,
		ToolArgsDigest:  p.toolArgsDigest,
		Resources:       p.resources,
	})
	if err != nil {
		return nil, fmt.Errorf("authorization unavailable (fail closed): %w", err)
	}
	return resp, nil
}

func authorizeTool(p authorizeParams) (AuthorizeOutput, error) {
	service := p.registry.Service(p.tool)

	// Prepend service to resource if not already present (e.g., HaikeiLabs/kei -> github:repo:HaikeiLabs/kei)
	resource := p.resource
	if service != "" && !strings.HasPrefix(resource, service+":") {
		resource = service + ":repo:" + resource
	}

	resp, err := authorizeDecision(p, service, resource)
	if err != nil {
		return AuthorizeOutput{}, err
	}

	out := AuthorizeOutput{}
	switch resp.Decision {
	case "allow":
		out.Decision = "allow"
		if service == "" {
			break
		}

		// Try OIDC bridge first for OAuth tokens (preferred for GitHub, etc.)
		if p.oidcBridge != nil {
			oauthToken, err := p.oidcBridge.GetOAuthToken(p.ctx, p.user, service)
			if err != nil {
				if errors.Is(err, ErrEnrollmentRequired) {
					// Bridge says enrollment required (404/409/bridge down)
					// OAuth-backed services require enrollment when no token is available.
					slog.Info("OIDC bridge enrollment required", "user_id", p.user, "service", service, "error", err)
					out.Decision = "enrollment_required"
					out.Service = service
					break
				}
				// Other bridge errors are logged before trying the runtime binding.
				slog.Warn("OIDC bridge error", "user_id", p.user, "service", service, "error", err)
			}
			if oauthToken != nil {
				out.Credential = &CredentialResponse{Value: oauthToken.AccessToken}
				out.Service = service
				break
			}
			// No token from bridge; resolve the runtime credential binding below.
		}

		var cred *string
		if p.credentialBinding != nil {
			// Customer-hosted runtimes resolve only non-secret metadata from Kei,
			// then retrieve the value directly from the customer's secret store.
			descriptor, err := p.credentialBinding.Resolve(p.ctx, p.harness, p.user, service)
			if err != nil {
				if errors.Is(err, errCredentialBindingNotFound) {
					slog.Info("credential binding enrollment required", "user_id", p.user, "service", service)
				} else {
					slog.Warn("credential binding lookup error", "user_id", p.user, "service", service, "error", err)
				}
				out.Decision = "enrollment_required"
				out.Service = service
				break
			}
			cred, err = p.secretStore.Get(p.ctx, descriptor.SecretBackend, descriptor.SecretRef)
			if err != nil {
				if errors.Is(err, errSecretNotFound) {
					slog.Info("credential secret not found", "user_id", p.user, "service", service)
				} else {
					slog.Warn("credential secret lookup error", "user_id", p.user, "service", service, "error", err)
				}
				out.Decision = "enrollment_required"
				out.Service = service
				break
			}
		}
		if cred == nil {
			out.Decision = "enrollment_required"
			out.Service = service
			break
		}
		out.Credential = &CredentialResponse{Value: *cred}
	case "enrollment_required":
		out.Decision = "deny"
		out.Reason = resp.Reason
		out.Enrollment = resp.Enrollment
	default:
		out.Decision = "deny"
		out.Reason = resp.Reason
	}

	emitDecision(p.auditPath, p.auditMaxBytes, buildDecisionEvent(p, resp, out, resource))

	return out, nil
}

// buildDecisionEvent assembles the canonical audit record for an authorize
// decision. The span_id is taken from the harness (stable across re-flushes);
// if absent, a fresh UUID is minted so every decision is individually
// dedupable. org_id and policy_id come from the ABAC response.
func buildDecisionEvent(p authorizeParams, resp *AuthorizeResponse, out AuthorizeOutput, resource string) DecisionEvent {
	spanID := p.spanID
	if spanID == "" {
		spanID = uuid.NewString()
	}

	subject := p.invokingSubject
	if subject == "" {
		subject = p.user
	}

	// The full resources_touched list comes from the harness when provided;
	// otherwise fall back to the single authorized resource.
	resources := p.resources
	if len(resources) == 0 && resource != "" {
		resources = []string{resource}
	}

	event := DecisionEvent{
		SpanID:           spanID,
		InvokedAt:        time.Now().UTC(),
		InvokingSubject:  subject,
		DelegationDepth:  p.delegationDepth,
		AgentID:          p.agentID,
		Framework:        p.framework,
		ToolName:         p.tool,
		ResourcesTouched: resources,
		Decision:         out.Decision,
	}
	if p.parentSpan != "" {
		event.ParentSpan = &p.parentSpan
	}
	if p.agentVersion != "" {
		event.AgentVersion = &p.agentVersion
	}
	if p.toolArgsDigest != "" {
		event.ToolArgsDigest = &p.toolArgsDigest
	}
	if resp != nil {
		if resp.OrgID != nil {
			event.OrgID = resp.OrgID
		} else if p.orgID != "" {
			event.OrgID = &p.orgID
		}
		if resp.PolicyID != "" {
			event.PolicyID = &resp.PolicyID
		}
		if resp.Reason != "" {
			event.PolicyReason = &resp.Reason
		}
	}
	if resp != nil && resp.WorkspaceID != nil {
		event.WorkspaceID = resp.WorkspaceID
	} else if p.workspaceID != "" {
		event.WorkspaceID = &p.workspaceID
	}
	return event
}

// resolveRuntimeScope reads the invocation's org and workspace off the
// authenticating key's runtime identity. The key is minted per
// (workspace, harness) and is the authority for its own scope (ADR 014), so
// there is nothing to override: a caller whose key names the wrong workspace
// mints a new key rather than passing a flag. A key with no workspace cannot
// scope an authorize call and must be re-minted.
func resolveRuntimeScope(identity *RuntimeIdentity) (orgID, workspaceID string, err error) {
	if identity == nil {
		return "", "", errors.New("runtime identity is missing")
	}
	if identity.WorkspaceID == nil {
		return "", "", fmt.Errorf("harness key for runtime installation %s has no workspace and must be re-minted", identity.ID)
	}
	return identity.OrgID, *identity.WorkspaceID, nil
}

// runtimeAuthorizeURL selects the policy catalog endpoint for runtime
// authorization. Runtime identity and management APIs continue to use the
// control-plane URL; deployments can route policy checks directly to their
// in-cluster catalog with KEI_API_URL (or ABAC_URL for compatibility).
func runtimeAuthorizeURL(cfg Config) string {
	if u := strings.TrimSpace(os.Getenv("KEI_API_URL")); u != "" {
		return u
	}
	if u := strings.TrimSpace(os.Getenv("ABAC_URL")); u != "" {
		return u
	}
	return cfg.RuntimeControlPlaneURL
}

func runAuthorize(args []string) int {
	fs := flag.NewFlagSet("authorize", flag.ContinueOnError)
	user := fs.String("user", "", "user_id to authorize as (or --user-id)")
	providerUser := fs.String("provider-user", "", "provider user id (e.g. Slack/Discord id; default $KEI_PROXY_PROVIDER_USER)")
	tool := fs.String("tool", "", "tool being invoked (e.g. github.create_pr)")
	action := fs.String("action", "", "action to authorize (e.g. github:write)")
	resource := fs.String("resource", "", "resource/data being accessed")
	registryPath := fs.String("registry", "", "tool->service registry path (default $KEI_PROXY_REGISTRY)")
	timeout := fs.Int("timeout", 30, "ABAC request timeout in seconds")
	auditPath := fs.String("audit", envOr("KEI_PROXY_AUDIT", ""), "audit JSONL file path (default $KEI_PROXY_AUDIT)")

	// Identity-propagation context (default to env, then to sensible fallbacks).
	spanID := fs.String("span-id", envOr("KEI_PROXY_SPAN_ID", ""), "span id for this invocation (stable dedupe key)")
	invokingSubject := fs.String("invoking-subject", envOr("KEI_PROXY_INVOKING_SUBJECT", ""), "invoking subject (defaults to --user)")
	parentSpan := fs.String("parent-span", envOr("KEI_PROXY_PARENT_SPAN", ""), "parent span id (delegation chain)")
	delegationDepth := fs.Int("delegation-depth", envIntOr("KEI_PROXY_DELEGATION_DEPTH", 0), "delegation depth (0 = direct)")
	agentID := fs.String("agent-id", envOr("KEI_PROXY_AGENT_ID", ""), "agent id making the call")
	agentVersion := fs.String("agent-version", envOr("KEI_PROXY_AGENT_VERSION", ""), "agent version")
	framework := fs.String("framework", envOr("KEI_PROXY_FRAMEWORK", ""), "agent framework (e.g. claude, codex)")
	toolArgsDigest := fs.String("tool-args-digest", envOr("KEI_PROXY_TOOL_ARGS_DIGEST", ""), "SHA256 digest of tool args (PII-safe, not raw args)")
	resources := fs.String("resources", envOr("KEI_PROXY_RESOURCES", ""), "comma-separated resources touched (defaults to --resource)")

	userID := fs.String("user-id", "", "user_id to authorize as (alias for --user)")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if *userID != "" && *user == "" {
		*user = *userID
	}
	cfg := configFromEnv()
	if *providerUser != "" {
		cfg.ProviderUserID = *providerUser
	}
	if cfg.ProviderUserID == "" {
		cfg.ProviderUserID = *user
	}
	if *registryPath != "" {
		cfg.RegistryPath = *registryPath
	}
	if *auditPath != "" {
		cfg.AuditPath = *auditPath
	}

	if *tool == "" {
		fmt.Fprintln(os.Stderr, "Error: --tool is required")
		return 1
	}
	if *action == "" {
		fmt.Fprintln(os.Stderr, "Error: --action is required")
		return 1
	}
	if cfg.RuntimeToken == "" {
		fmt.Fprintln(os.Stderr, "Error: KEI_RUNTIME_TOKEN is required")
		return 1
	}

	reg, err := LoadRegistry(cfg.RegistryPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	identity, err := bootstrapRuntime(context.Background(), cfg, time.Duration(*timeout)*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: runtime bootstrap failed: %v\n", err)
		return 1
	}
	if cfg.IsRuntime() {
		// Keep runtime lifecycle traffic on the control plane, but send policy
		// checks directly to the configured policy catalog when one is available.
		cfg.ABACURL = runtimeAuthorizeURL(cfg)
		cfg.ABACSecret = ""
	}

	client := NewABACClient(cfg.ABACURL, cfg.ABACSecret, time.Duration(*timeout)*time.Second)
	var oidcBridge OIDCBridgeClient
	// Customer runtimes resolve static credentials from their own secret store.
	// Do not call the internal OIDC bridge by default; an explicitly configured
	// bridge may be enabled later for OAuth-backed services.
	if !cfg.IsRuntime() || os.Getenv("OIDC_BRIDGE_URL") != "" {
		oidcBridge = NewOIDCBridgeClient(cfg.OIDCBridgeURL, cfg.OIDCBridgeSecret, time.Duration(*timeout)*time.Second)
	}
	var credentialBinding CredentialBindingClient
	var secretStore SecretStore
	if cfg.IsRuntime() {
		credentialBinding = NewCredentialBindingClient(cfg.RuntimeControlPlaneURL, time.Duration(*timeout)*time.Second)
		secretStore, err = NewSecretStore()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: runtime secret store initialization failed: %v\n", err)
			return 1
		}
	} else {
		fmt.Fprintln(os.Stderr, "Error: KEI_RUNTIME_TOKEN is required")
		return 1
	}

	orgID, workspaceID, err := resolveRuntimeScope(identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	resourcesList := splitCSV(*resources)

	out, err := authorizeTool(authorizeParams{
		ctx:               context.Background(),
		user:              *user,
		providerUser:      cfg.ProviderUserID,
		tool:              *tool,
		action:            *action,
		resource:          *resource,
		harness:           cfg.RuntimeToken,
		abac:              client,
		credentialBinding: credentialBinding,
		secretStore:       secretStore,
		oidcBridge:        oidcBridge,
		auditPath:         cfg.AuditPath,
		auditMaxBytes:     cfg.AuditMaxBytes,
		registry:          reg,
		spanID:            *spanID,
		invokingSubject:   *invokingSubject,
		parentSpan:        *parentSpan,
		delegationDepth:   *delegationDepth,
		agentID:           *agentID,
		agentVersion:      *agentVersion,
		framework:         *framework,
		toolArgsDigest:    *toolArgsDigest,
		resources:         resourcesList,
		orgID:             orgID,
		workspaceID:       workspaceID,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if err := writeJSON(os.Stdout, out); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if out.Decision == "deny" {
		return 1
	}
	return 0
}

/* legacyKeyVaultLookup removed: runtime credentials are resolved exclusively
   through credential bindings and the configured external secret store.
func legacyKeyVaultLookup(ctx context.Context, kv KVClient, abac ABACClient, harnessToken, userID, service string) (*string, error) {
	// Get org ID from harness token via a lightweight authorize probe
	probeResp, err := abac.Authorize(ctx, AuthorizeRequest{
		HarnessToken: harnessToken,
		UserID:       userID,
		Action:       "public:read",
	})
	if err != nil || probeResp.OrgID == nil {
		return nil, fmt.Errorf("cannot resolve org: %w", err)
	}

	orgID := *probeResp.OrgID

	// Fetch service principals for this org from ABAC
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/service-principals?org_id=%s", abacURL(), orgID))
	if err != nil {
		return nil, fmt.Errorf("fetch service principals: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	var body struct {
		ServicePrincipals []struct {
			RoleName     string `json:"role_name"`
			KVVaultURL   string `json:"kv_vault_url"`
			KVSecretName string `json:"kv_secret_name"`
			Enabled      bool   `json:"enabled"`
		} `json:"service_principals"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode service principals: %w", err)
	}

	// Get user's roles from ABAC
	membersResp, err := http.Get(fmt.Sprintf("%s/api/v1/organizations/%s/members?user_id=%s", abacURL(), orgID, userID))
	if err != nil || membersResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch user roles: %w", err)
	}
	defer membersResp.Body.Close()

	var membersBody struct {
		Members []struct {
			Role string `json:"role"`
		} `json:"members"`
	}
	if err := json.NewDecoder(membersResp.Body).Decode(&membersBody); err != nil {
		return nil, fmt.Errorf("decode user roles: %w", err)
	}

	userRoles := make(map[string]struct{})
	for _, m := range membersBody.Members {
		userRoles[m.Role] = struct{}{}
	}

	// Find matching enabled service principal for a role the user has
	for _, sp := range body.ServicePrincipals {
		if !sp.Enabled {
			continue
		}
		if _, hasRole := userRoles[sp.RoleName]; hasRole {
			secret, err := kv.GetSecret(ctx, sp.KVVaultURL, sp.KVSecretName)
			if err != nil {
				return nil, fmt.Errorf("key vault fetch for role %q: %w", sp.RoleName, err)
			}
			if secret != nil {
				return secret, nil
			}
		}
	}

	return nil, nil
}
*/

func abacURL() string {
	if u := os.Getenv("ABAC_URL"); u != "" {
		return u
	}
	return "http://abac-engine"
}

func writeJSON(w interface{ Write([]byte) (int, error) }, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

// splitCSV splits a comma-separated string into trimmed, non-empty fields.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
