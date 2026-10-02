package connectorruntime

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
)

// CredentialResponse carries only the secret value. Injection is decided by the
// tool, not by the proxy.
type CredentialResponse struct {
	Value string `json:"value"`
}

type AuthorizeOutput struct {
	Decision   string              `json:"decision"`
	ReasonCode string              `json:"reason_code,omitempty"`
	DenySource string              `json:"deny_source,omitempty"`
	Reason     string              `json:"reason,omitempty"`
	Service    string              `json:"service,omitempty"`
	Credential *CredentialResponse `json:"credential,omitempty"`
	Enrollment *json.RawMessage    `json:"enrollment,omitempty"`
	Connect    *json.RawMessage    `json:"connect,omitempty"`
}

type authorizeParams struct {
	ctx          context.Context
	user         string
	providerUser string
	tool         string
	action       string
	resource     string
	harness      string
	// Deprecated compatibility fields; runtime authorization never uses them.
	credentialBinding CredentialBindingClient
	secretStore       secrets.Store
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
	policyBundle    *policybundle.Verified
	policySubject   *policybundle.Subject
	bundleState     string
}

func authorizeTool(p authorizeParams) (AuthorizeOutput, error) {
	service := p.registry.Service(p.tool)

	// Prepend service to resource if not already present (e.g., HaikeiLabs/kei -> github:repo:HaikeiLabs/kei)
	resource := p.resource
	if service != "" && !strings.HasPrefix(resource, service+":") {
		resource = service + ":repo:" + resource
	}

	var resp *AuthorizeResponse
	var localDecision *policybundle.Decision
	if p.policyBundle != nil {
		subjectID := p.user
		if p.policySubject != nil && p.policySubject.UserID != "" {
			subjectID = p.policySubject.UserID
		}
		decision := p.policyBundle.Evaluate(policybundle.Call{Tool: p.tool, Action: p.action, Resource: resource, AgentID: p.agentID, UserID: subjectID}, p.policySubject)
		localDecision = &decision
		resp = &AuthorizeResponse{Decision: decision.Outcome, Reason: decision.Reason, PolicyID: decision.PolicyID, ReasonCode: decision.ReasonCode}
		if p.policySubject != nil && len(p.policySubject.Enrollment) > 0 {
			enrollment := json.RawMessage(p.policySubject.Enrollment)
			resp.Enrollment = &enrollment
		}
		if decision.Outcome == "deny" && decision.ReasonCode == "enrollment_required" {
			resp.Decision = "enrollment_required"
		}
	} else {
		return AuthorizeOutput{Decision: "deny", ReasonCode: "policy_bundle_missing", DenySource: "runtime_state", Reason: "no verified local policy bundle"}, nil
	}

	out := AuthorizeOutput{}
	if localDecision != nil {
		out.ReasonCode = localDecision.ReasonCode
		if localDecision.ReasonCode != "" {
			out.DenySource = "policy"
			if localDecision.ReasonCode == "subject_resolution_unavailable" || strings.HasPrefix(localDecision.ReasonCode, "identity_") || localDecision.ReasonCode == "enrollment_required" {
				out.DenySource = "identity"
			}
			if strings.HasPrefix(localDecision.ReasonCode, "policy_bundle_") {
				out.DenySource = "runtime_state"
			}
			if localDecision.ReasonCode == "tool_not_registered" || localDecision.ReasonCode == "tool_action_mismatch" || strings.HasPrefix(localDecision.ReasonCode, "agent_") {
				out.DenySource = "registry"
			}
		}
	}
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
				if errors.Is(err, secrets.ErrNotFound) {
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
		out.Connect = resp.Connect
	default:
		out.Decision = "deny"
		out.Reason = resp.Reason
		out.Connect = resp.Connect
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
	if p.policyBundle != nil {
		version := p.policyBundle.Payload.BundleVersion
		revision := p.policyBundle.Payload.PolicyRevision
		digest := p.policyBundle.Digest
		event.PolicyBundleVersion = &version
		event.PolicyRevision = &revision
		event.PolicyBundleDigest = &digest
		event.BundleState = p.bundleState
	}
	if out.DenySource != "" {
		event.DenySource = out.DenySource
	}
	if out.ReasonCode != "" {
		event.ReasonCode = out.ReasonCode
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
		if IsRuntimeRevocation(err) {
			RevokePolicyState(cfg)
		}
		fmt.Fprintf(os.Stderr, "Error: runtime bootstrap failed: %v\n", err)
		return 1
	}
	if identity.Status != "active" || identity.BindingStatus != "verified" {
		return writePolicyStateDenial(os.Stdout, os.Stderr, "installation_revoked", errors.New("runtime installation is inactive or unverified"))
	}
	var oidcBridge OIDCBridgeClient
	// Customer runtimes resolve static credentials from their own secret store.
	// Do not call the internal OIDC bridge by default; an explicitly configured
	// bridge may be enabled later for OAuth-backed services.
	if !cfg.IsRuntime() || os.Getenv("OIDC_BRIDGE_URL") != "" {
		oidcBridge = NewOIDCBridgeClient(cfg.OIDCBridgeURL, cfg.OIDCBridgeSecret, time.Duration(*timeout)*time.Second)
	}
	var credentialBinding CredentialBindingClient
	var secretStore secrets.Store
	if cfg.IsRuntime() {
		credentialBinding = NewCredentialBindingClient(cfg.RuntimeControlPlaneURL, time.Duration(*timeout)*time.Second)
		secretStore, err = secrets.NewStore()
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

	store, err := policybundle.OpenStore(cfg.RuntimeStateDir)
	if err != nil {
		return writePolicyStateDenial(os.Stdout, os.Stderr, "startup_config_invalid", err)
	}
	activeBundle, bundleState, err := store.Check(identity.ID, orgID, workspaceID, time.Now().UTC())
	if err != nil {
		reason := "policy_bundle_missing"
		if bundleState == policybundle.Expired {
			reason = "policy_bundle_expired"
		} else if bundleState == policybundle.Invalid {
			reason = "policy_bundle_invalid"
		} else if bundleState == policybundle.Unsupported {
			reason = "policy_bundle_unsupported"
		} else if bundleState == policybundle.Revoked {
			reason = "installation_revoked"
		}
		return writePolicyStateDenial(os.Stdout, os.Stderr, reason, err)
	}
	// Resolve the invoking subject from the runtime session (G0: never from env/argv).
	invokingSubject := ""
	if cfg.IsRuntime() {
		if s, err := session.NewSocketSubjectSource(runtimeSocketPathFromEnv(), cfg.RuntimeToken).Subject(context.Background()); err == nil {
			invokingSubject = s
		}
	}

	subjectProviderID := cfg.ProviderUserID
	var subject *policybundle.Subject
	if *user != "" || subjectProviderID != "" {
		control := newPolicyControlClient(cfg.RuntimeControlPlaneURL, cfg.RuntimeToken, time.Duration(*timeout)*time.Second, !cfg.IsProduction())
		req := subjectResolveRequest{}
		if *user != "" {
			req.UserID = *user
		} else {
			req.PlatformUserID = subjectProviderID
			req.TenantID = os.Getenv("KEI_PROXY_PLATFORM_TENANT_ID")
		}
		resolved, resolveErr := control.ResolveSubject(context.Background(), req)
		if errors.Is(resolveErr, ErrPolicyInstallationRevoked) {
			_ = store.Revoke(time.Now().UTC())
			return writePolicyStateDenial(os.Stdout, os.Stderr, "installation_revoked", resolveErr)
		}
		if resolveErr != nil {
			return writePolicyStateDenial(os.Stdout, os.Stderr, "subject_resolution_unavailable", resolveErr)
		}
		subject = &resolved
	}
	resourcesList := splitCSV(*resources)

	out, err := authorizeTool(authorizeParams{
		ctx:               context.Background(),
		user:              *user,
		providerUser:      subjectProviderID,
		tool:              *tool,
		action:            *action,
		resource:          *resource,
		harness:           cfg.RuntimeToken,
		credentialBinding: credentialBinding,
		secretStore:       secretStore,
		oidcBridge:        oidcBridge,
		auditPath:         cfg.AuditPath,
		auditMaxBytes:     cfg.AuditMaxBytes,
		registry:          reg,
		spanID:            *spanID,
		invokingSubject:   invokingSubject,
		parentSpan:        *parentSpan,
		delegationDepth:   *delegationDepth,
		agentID:           *agentID,
		agentVersion:      *agentVersion,
		framework:         *framework,
		toolArgsDigest:    *toolArgsDigest,
		resources:         resourcesList,
		orgID:             orgID,
		workspaceID:       workspaceID,
		policyBundle:      activeBundle,
		policySubject:     subject,
		bundleState:       string(bundleState),
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

func writePolicyStateDenial(stdout, stderr io.Writer, reason string, err error) int {
	source := "runtime_state"
	if reason == "subject_resolution_unavailable" || reason == "enrollment_required" || strings.HasPrefix(reason, "identity_") {
		source = "identity"
	}
	_ = writeJSON(stdout, AuthorizeOutput{Decision: "deny", ReasonCode: reason, DenySource: source, Reason: reason})
	if err != nil {
		fmt.Fprintf(stderr, "authorization denied (%s): %v\n", reason, err)
	}
	return 1
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
