package connectorruntime

// Package authorize provides the runtime authorize subcommand. The core
// authorization logic lives in runtime/; this file contains the CLI entry
// point (runAuthorize), the scope resolver, and thin wrappers.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

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
	invokingSubjectFlag := fs.String("invoking-subject", "", "canonical invoking subject for audit identity propagation")

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

	reg, err := keiruntime.LoadRegistry(cfg.RegistryPath)
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
		return keiruntime.WritePolicyStateDenial(os.Stdout, os.Stderr, "installation_revoked", errors.New("runtime installation is inactive or unverified"))
	}
	var oidcBridge keiruntime.OIDCTokenProvider
	if !cfg.IsRuntime() || os.Getenv("OIDC_BRIDGE_URL") != "" {
		oidcBridge = keiruntime.NewOIDCBridgeClient(cfg.OIDCBridgeURL, cfg.OIDCBridgeSecret, time.Duration(*timeout)*time.Second)
	}
	var credentialBinding keiruntime.CredentialResolver
	var secretStore keiruntime.SecretGetter
	if cfg.IsRuntime() {
		credentialBinding = keiruntime.NewCredentialBindingClient(cfg.RuntimeControlPlaneURL, time.Duration(*timeout)*time.Second)
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
		return keiruntime.WritePolicyStateDenial(os.Stdout, os.Stderr, "startup_config_invalid", err)
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
		return keiruntime.WritePolicyStateDenial(os.Stdout, os.Stderr, reason, err)
	}
	invokingSubject := *invokingSubjectFlag
	if invokingSubject == "" && cfg.IsRuntime() {
		if s, err := session.NewSocketSubjectSource(runtimeSocketPathFromEnv(), cfg.RuntimeToken).Subject(context.Background()); err == nil {
			invokingSubject = s
		}
	}

	subjectProviderID := cfg.ProviderUserID
	var subject *policybundle.Subject
	if *user != "" || subjectProviderID != "" {
		control := keiruntime.NewPolicyControlClient(cfg.ABACURL, cfg.RuntimeToken, time.Duration(*timeout)*time.Second, !cfg.IsProduction())
		req := keiruntime.SubjectResolveRequest{}
		if *user != "" {
			req.UserID = *user
		} else {
			req.PlatformUserID = subjectProviderID
			req.TenantID = os.Getenv("KEI_PROXY_PLATFORM_TENANT_ID")
		}
		resolved, resolveErr := control.ResolveSubject(context.Background(), req)
		if errors.Is(resolveErr, keiruntime.ErrPolicyInstallationRevoked) {
			_ = store.Revoke(time.Now().UTC())
			return keiruntime.WritePolicyStateDenial(os.Stdout, os.Stderr, "installation_revoked", resolveErr)
		}
		if resolveErr != nil {
			return keiruntime.WritePolicyStateDenial(os.Stdout, os.Stderr, "subject_resolution_unavailable", resolveErr)
		}
		subject = &resolved
	}
	resourcesList := keiruntime.SplitCSV(*resources)

	out, err := keiruntime.AuthorizeTool(keiruntime.AuthorizeParams{
		Ctx:               context.Background(),
		User:              *user,
		ProviderUser:      subjectProviderID,
		Tool:              *tool,
		Action:            *action,
		Resource:          *resource,
		Harness:           cfg.RuntimeToken,
		CredentialBinding: credentialBinding,
		SecretStore:       secretStore,
		OIDCBridge:        oidcBridge,
		AuditPath:         cfg.AuditPath,
		AuditMaxBytes:     cfg.AuditMaxBytes,
		Registry:          reg,
		SpanID:            *spanID,
		InvokingSubject:   invokingSubject,
		ParentSpan:        *parentSpan,
		DelegationDepth:   *delegationDepth,
		AgentID:           *agentID,
		AgentVersion:      *agentVersion,
		Framework:         *framework,
		ToolArgsDigest:    *toolArgsDigest,
		Resources:         resourcesList,
		OrgID:             orgID,
		WorkspaceID:       workspaceID,
		PolicyBundle:      activeBundle,
		PolicySubject:     subject,
		BundleState:       string(bundleState),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if err := keiruntime.WriteJSON(os.Stdout, out); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if out.Decision == "deny" {
		return 1
	}
	return 0
}

// writeJSON is a thin wrapper retained for callers in this package that have
// not yet migrated to keiruntime.WriteJSON directly.
func writeJSON(w interface{ Write([]byte) (int, error) }, v any) error {
	return keiruntime.WriteJSON(w, v)
}

// splitCSV is a thin wrapper retained for callers in this package that have
// not yet migrated to keiruntime.SplitCSV directly.
func splitCSV(s string) []string {
	return keiruntime.SplitCSV(s)
}

// Ensure *Registry satisfies keiruntime.ToolRegistry.
var _ keiruntime.ToolRegistry = (*keiruntime.Registry)(nil)
