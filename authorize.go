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

	"github.com/HaikeiLabs/kei-connector-runtime/internal/secrets"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/session"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
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

// Exit codes of the authorize CLI (API-012): permit, deny, or an error that
// stopped the call before any decision was made. The values are part of the CLI
// contract (0, 1, 2) that subprocess clients branch on: keep the order, and
// TestAuthorizeExitCodeValuesArePinned fails if it changes.
const (
	authorizeExitPermit = iota
	authorizeExitDeny
	authorizeExitError
)

func runAuthorize(args []string) int {
	fs := flag.NewFlagSet("authorize", flag.ContinueOnError)
	user := fs.String("user", "", "user_id to authorize as (or --user-id)")
	providerUser := fs.String("provider-user", "", "provider user id (e.g. Slack/Discord id; default $KEI_PROXY_PROVIDER_USER)")
	tool := fs.String("tool", "", "tool being invoked (e.g. github.create_pr)")
	action := fs.String("action", "", "action to authorize (e.g. github:write)")
	resource := fs.String("resource", "", "resource/data being accessed")
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
	sessionID := fs.String("session", session.IDFromEnv(), "kei-proxy daemon session id from PUT /v1/session (default $KEI_SESSION_ID; empty = the deprecated default session)")

	if err := fs.Parse(args); err != nil {
		return authorizeExitError
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
	if *auditPath != "" {
		cfg.AuditPath = *auditPath
	}

	if *tool == "" {
		fmt.Fprintln(os.Stderr, "Error: --tool is required")
		return authorizeExitError
	}
	if cfg.RuntimeToken == "" {
		fmt.Fprintln(os.Stderr, "Error: KEI_RUNTIME_TOKEN is required")
		return authorizeExitError
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return authorizeExitError
	}
	identity, err := bootstrapRuntime(context.Background(), cfg, time.Duration(*timeout)*time.Second)
	if err != nil {
		if IsRuntimeRevocation(err) {
			RevokePolicyState(cfg)
		}
		fmt.Fprintf(os.Stderr, "Error: runtime bootstrap failed: %v\n", err)
		return authorizeExitError
	}
	if identity.Status != "active" || identity.BindingStatus != "verified" {
		return keiruntime.WritePolicyStateDenial(os.Stdout, os.Stderr, "installation_revoked", errors.New("runtime installation is inactive or unverified"))
	}
	var credentialBinding keiruntime.CredentialResolver
	var secretStore keiruntime.SecretGetter
	if cfg.IsRuntime() {
		credentialBinding = keiruntime.NewCredentialBindingClient(cfg.RuntimeControlPlaneURL, time.Duration(*timeout)*time.Second)
		secretStore, err = secrets.NewStore()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: runtime secret store initialization failed: %v\n", err)
			return authorizeExitError
		}
	} else {
		fmt.Fprintln(os.Stderr, "Error: KEI_RUNTIME_TOKEN is required")
		return authorizeExitError
	}

	orgID, workspaceID, err := resolveRuntimeScope(identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return authorizeExitError
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
	if activeBundle.Payload.Schema == "kei.policy-bundle/v2" {
		return keiruntime.WritePolicyStateDenial(os.Stdout, os.Stderr, "preflight_required", errors.New("v2 connector calls are not supported by one-shot authorize"))
	}
	invokingSubject := *invokingSubjectFlag
	if invokingSubject == "" && cfg.IsRuntime() {
		if s, err := session.NewSocketSubjectSource(runtimeSocketPathFromEnv(), cfg.RuntimeToken).Subject(session.WithID(context.Background(), *sessionID)); err == nil {
			invokingSubject = s
		}
	}

	subjectProviderID := cfg.ProviderUserID
	var subject *policybundle.Subject
	// Identity is only for credentials: resolve the subject lazily, only when
	// the tool or a reached policy needs it.
	if (*user != "" || subjectProviderID != "") && keiruntime.AuthorizeNeedsSubject(activeBundle, *tool, *action, *resource, *agentID) {
		control := keiruntime.NewPolicyControlClient(cfg.RuntimeControlPlaneURL, cfg.RuntimeToken, time.Duration(*timeout)*time.Second, !cfg.IsProduction())
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
		AuditPath:         cfg.AuditPath,
		AuditMaxBytes:     cfg.AuditMaxBytes,
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
		return authorizeExitError
	}

	if err := keiruntime.WriteJSON(os.Stdout, out); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return authorizeExitError
	}

	if out.Decision == "deny" {
		return authorizeExitDeny
	}
	return authorizeExitPermit
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
