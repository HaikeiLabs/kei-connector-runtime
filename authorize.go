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
	tool := fs.String("tool", "", "tool being invoked (e.g. github.create_pr)")
	action := fs.String("action", "", "action to authorize (e.g. github:write)")
	resource := fs.String("resource", "", "resource/data being accessed")
	timeout := fs.Int("timeout", 30, "ABAC request timeout in seconds")

	// Identity-propagation context (default to env, then to sensible fallbacks).
	spanID := fs.String("span-id", envOr("KEI_PROXY_SPAN_ID", ""), "span id for this invocation (stable dedupe key)")
	parentSpan := fs.String("parent-span", envOr("KEI_PROXY_PARENT_SPAN", ""), "parent span id (delegation chain)")
	delegationDepth := fs.Int("delegation-depth", envIntOr("KEI_PROXY_DELEGATION_DEPTH", 0), "delegation depth (0 = direct)")
	agentID := fs.String("agent-id", envOr("KEI_PROXY_AGENT_ID", ""), "agent id making the call")
	framework := fs.String("framework", envOr("KEI_PROXY_FRAMEWORK", ""), "agent framework (e.g. claude, codex)")
	toolArgsDigest := fs.String("tool-args-digest", envOr("KEI_PROXY_TOOL_ARGS_DIGEST", ""), "SHA256 digest of tool args (PII-safe, not raw args)")

	sessionID := fs.String("session", session.IDFromEnv(), "kei-proxy daemon session id from PUT /v1/session (default $KEI_SESSION_ID; empty = the deprecated default session)")

	// The one-shot command no longer decides from a bundle's policies or audits
	// the call itself: these flags are accepted and ignored so a subprocess client
	// that still passes them does not fail on an unknown flag (exit 2).
	for _, name := range []string{"user", "user-id", "provider-user", "audit", "agent-version", "resources", "invoking-subject"} {
		fs.String(name, "", "ignored: one-shot authorize no longer uses it")
	}

	// --help still exits authorizeExitError: exit 0 is this command's permit
	// contract, and a help request must never read as a permit.
	flagUsage(fs, "kei-proxy authorize --tool <tool> [flags] (deprecated: harnesses use the serve socket)")
	if err := fs.Parse(args); err != nil {
		return authorizeExitError
	}

	cfg := configFromEnv()

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
	orgID, workspaceID, err := resolveRuntimeScope(identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return authorizeExitError
	}

	store, err := policybundle.OpenStore(cfg.RuntimeStateDir)
	if err != nil {
		return keiruntime.WritePolicyStateDenial(os.Stdout, os.Stderr, "startup_config_invalid", err)
	}
	_, bundleState, err := store.Check(identity.ID, orgID, workspaceID, time.Now().UTC())
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
	// A bundle that passes Check is a v2 bundle (a v1 bundle is rejected as
	// unsupported when it is fetched or loaded). A v2 decision needs a subject, which only a daemon session holds.
	out, err := authorizeViaDaemon(context.Background(), runtimeSocketPathFromEnv(), cfg.RuntimeToken, *sessionID, daemonAuthorizeCall{
		Tool: *tool, Action: *action, Resource: *resource, AgentID: *agentID,
		SpanID: *spanID, ParentSpan: *parentSpan, DelegationDepth: *delegationDepth,
		Framework: *framework, ToolArgsDigest: *toolArgsDigest,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: a v2 policy bundle is decided by kei-proxy serve: %v\n", err)
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
