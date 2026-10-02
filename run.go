package connectorruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/hooks"
	runcommand "github.com/HaikeiLabs/kei-connector-runtime/internal/run"
	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// runPolicy implements `kei-proxy policy sync|show`.
func runPolicy(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: kei-proxy policy <sync|show>")
		return 1
	}
	cfg := configFromEnv()
	switch args[0] {
	case "sync":
		identityFunc := func() (*keiruntime.Identity, error) {
			identity, err := NewRuntimeClient(cfg.RuntimeControlPlaneURL, 30*time.Second).WhoAmI(context.Background(), cfg.RuntimeToken)
			if err != nil {
				return nil, err
			}
			return &keiruntime.Identity{
				ID: identity.ID, OrgID: identity.OrgID, WorkspaceID: identity.WorkspaceID,
			}, nil
		}
		syncBundle := func(identity *keiruntime.Identity) error {
			return SyncPolicyBundle(context.Background(), cfg, &RuntimeIdentity{
				ID: identity.ID, OrgID: identity.OrgID, WorkspaceID: identity.WorkspaceID,
			}, 30*time.Second)
		}
		return keiruntime.RunPolicySync(context.Background(), args[1:], os.Stdout, os.Stderr, cfg, identityFunc, syncBundle, IsRuntimeRevocation, func() { RevokePolicyState(cfg) })
	case "show":
		return keiruntime.RunPolicyShow(args[1:], os.Stdout, os.Stderr, cfg)
	}
	fmt.Fprintf(os.Stderr, "Error: unknown policy command %q\n", args[0])
	return 1
}

// Main runs the kei-proxy command line with args (os.Args[1:]) and returns
// the process exit code. buildVersion is the release version injected into
// the cmd/kei-proxy entrypoint; it is reported by the version command and in
// runtime heartbeats.
func Main(buildVersion string, args []string) int {
	version = buildVersion

	if len(args) < 1 {
		usage()
		return 1
	}

	var code int
	if args[0] == "authorize" {
		code = runAuthorize(args[1:])
	} else if args[0] == "hook" {
		code = runHook(args[1:])
	} else if args[0] == "connector" {
		code = runConnector(args[1:])
	} else if args[0] == "collector" {
		code = runCollector(args[1:])
	} else if args[0] == "model" {
		code = runModel(args[1:])
	} else if args[0] == "credential" {
		code = runCredential(args[1:])
	} else if args[0] == "run" {
		code = runProxyRun(args[1:])
	} else if args[0] == "org" {
		code = runOrg(args[1:], os.Stdout, os.Stderr)
	} else if args[0] == "init" {
		code = runInit(args[1:], os.Stdout, os.Stderr)
	} else if args[0] == "identity" {
		code = runIdentity(args[1:])
	} else if args[0] == "runtime" {
		code = runRuntime(args[1:])
	} else if args[0] == "harness" {
		code = runHarness(args[1:])
	} else if args[0] == "serve" {
		code = runServe(args[1:])
	} else if args[0] == "policy" {
		code = runPolicy(args[1:])
	} else if args[0] == "version" || args[0] == "-v" || args[0] == "--version" {
		printVersion(os.Stdout)
	} else if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usage()
	} else if hasTopLevelFlags(args) {
		code = runAuthorize(args)
	} else {
		fmt.Fprintf(os.Stderr, "Error: unknown command %q\n\n", args[0])
		usage()
		code = 1
	}
	return code
}

func runHook(args []string) int {
	cfg := configFromEnv()
	return hooks.Run(args, os.Stdin, os.Stdout, hooks.Config{
		RuntimeStateDir: cfg.RuntimeStateDir,
		AppendAudit: func(record []byte) error {
			return newAuditSpool(cfg.AuditPath, cfg.AuditMaxBytes).Append(eventClassDecision, record)
		},
	})
}

func runProxyRun(args []string) int {
	cfg := configFromEnv()
	return runcommand.Run(args, os.Stdout, os.Stderr, runcommand.Config{
		ABACURL: cfg.ABACURL, ABACSecret: cfg.ABACSecret, RuntimeToken: cfg.RuntimeToken,
		RuntimeStateDir: cfg.RuntimeStateDir, ProviderUserID: cfg.ProviderUserID,
		AppendAudit: func(record []byte) error {
			return newAuditSpool(cfg.AuditPath, cfg.AuditMaxBytes).Append(eventClassDecision, record)
		},
	})
}

// runHarness is CLI wiring; discovery and sync behavior live in pkg/harness.
func runHarness(args []string) int {
	if len(args) < 2 || args[0] != "tools" || args[1] != "sync" {
		fmt.Fprintln(os.Stderr, "usage: kei-proxy harness tools sync")
		return 2
	}
	cfg := configFromEnv()
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "harness tools sync configuration invalid: %v\n", err)
		return 1
	}
	client := runtimeToolRegistryClient{client: NewRuntimeClient(cfg.RuntimeControlPlaneURL, 15*time.Second)}
	return keiruntime.RunHarnessToolsSync(args[2:], os.Stderr, cfg.RuntimeToken, client)
}

type runtimeToolRegistryClient struct{ client RuntimeClient }

func (c runtimeToolRegistryClient) SyncTools(ctx context.Context, token string, manifest []byte) error {
	var clientManifest ToolManifest
	if err := json.Unmarshal(manifest, &clientManifest); err != nil {
		return fmt.Errorf("decode discovered tool manifest")
	}
	return c.client.SyncTools(ctx, token, &clientManifest)
}

func runModel(args []string) int {
	if len(args) > 0 && args[0] == "profile" {
		return runModelProfile(args[1:])
	}
	return runModelInvoke(args)
}

func hasTopLevelFlags(args []string) bool {
	for _, arg := range args {
		if arg == "--user-id" || len(arg) > len("--user-id=") && arg[:len("--user-id=")] == "--user-id=" {
			return true
		}
	}
	return false
}

func usage() {
	fmt.Fprint(os.Stderr, `kei-proxy - tenant-side runtime policy engine

CLI commands and a long-running serve daemon. Each CLI command performs one
governed action (authorize, connector invoke, collector ship, or credential
sync). The serve daemon exposes a local HTTP/1.1 API on a Unix socket and
optional TCP listener. Customer-hosted runtimes resolve credential metadata
from Kei and fetch values from the configured secret store. Emits each
decision as a structured JSON audit event on stderr.

Usage:
  kei-proxy <command> [flags]

Commands:
  authorize    authorize a tool call and serve its credential (stdout JSON, exit codes)
  connector    invoke a governed data connector through the control plane
  collector    ship pending audit JSONL records to ABAC (idempotent, resumable)
  credential   manage credential sync (see: kei-proxy credential --help)
  run          run a child process with governed connector credentials
  model        model profile and invocation commands (see: kei-proxy model --help)
  org          manage organization members (list, add, remove, update)
  init         provision a member and/or agent via canonical ABAC initialization
  runtime      report and maintain a customer runtime installation heartbeat
  harness      discover tools from all installed harness kinds and sync metadata
  identity link        start a platform identity claim for the current runtime
  identity status      resolve chat identity status for the current runtime
  policy sync  fetch, validate and persist the installation's policy bundle
  policy show  print the persisted policy bundle's version and enforcement state
  serve        start the local OpenAI-compatible HTTP listener
  help         show this help

Environment:
  ABAC_URL                  ABAC Engine URL (default http://localhost:8080)
  KEI_RUNTIME_CONTROL_PLANE_URL public Kei gateway URL for a customer-hosted runtime
  KEI_RUNTIME_TOKEN          installation credential from the customer secret manager
  KEI_CREDENTIAL_STORE_INSTALLATION_ID credential store to register for sync
  KEI_CREDENTIAL_SYNC_KEY_ID sync recipient key identifier
  KEI_CREDENTIAL_SYNC_PRIVATE_KEY base64 X25519 private key for sync
  KEI_PROXY_REGISTRY        tool->service registry path (default /data/config/tools.yaml)
  KEI_PROXY_AUDIT           audit JSONL file path (authorize appends, collector ships)
  KEI_PROXY_AUDIT_MAX_BYTES total audit spool cap in bytes (default 104857600, 100 MiB)
  KEI_RUNTIME_SOCKET_PATH   local HTTP Unix socket (serve; default platform-dependent, see docs/unix-socket.md)
  KEI_RUNTIME_STATE_DIR     protected policy bundle state directory (default /var/lib/kei-proxy)
  KEI_PROXY_SPAN_ID         span id for the invocation (stable dedupe key)
  KEI_PROXY_INVOKING_SUBJECT invoking subject (defaults to --user)
  KEI_PROXY_PARENT_SPAN     parent span id (delegation chain)
  KEI_PROXY_DELEGATION_DEPTH delegation depth (0 = direct)
  KEI_PROXY_AGENT_ID        optional per-call agent id override; harnesses get their
                            assigned agent from whoami (heartbeat identity event)
  KEI_PROXY_AGENT_VERSION   agent version
  KEI_PROXY_FRAMEWORK       agent framework (e.g. claude, codex)
  KEI_TOOL_MANIFEST        path to the agentware tool-manifest v2 JSON file to sync at bootstrap

Examples:
  kei-proxy authorize --user U1234ABCD --tool github.create_pr --action github:write --resource repo:acme/widgets
  kei-proxy connector invoke --connector conn-1 --capability lead.read --action read --resource leads/42 --trace-id t-1
  kei-proxy init --member --user U1234ABCD --org 9f2c...
  kei-proxy init --agent --org 9f2c... --name researcher --tools search_wiki,search_web --scopes wiki:read
  kei-proxy runtime bootstrap
	kei-proxy identity link --platform discord --platform-user-id 123456789
  kei-proxy identity status --platform-user-id 123456789 --tenant-id guild-id
  echo '{"request":{...}}' | KEI_RUNTIME_TOKEN=$KEI_RUNTIME_TOKEN kei-proxy model invoke
  kei-proxy model profile [--profile-id PROFILE_ID]
  kei-proxy --user-id U1234ABCD --tool github.create_pr --action github:write
`)
}
