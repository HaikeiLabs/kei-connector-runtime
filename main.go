package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

func main() {
	// Diagnostics are structured JSON on stderr (KEI-108): stdout is the
	// machine-readable protocol channel for the harness.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var code int
	args := os.Args[1:]

	if args[0] == "authorize" {
		code = runAuthorize(args[1:])
	} else if args[0] == "connector" {
		code = runConnector(args[1:])
	} else if args[0] == "collector" {
		code = runCollector(args[1:])
	} else if args[0] == "model" {
		code = runModel(args[1:])
	} else if args[0] == "credential" {
		code = runCredential(args[1:])
	} else if args[0] == "org" {
		code = runOrg(args[1:], os.Stdout, os.Stderr)
	} else if args[0] == "init" {
		code = runInit(args[1:], os.Stdout, os.Stderr)
	} else if args[0] == "runtime" {
		code = runRuntime(args[1:])
	} else if args[0] == "serve" {
		code = runServe(args[1:])
	} else if args[0] == "version" || args[0] == "-v" || args[0] == "--version" {
		printVersion(os.Stdout)
	} else if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usage()
	} else if hasTopLevelFlags(args) {
		_ = os.Setenv("KEI_HARNESS_TOKEN", getFlagValue(args, "key"))
		code = runAuthorize(args)
	} else {
		fmt.Fprintf(os.Stderr, "Error: unknown command %q\n\n", args[0])
		usage()
		code = 1
	}
	os.Exit(code)
}

func runModel(args []string) int {
	if len(args) > 0 && args[0] == "profile" {
		return runModelProfile(args[1:])
	}
	return runModelInvoke(args)
}

func hasTopLevelFlags(args []string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, "--key") || strings.HasPrefix(arg, "--user-id") {
			return true
		}
	}
	return false
}

func getFlagValue(args []string, name string) string {
	prefix := "--" + name + "="
	for _, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			return strings.TrimPrefix(arg, prefix)
		}
	}
	return ""
}

func usage() {
	fmt.Fprint(os.Stderr, `kei-proxy - tenant-side runtime policy engine

A CLI invoked per tool call via cmd.Run. Calls ABAC Engine for access decisions
and serves credentials from the configured secret store. Customer-hosted runtimes
resolve credential metadata from Kei and fetch values from the configured secret store. Emits each decision as a
structured JSON audit event on stderr. No network listener, no local storage.

Usage:
  kei-proxy <command> [flags]

Commands:
  authorize    authorize a tool call and serve its credential (stdout JSON, exit codes)
  connector    invoke a governed data connector through the control plane
  collector    ship pending audit JSONL records to ABAC (idempotent, resumable)
  credential   manage credential sync (see: kei-proxy credential --help)
  model        model profile and invocation commands (see: kei-proxy model --help)
  org          manage organization members (list, add, remove, update)
  init         provision a member and/or agent via canonical ABAC initialization
  runtime      report and maintain a customer runtime installation heartbeat
  serve        start the local OpenAI-compatible HTTP listener
  help         show this help

Environment:
  ABAC_URL                  ABAC Engine URL (default http://localhost:8080)
  KEI_RUNTIME_CONTROL_PLANE_URL public Kei gateway URL for a customer-hosted runtime
  KEI_RUNTIME_TOKEN          installation credential from the customer secret manager
  KEI_RUNTIME_VERSION        runtime image/version reported with each heartbeat
  KEI_CREDENTIAL_STORE_INSTALLATION_ID credential store to register for sync
  KEI_CREDENTIAL_SYNC_KEY_ID sync recipient key identifier
  KEI_CREDENTIAL_SYNC_PRIVATE_KEY base64 X25519 private key for sync
  KEI_RUNTIME_CONTROL_PLANE_URL  Kei control-plane URL for customer runtimes
  KEI_RUNTIME_TOKEN         installation token for customer runtimes
  KEI_HARNESS_TOKEN         legacy org/harness key (read from env, never passed as an argument)
  KEI_PROXY_REGISTRY        tool->service registry path (default /data/config/tools.yaml)
  KEI_PROXY_AUDIT           audit JSONL file path (authorize appends, collector ships)
  KEI_PROXY_SPAN_ID         span id for the invocation (stable dedupe key)
  KEI_PROXY_INVOKING_SUBJECT invoking subject (defaults to --user)
  KEI_PROXY_PARENT_SPAN     parent span id (delegation chain)
  KEI_PROXY_DELEGATION_DEPTH delegation depth (0 = direct)
  KEI_PROXY_AGENT_ID        agent id making the call
  KEI_PROXY_AGENT_VERSION   agent version
  KEI_PROXY_FRAMEWORK       agent framework (e.g. claude, codex)

Examples:
  kei-proxy authorize --user U1234ABCD --tool github.create_pr --action github:write --resource repo:acme/widgets
  kei-proxy connector invoke --connector conn-1 --capability lead.read --action read --resource leads/42 --trace-id t-1
  kei-proxy init --member --user U1234ABCD --org 9f2c...
  kei-proxy init --agent --org 9f2c... --name researcher --tools search_wiki,search_web --scopes wiki:read
  kei-proxy runtime bootstrap
  echo '{"request":{...}}' | kei-proxy model invoke --harness-key $HARNESS_KEY
  kei-proxy model profile [--profile-id PROFILE_ID]
  kei-proxy --key kh_live_xxx --user-id U1234ABCD --tool github.create_pr --action github:write
`)
}
