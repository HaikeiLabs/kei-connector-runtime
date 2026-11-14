package connectorruntime

import (
	"flag"
	"fmt"
	"io"
)

// isHelpArg reports whether arg asks for help.
func isHelpArg(arg string) bool {
	return arg == "-h" || arg == "--help" || arg == "help"
}

// commandHelp is the `kei-proxy <command> --help` text for commands that
// dispatch to subcommands or take no flags of their own. Commands built on a
// single flag set (authorize, collector) print their flags instead; see
// flagUsage.
var commandHelp = map[string]string{
	"serve": `Usage: kei-proxy serve

Run the local daemon a harness talks to. It serves sessions, local policy
decisions (POST /v1/authorize), model profiles and tool registration on an
owner-only Unix socket, and runs the policy refresher, audit collector and
heartbeat until SIGINT or SIGTERM. It takes no arguments.

Environment:
  KEI_RUNTIME_CONTROL_PLANE_URL  Kei gateway URL (required)
  KEI_RUNTIME_TOKEN              runtime installation credential (required)
  KEI_RUNTIME_SOCKET_PATH        Unix socket path (default platform-dependent)
  KEI_PROXY_LISTEN_ADDR          TCP listener address (default :8085)
  KEI_RUNTIME_STATE_DIR          policy bundle and audit state directory
`,
	"runtime": `Usage: kei-proxy runtime <bootstrap|heartbeat> [flags]

Commands:
  bootstrap   check the installation credential, print the installation's scope
              as JSON and fetch the policy bundle
  heartbeat   report liveness to Kei until stopped (not needed beside serve,
              which sends heartbeats itself)

Run "kei-proxy runtime <command> -h" for flags.
`,
	"policy": `Usage: kei-proxy policy <sync|show> [flags]

Commands:
  sync   fetch, validate and persist the installation's policy bundle
  show   print the persisted policy bundle's version and enforcement state
`,
	"credential": `Usage: kei-proxy credential sync [flags]

Commands:
  sync   process pending connector credential deliveries from Kei, write them
         to the configured secret store (KEI_SECRETS_BACKEND) and acknowledge
         them

Run "kei-proxy credential sync -h" for flags.
`,
	"identity": `Usage: kei-proxy identity <link|status> [flags]

Commands:
  link     start a platform identity claim and print its claim URL as JSON; the
           URL is a bearer secret, so deliver it privately to the user
  status   print whether a platform user is linked to this installation

Run "kei-proxy identity <command> -h" for flags.
`,
	"hook": `Usage: kei-proxy hook <claude|codex|opencode|cursor|pi> --harness <agent-id>

Record one harness tool call, read as JSON on stdin, as a report-only audit
event. The hook never blocks the harness: it always exits 0. The harness
configuration that "kei harness sync" writes calls it for you.
`,
	"model": `Usage: kei-proxy model <profile|profiles|invoke> [flags]

Commands:
  profile    print the assigned model profile, with its credential, as JSON
             (--agent-id, --profile-id); keep that output private
  profiles   list the active model profile assignments, without credentials
             (--agent-id)
  invoke     read a JSON request on stdin and call the assigned model
`,
	"run": `Usage: kei-proxy run [--connector <id>] [--session <id>] -- <command> [args...]

Run a child process with connector credentials in its environment. Output
that contains a released credential is redacted. With
KEI_CREDENTIAL_RELEASE=identity, the serve daemon resolves the credentials
from the session (--session, default $KEI_SESSION_ID) and starts the child.
`,
	"harness": `Usage: kei-proxy harness tools sync

Discover tools from every installed harness kind and sync their metadata to
Kei.
`,
}

// flagUsage gives a flag set a usage line in the same shape as commandHelp.
func flagUsage(fs *flag.FlagSet, line string) {
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintf(out, "Usage: %s\n\nFlags:\n", line)
		fs.PrintDefaults()
	}
}

// printCommandHelp writes command's help to w and reports whether command has
// help text.
func printCommandHelp(w io.Writer, command string) bool {
	text, ok := commandHelp[command]
	if ok {
		fmt.Fprint(w, text)
	}
	return ok
}
