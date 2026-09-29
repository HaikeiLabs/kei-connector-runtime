package connectorruntime

import (
	"fmt"
	"os"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/invoke"
)

// runConnector dispatches the connector subcommand.
func runConnector(args []string) int {
	if len(args) > 0 && args[0] == "invoke" {
		cfg := configFromEnv()
		return invoke.Run(args[1:], invoke.Env{
			RuntimeToken:           cfg.RuntimeToken,
			RuntimeControlPlaneURL: cfg.RuntimeControlPlaneURL,
			ABACURL:                cfg.ABACURL,
			ABACSecret:             cfg.ABACSecret,
		}, os.Stdout, os.Stderr)
	}
	fmt.Fprintln(os.Stderr, "Error: unknown connector command\n\nUsage: kei-proxy connector invoke --connector <id> --capability <name> --action <action> --resource <resource>")
	return 1
}
