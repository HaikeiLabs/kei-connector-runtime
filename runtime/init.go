package runtime

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"
)

// InitResult is the single JSON object the `init` command writes to stdout.
// Only the operations requested are present.
type InitResult struct {
	Member *MemberInitResponse `json:"member,omitempty"`
	Agent  *AgentInitResponse  `json:"agent,omitempty"`
}

// RunInit implements the `init` subcommand. It provisions a member and/or an
// agent by calling the canonical ABAC initialization endpoints over HTTP.
//
// The proxy performs no local provisioning or permission fallback: every
// outcome is taken from the ABAC engine, and any transport or HTTP failure is
// reported to stderr with a non-zero exit code (fail closed).
//
// Output contract (KEI-108): the provisioning result is written to stdout as a
// single JSON object; diagnostics and errors go to stderr.
func RunInit(args []string, stdout, stderr io.Writer, defaultABACURL, defaultABACSecret string, isProduction bool) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	member := fs.Bool("member", false, "initialize a member (requires --user and --org)")
	agent := fs.Bool("agent", false, "initialize an agent (requires --org and --name)")
	userID := fs.String("user", "", "user ID to provision as a member")
	orgID := fs.String("org", "", "organization ID (required)")
	name := fs.String("name", "", "agent name (for --agent)")
	description := fs.String("description", "", "agent description (for --agent)")
	tools := fs.String("tools", "", "comma-separated declared tools (for --agent)")
	scopes := fs.String("scopes", "", "comma-separated declared data scopes (for --agent)")
	abacURL := fs.String("abac-url", "", "ABAC Engine URL (default $ABAC_URL)")
	key := fs.String("key", "", "ABAC service secret (default $ABAC_API_SECRET)")
	timeout := fs.Int("timeout", 30, "request timeout in seconds")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	if !*member && !*agent {
		fmt.Fprintln(stderr, "Error: specify --member and/or --agent")
		return 1
	}
	if *orgID == "" {
		fmt.Fprintln(stderr, "Error: --org is required")
		return 1
	}
	if *member && *userID == "" {
		fmt.Fprintln(stderr, "Error: --user is required for --member")
		return 1
	}
	if *agent && *name == "" {
		fmt.Fprintln(stderr, "Error: --name is required for --agent")
		return 1
	}

	abacURLStr := defaultABACURL
	if *abacURL != "" {
		abacURLStr = *abacURL
	}
	secret := defaultABACSecret
	if *key != "" {
		secret = *key
	}
	// Service-to-service initialization requires the ABAC secret in
	// environments that enforce authentication. This is a platform operation,
	// not a runtime path, so the runtime control-plane check does not apply.
	if isProduction && secret == "" {
		fmt.Fprintln(stderr, "Error: ABAC_API_SECRET is required when ENV is production or staging")
		return 1
	}

	client := NewInitializationClient(abacURLStr, secret, time.Duration(*timeout)*time.Second)
	ctx := context.Background()

	result := InitResult{}
	if *member {
		out, err := client.InitializeMember(ctx, MemberInitRequest{UserID: *userID, OrgID: *orgID})
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		result.Member = out
	}
	if *agent {
		req := AgentInitRequest{
			OrgID:       *orgID,
			Name:        *name,
			Description: *description,
		}
		if list := SplitCSV(*tools); len(list) > 0 {
			toolsJSON, _ := json.Marshal(list)
			req.DeclaredTools = toolsJSON
		}
		if list := SplitCSV(*scopes); len(list) > 0 {
			scopesJSON, _ := json.Marshal(list)
			req.DeclaredDataScopes = scopesJSON
		}
		out, err := client.InitializeAgent(ctx, req)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		result.Agent = out
	}

	if err := WriteJSON(stdout, result); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}
