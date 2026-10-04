package connectorruntime

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

type OrgRole = keiruntime.OrgRole

type RolesResponse = keiruntime.RolesResponse

type ABACRolesClient = keiruntime.ABACRolesClient

func NewABACRolesClient(baseURL string, timeout time.Duration) ABACRolesClient {
	return keiruntime.NewABACRolesClient(baseURL, timeout)
}

type rolesParams struct {
	ctx     context.Context
	org     string
	harness string
	abac    ABACRolesClient
	timeout time.Duration
}

func listRoles(p rolesParams) ([]OrgRole, error) {
	if p.org == "" {
		return nil, fmt.Errorf("org is required")
	}

	resp, err := p.abac.ListRoles(p.ctx, p.org)
	if err != nil {
		return nil, err
	}

	return resp.Roles, nil
}

func runRoles(args []string) int {
	fs := flag.NewFlagSet("roles", flag.ContinueOnError)
	org := fs.String("org", "", "organization ID")
	abacURL := fs.String("abac-url", "", "ABAC Engine URL (default $ABAC_URL)")
	timeout := fs.Int("timeout", 30, "request timeout in seconds")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	cfg := configFromEnv()
	if *abacURL != "" {
		cfg.ABACURL = *abacURL
	}

	if cfg.RuntimeToken == "" {
		fmt.Fprintln(os.Stderr, "Error: KEI_RUNTIME_TOKEN is required")
		return 1
	}

	client := NewABACRolesClient(cfg.ABACURL, time.Duration(*timeout)*time.Second)

	roles, err := listRoles(rolesParams{
		ctx:     context.Background(),
		org:     *org,
		harness: cfg.RuntimeToken,
		abac:    client,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if err := writeJSON(os.Stdout, RolesResponse{Roles: roles}); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	return 0
}
