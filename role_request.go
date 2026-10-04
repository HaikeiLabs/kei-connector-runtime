package connectorruntime

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

type RoleRequest = keiruntime.RoleRequest

type RoleRequestResponse = keiruntime.RoleRequestResponse

type CreateRoleRequestInput = keiruntime.CreateRoleRequestInput

type ABACRoleRequestClient = keiruntime.ABACRoleRequestClient

func NewABACRoleRequestClient(baseURL string, timeout time.Duration) ABACRoleRequestClient {
	return keiruntime.NewABACRoleRequestClient(baseURL, timeout)
}

type roleRequestParams struct {
	ctx     context.Context
	user    string
	org     string
	role    string
	harness string
	reason  string
	client  ABACRoleRequestClient
	timeout time.Duration
}

func createRoleRequest(p roleRequestParams) (*RoleRequest, error) {
	if p.user == "" {
		return nil, fmt.Errorf("user is required")
	}
	if p.role == "" {
		return nil, fmt.Errorf("role is required")
	}

	input := CreateRoleRequestInput{
		UserID:        p.user,
		OrgID:         p.org,
		RequestedRole: p.role,
		Harness:       p.harness,
		RequestedBy:   p.user,
		Reason:        p.reason,
	}

	return p.client.CreateRoleRequest(p.ctx, input)
}

func runRoleRequest(args []string) int {
	fs := flag.NewFlagSet("role-request", flag.ContinueOnError)
	user := fs.String("user", "", "user ID requesting the role")
	org := fs.String("org", "", "organization ID")
	role := fs.String("role", "", "role name to request")
	reason := fs.String("reason", "", "reason for request")
	harness := fs.String("harness", "", "harness provider (slack, discord, teams)")
	abacURL := fs.String("abac-url", "", "ABAC Engine URL (default $ABAC_URL)")
	timeout := fs.Int("timeout", 30, "request timeout in seconds")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	cfg := configFromEnv()
	if *abacURL != "" {
		cfg.ABACURL = *abacURL
	}

	if *harness == "" {
		fmt.Fprintln(os.Stderr, "Error: --harness is required (slack, discord, or teams)")
		return 1
	}

	client := NewABACRoleRequestClient(cfg.ABACURL, time.Duration(*timeout)*time.Second)

	req, err := createRoleRequest(roleRequestParams{
		ctx:     context.Background(),
		user:    *user,
		org:     *org,
		role:    *role,
		harness: *harness,
		reason:  *reason,
		client:  client,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if err := writeJSON(os.Stdout, RoleRequestResponse{Request: *req}); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	return 0
}
