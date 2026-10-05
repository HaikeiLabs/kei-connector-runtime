package runtime

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"
)

type OrgMember struct {
	OrgID   string `json:"org_id"`
	UserID  string `json:"user_id"`
	Role    string `json:"role"`
	AddedAt string `json:"added_at,omitempty"`
	Email   string `json:"email,omitempty"`
}

type OrgMembersResponse struct {
	Members []OrgMember `json:"members"`
}

// RunOrg implements the `org` subcommand.
//
// Output contract (documented CLI protocol, KEI-108): machine-readable
// results go to stdout — the member list as JSON for --list, or the raw ABAC
// response for mutating operations. Diagnostics and errors go to stderr with
// a non-zero exit code. stdout is never used for diagnostics, and no
// credential material is written to either stream.
func RunOrg(args []string, stdout, stderr io.Writer, cfg RuntimeConfig) int {
	fs := flag.NewFlagSet("org", flag.ContinueOnError)
	orgID := fs.String("org", "", "organization ID (required)")
	userID := fs.String("user", "", "user ID for add/remove/update operations")
	role := fs.String("role", "", "role to assign (admin, member, viewer)")
	list := fs.Bool("list", false, "list organization members")
	add := fs.Bool("add", false, "add user to organization")
	remove := fs.Bool("remove", false, "remove user from organization")
	update := fs.Bool("update", false, "update user's role")
	abacURL := fs.String("abac-url", "", "ABAC Engine URL (default $ABAC_URL)")
	timeout := fs.Int("timeout", 30, "request timeout in seconds")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	if cfg.Token() == "" {
		fmt.Fprintln(stderr, "Error: KEI_RUNTIME_TOKEN is required")
		return 1
	}

	if *orgID == "" {
		fmt.Fprintln(stderr, "Error: --org is required")
		return 1
	}

	client := &http.Client{Timeout: time.Duration(*timeout) * time.Second}
	baseURL := cfg.FlushURL()
	if *abacURL != "" {
		baseURL = *abacURL
	}
	url := fmt.Sprintf("%s/api/v1/organizations/%s/members", baseURL, *orgID)

	var httpReq *http.Request
	method := http.MethodGet

	if *list {
		method = http.MethodGet
	} else if *add {
		method = http.MethodPost
		if *userID == "" || *role == "" {
			fmt.Fprintln(stderr, "Error: --user and --role required for --add")
			return 1
		}
		body := map[string]string{"user_id": *userID, "role": *role}
		jsonBody, _ := json.Marshal(body)
		httpReq, _ = http.NewRequest(method, url, bytes.NewReader(jsonBody))
		httpReq.Header.Set("Content-Type", "application/json")
	} else if *remove {
		method = http.MethodDelete
		url = fmt.Sprintf("%s/%s", url, *userID)
		if *userID == "" {
			fmt.Fprintln(stderr, "Error: --user required for --remove")
			return 1
		}
	} else if *update {
		method = http.MethodPut
		url = fmt.Sprintf("%s/%s", url, *userID)
		if *userID == "" || *role == "" {
			fmt.Fprintln(stderr, "Error: --user and --role required for --update")
			return 1
		}
		body := map[string]string{"role": *role}
		jsonBody, _ := json.Marshal(body)
		httpReq, _ = http.NewRequest(method, url, bytes.NewReader(jsonBody))
		httpReq.Header.Set("Content-Type", "application/json")
	}

	if httpReq == nil {
		httpReq, _ = http.NewRequest(method, url, nil)
	}
	httpReq.Header.Set("Authorization", "Bearer "+cfg.Token())

	resp, err := client.Do(httpReq)
	if err != nil {
		fmt.Fprintf(stderr, "Error: request failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to read response: %v\n", err)
		return 1
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "Error: request failed with status %d: %s\n", resp.StatusCode, string(respBody))
		return 1
	}

	if *list {
		var members OrgMembersResponse
		if err := json.Unmarshal(respBody, &members); err != nil {
			fmt.Fprintf(stderr, "Error: failed to parse response: %v\n", err)
			return 1
		}
		if err := WriteJSON(stdout, members); err != nil {
			fmt.Fprintf(stderr, "Error: failed to write output: %v\n", err)
			return 1
		}
	} else {
		fmt.Println(string(respBody))
	}

	return 0
}
