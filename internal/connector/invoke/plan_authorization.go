package invoke

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

type socketPlanAuthorization struct {
	path, token, parentSpan string
	depth                   int
	client                  *http.Client
}

func NewSocketPlanAuthorization(path, token, parentSpan string, depth int) PlanAuthorization {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", path)
	}}
	return &socketPlanAuthorization{path: path, token: token, parentSpan: parentSpan, depth: depth, client: &http.Client{Transport: transport, Timeout: 5 * time.Second}}
}
func (c *socketPlanAuthorization) Consume(handle, tool, agentID string, op policybundle.Operation) error {
	body, err := json.Marshal(map[string]any{"schema": "kei.operation-consume-request/v1", "handle": handle, "tool": tool, "parent_span": c.parentSpan, "delegation_depth": c.depth, "operation": op})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "http://runtime/v1/consume", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return errors.New("runtime preflight consume unavailable")
	}
	defer resp.Body.Close()
	var out struct {
		Schema   string `json:"schema"`
		Decision string `json:"decision"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil || resp.StatusCode != http.StatusOK || out.Schema != "kei.operation-consume-response/v1" || out.Decision != "permit" {
		return errors.New("runtime preflight consume denied")
	}
	return nil
}
